//
//  TailscaleControlTransport.swift
//  VPNEngine
//
//  The client end of a Tailscale/Headscale control connection: Noise over a
//  byte stream, with each record sealed in its own frame.
//
//  The layers, outermost first:
//
//      TCP (optionally TLS) ── HTTP/1.1 upgrade ── Noise records
//        └ record = [type 0x04][2 byte length][ChaCha20-Poly1305 ciphertext]
//
//  A caller normally only needs ``TS2021ControlTransport/connect(loginServer:capabilityVersion:nodeKeyPublic:localStaticPrivate:session:tlsTrust:onServerEarlyPayload:log:)``:
//  it fetches the server key, performs the upgrade and the Noise handshake, and
//  returns something it can hand records to.
//
//  Reconnection is deliberately not here. When a record cannot be read the
//  transport fails with ``TailscaleControlError/streamClosed`` or
//  ``TailscaleControlError/transportFailed(_:)`` and stays failed; the caller
//  decides whether to dial again, because only the caller knows whether the
//  registration state it holds is still valid.
//
//  Note on what travels *inside* the records: this layer is a byte stream of
//  records, and the framing, handshake and error handling are exactly
//  Tailscale's. Current Tailscale and Headscale servers run HTTP/2 on top of
//  these records (`/machine/register`, `/machine/map` and friends), so a
//  complete control client needs an HTTP/2 client above this one. The
//  record-oriented API here is what the surrounding session code in this
//  package expects; see the notes in the handover report.
//
//  References:
//   * `control/controlbase/conn.go` in https://github.com/tailscale/tailscale
//     (BSD-3-Clause)
//   * Headscale's server half: `hscontrol/noise.go` in
//     https://github.com/juanfont/headscale (BSD-3-Clause)
//

import Foundation

/// A connection that can send and receive control protocol records.
///
/// Records are `tailcfg` messages, JSON encoded. Ping and pong frames, which
/// only ever come from a peer that speaks this engine's keepalive extension,
/// are answered inside the transport and never surface.
public protocol TailscaleControlTransport: AnyObject, Sendable {

    /// Sends one record payload.
    ///
    /// - Parameter json: The record, normally a JSON `tailcfg` message.
    /// - Throws: ``TailscaleControlError/recordTooLarge(_:)`` when the record
    ///   does not fit one frame, or a transport error when the stream is
    ///   broken.
    func sendRecord(_ json: Data) async throws

    /// Awaits the next record payload.
    ///
    /// - Throws: ``TailscaleControlError/streamClosed`` at end of stream, or
    ///   another transport error.
    /// - Returns: The record payload.
    func receiveRecord() async throws -> Data

    /// Closes the connection. Safe to call more than once.
    func close() async
}

/// A control connection established with the ts2021 handshake.
///
/// The type is a thin, `Sendable` front for an actor that owns the stream and
/// the two cipher states, so that concurrent ``sendRecord(_:)`` and
/// ``receiveRecord()`` calls cannot interleave a frame or corrupt a nonce.
public final class TS2021ControlTransport: TailscaleControlTransport, @unchecked Sendable {

    /// The actor that serialises all stream and cipher access.
    private let connection: TS2021Connection

    /// The Noise transcript hash of the completed handshake.
    ///
    /// Tailscale uses it to bind other messages to the connection, so that a
    /// message replayed from a different connection is detectable.
    public var handshakeHash: Data { get async { await connection.handshakeHash } }

    /// The JSON the server sent as its early payload, once it has arrived.
    ///
    /// This is `tailcfg.EarlyNoise`: a per-connection challenge key the client
    /// proves possession of its node key against later. It is `nil` until the
    /// first record has been read, and `nil` forever for servers that do not
    /// send one.
    public var serverEarlyPayload: Data? { get async { await connection.earlyPayload } }

    /// Wraps a connection that has already completed its handshake.
    ///
    /// - Parameter connection: The actor holding the stream and keys.
    private init(connection: TS2021Connection) {
        self.connection = connection
    }

    // MARK: - Connecting

    /// Dials a login server and completes the ts2021 handshake.
    ///
    /// - Parameters:
    ///   - loginServer: The control server's base URL. `http`, `https`, `ws`
    ///     and `wss` are accepted; `ws` and `wss` select the plain and TLS
    ///     transports respectively. The WebSocket *handshake* is not
    ///     implemented, because only Tailscale's browser client uses it and
    ///     native clients use the `Upgrade:` header below.
    ///   - capabilityVersion: The client's capability version. It is mixed into
    ///     the Noise prologue and written into the initiation frame, and
    ///     Headscale refuses versions below its floor.
    ///   - nodeKeyPublic: The client's node public key, 32 bytes.
    ///   - localStaticPrivate: The client's Noise (machine) static private key,
    ///     32 bytes. Never logged.
    ///   - session: The URL session used for `GET /key`. Inject one with a
    ///     delegate to trust a private CA.
    ///   - tlsTrust: Called with the server's `SecTrust` for the upgrade
    ///     connection when TLS is in use. Returning `true` accepts the
    ///     certificate; `nil` means the platform's default verification.
    ///   - onServerEarlyPayload: Called with the server's early payload JSON
    ///     when it arrives, which is after this call has returned.
    ///   - log: A logger. Key material is never passed to it.
    /// - Throws: ``TailscaleControlError`` for every failure, including a
    ///   non-101 upgrade response.
    /// - Returns: A connected transport.
    public static func connect(loginServer: URL,
                               capabilityVersion: Int,
                               nodeKeyPublic: Data,
                               localStaticPrivate: Data,
                               session: URLSession = .shared,
                               tlsTrust: ((SecTrust) -> Bool)? = nil,
                               onServerEarlyPayload: (@Sendable (Data) -> Void)? = nil,
                               log: @escaping @Sendable (String) -> Void = { _ in }) async throws -> TS2021ControlTransport {
        let target = try ConnectionTarget(loginServer: loginServer)

        log("tailscale: fetching the server key from \(target.host):\(target.port)")
        let serverKey = try await TS2021.fetchServerKey(loginServer: loginServer,
                                                       capabilityVersion: capabilityVersion,
                                                       session: session)

        let clientHandshake = try TS2021.beginClientHandshake(nodeKey: nodeKeyPublic,
                                                              capabilityVersion: capabilityVersion,
                                                              localStaticPrivate: localStaticPrivate,
                                                              serverKey: serverKey.publicKey)
        let request = try TS2021.upgradeRequest(loginServer: loginServer,
                                                host: target.hostHeader,
                                                handshakeHeaderValue: clientHandshake.headerValue)

        let upgrade = try await TailscaleHTTPUpgrade.connect(host: target.host,
                                                             port: target.port,
                                                             useTLS: target.useTLS,
                                                             request: request,
                                                             tlsTrust: tlsTrust,
                                                             log: log)
        return try await TS2021ControlTransport.connect(stream: upgrade,
                                                        handshake: clientHandshake.handshake,
                                                        onServerEarlyPayload: onServerEarlyPayload,
                                                        log: log)
    }

    /// Completes a handshake over an already-open byte stream.
    ///
    /// The stream must be positioned at the start of the server's Noise
    /// response frame — that is, immediately after the `101 Switching
    /// Protocols` headers — which is exactly where
    /// ``TailscaleHTTPUpgrade/connect(host:port:useTLS:request:tlsTrust:timeout:log:)``
    /// leaves it. Any bytes the server packed into the same segment are held in
    /// the stream's buffer and are not lost.
    ///
    /// - Parameters:
    ///   - stream: The stream, positioned before the response frame.
    ///   - handshake: A handshake whose message 1 has already been sent.
    ///   - onServerEarlyPayload: Called with the server's early payload JSON.
    ///   - log: A logger.
    /// - Throws: ``TailscaleControlError`` when the response is malformed, the
    ///   handshake does not authenticate, or the stream ends.
    /// - Returns: A connected transport.
    public static func connect(stream: TailscaleByteStream,
                               handshake: NoiseIKHandshake,
                               onServerEarlyPayload: (@Sendable (Data) -> Void)? = nil,
                               log: @escaping @Sendable (String) -> Void = { _ in }) async throws -> TS2021ControlTransport {
        let connection = try await TS2021Connection(stream: stream,
                                                    handshake: handshake,
                                                    onServerEarlyPayload: onServerEarlyPayload,
                                                    log: log)
        return TS2021ControlTransport(connection: connection)
    }

    /// Creates a transport over a stream and a pair of session keys.
    ///
    /// This is the seam the tests use to drive the framing and the ping/pong
    /// handling without a handshake in the way.
    ///
    /// - Parameters:
    ///   - stream: The stream, positioned at the first record.
    ///   - send: The state to seal outbound records with.
    ///   - receive: The state to open inbound records with.
    ///   - log: A logger.
    /// - Returns: A transport.
    public init(stream: TailscaleByteStream,
                send: NoiseCipherState,
                receive: NoiseCipherState,
                log: @escaping @Sendable (String) -> Void = { _ in }) {
        self.connection = TS2021Connection(stream: stream, send: send, receive: receive, log: log)
    }

    // MARK: - TailscaleControlTransport

    /// Sends one record payload.
    ///
    /// - Parameter json: The record, normally a JSON `tailcfg` message.
    /// - Throws: A ``TailscaleControlError`` when the record does not fit or
    ///   the stream is broken.
    public func sendRecord(_ json: Data) async throws {
        try await connection.sendRecord(json)
    }

    /// Awaits the next record payload.
    ///
    /// - Throws: A ``TailscaleControlError`` when the stream is broken.
    /// - Returns: The record payload.
    public func receiveRecord() async throws -> Data {
        try await connection.receiveRecord()
    }

    /// Closes the connection.
    public func close() async {
        await connection.close()
    }
}

/// The actor that owns one control connection's stream, keys and read buffer.
///
/// Everything that touches the stream or a nonce happens here, which is what
/// makes a concurrent `sendRecord` and `receiveRecord` safe.
actor TS2021Connection {

    /// The largest early payload this engine will buffer.
    static let maxEarlyPayloadSize = 64 * 1024

    /// The largest number of bytes held while waiting for a frame to complete.
    ///
    /// A frame is at most ``TailscaleControlFrameCodec/maxFrameSize`` bytes and
    /// a read returns at most 64 KiB, so anything larger means the peer is not
    /// speaking this protocol.
    private static let maxBufferedBytes = TailscaleControlFrameCodec.maxFrameSize + 64 * 1024

    /// The underlying byte stream.
    private let stream: TailscaleByteStream

    /// Seals outbound records.
    private var sendState: NoiseCipherState

    /// Opens inbound records.
    private var receiveState: NoiseCipherState

    /// Bytes read from the stream that have not been consumed by a frame.
    private var readBuffer = Data()

    /// Whether the one-time early payload check has run.
    private var checkedEarlyPayload = false

    /// The server's early payload JSON, once seen.
    private(set) var earlyPayload: Data?

    /// Whether the connection has been closed.
    private var closed = false

    /// The Noise transcript hash of the handshake that built this connection.
    private(set) var handshakeHash: Data = Data()

    /// Called with the server's early payload when it arrives.
    private let onServerEarlyPayload: (@Sendable (Data) -> Void)?

    /// A logger that never receives key material.
    private let log: @Sendable (String) -> Void

    /// Completes the Noise handshake over an open stream.
    ///
    /// - Parameters:
    ///   - stream: The stream, positioned before the server's response frame.
    ///   - handshake: A handshake whose message 1 has already been sent.
    ///   - onServerEarlyPayload: Called with the server's early payload JSON.
    ///   - log: A logger.
    /// - Throws: ``TailscaleControlError`` on any failure.
    init(stream: TailscaleByteStream,
         handshake: NoiseIKHandshake,
         onServerEarlyPayload: (@Sendable (Data) -> Void)? = nil,
         log: @escaping @Sendable (String) -> Void = { _ in }) async throws {
        self.stream = stream
        self.onServerEarlyPayload = onServerEarlyPayload
        self.log = log
        self.sendState = try NoiseCipherState(key: Data(repeating: 0, count: NoiseCipherState.keySize))
        self.receiveState = try NoiseCipherState(key: Data(repeating: 0, count: NoiseCipherState.keySize))

        // Read the server's response frame. Any bytes after it stay in the
        // buffer, so a server that packs its first record into the same segment
        // as its response does not lose it.
        try await fill(until: TS2021.responseSize)
        let frame = Data(readBuffer.prefix(TS2021.responseSize))
        readBuffer.removeFirst(TS2021.responseSize)

        let payload: Data
        do {
            payload = try TS2021HandshakeMessage.parseResponse(frame)
        } catch {
            await stream.close()
            throw error
        }

        let noisePayload: Data
        let keys: (send: NoiseCipherState, receive: NoiseCipherState)
        do {
            noisePayload = try handshake.readMessage2(payload)
            keys = try handshake.split()
        } catch {
            await stream.close()
            throw TailscaleControlError.handshakeFailed(String(describing: error))
        }
        if !noisePayload.isEmpty {
            log("tailscale: the server sent \(noisePayload.count) bytes in the handshake payload")
        }

        self.sendState = keys.send
        self.receiveState = keys.receive
        self.handshakeHash = handshake.handshakeHash
        log("tailscale: handshake complete")
    }

    /// Creates a connection that has already finished its handshake.
    ///
    /// - Parameters:
    ///   - stream: The stream, positioned at the first record.
    ///   - send: The state to seal outbound records with.
    ///   - receive: The state to open inbound records with.
    ///   - log: A logger.
    init(stream: TailscaleByteStream,
         send: NoiseCipherState,
         receive: NoiseCipherState,
         log: @escaping @Sendable (String) -> Void = { _ in }) {
        self.stream = stream
        self.sendState = send
        self.receiveState = receive
        self.onServerEarlyPayload = nil
        self.log = log
    }

    // MARK: - Records

    /// Seals and writes one record.
    ///
    /// - Parameter json: The record payload.
    /// - Throws: ``TailscaleControlError`` when it does not fit or the stream
    ///   is broken.
    func sendRecord(_ json: Data) async throws {
        guard !closed else { throw TailscaleControlError.closed }
        guard json.count <= TailscaleControlFrameCodec.maxRecordPayloadSize else {
            throw TailscaleControlError.recordTooLarge(json.count)
        }

        let ciphertext: Data
        do {
            ciphertext = try sendState.encryptWithAd(json, ad: Data())
        } catch {
            throw TailscaleControlError.transportFailed("sealing a record failed: \(error)")
        }

        let frame = try TailscaleControlFrameCodec.encode(.record(ciphertext))
        do {
            try await stream.write(frame)
        } catch let error as TailscaleControlError {
            closed = true
            throw error
        } catch {
            closed = true
            throw TailscaleControlError.transportFailed(error.localizedDescription)
        }
    }

    /// Reads records until a real one turns up, answering keepalives on the way.
    ///
    /// - Throws: ``TailscaleControlError`` when the stream is broken.
    /// - Returns: The next record payload.
    func receiveRecord() async throws -> Data {
        while true {
            guard !closed else { throw TailscaleControlError.closed }
            try await consumeEarlyPayloadIfPresent()

            if let frame = try TailscaleControlFrameCodec.decode(&readBuffer) {
                switch frame {
                case .record(let ciphertext):
                    do {
                        return try receiveState.decryptWithAd(ciphertext, ad: Data())
                    } catch {
                        closed = true
                        throw TailscaleControlError.transportFailed(
                            "a record did not authenticate; the stream is out of step")
                    }
                case .ping(let payload):
                    // A peer that pings expects the payload back. Answering is
                    // this layer's job: the record stream above must never see
                    // it, and a peer that gets no pong drops the connection.
                    try await writeFrame(.pong(payload))
                    continue
                case .pong:
                    continue
                }
            }

            try await fill()
        }
    }

    /// Closes the stream.
    func close() async {
        guard !closed else { return }
        closed = true
        await stream.close()
    }

    // MARK: - Internals

    /// Writes one frame, whatever its type.
    ///
    /// - Parameter frame: The frame.
    /// - Throws: ``TailscaleControlError`` when the stream is broken.
    private func writeFrame(_ frame: TailscaleControlFrame) async throws {
        let encoded = try TailscaleControlFrameCodec.encode(frame)
        do {
            try await stream.write(encoded)
        } catch let error as TailscaleControlError {
            closed = true
            throw error
        } catch {
            closed = true
            throw TailscaleControlError.transportFailed(error.localizedDescription)
        }
    }

    /// Reads one chunk from the stream into ``readBuffer``.
    ///
    /// - Throws: ``TailscaleControlError/streamClosed`` at end of stream, or
    ///   ``TailscaleControlError/transportFailed(_:)``.
    private func fill() async throws {
        let chunk: Data?
        do {
            chunk = try await stream.read()
        } catch let error as TailscaleControlError {
            closed = true
            throw error
        } catch {
            closed = true
            throw TailscaleControlError.transportFailed(error.localizedDescription)
        }
        guard let chunk, !chunk.isEmpty else {
            closed = true
            throw TailscaleControlError.streamClosed
        }
        readBuffer.append(chunk)
        guard readBuffer.count <= TS2021Connection.maxBufferedBytes else {
            closed = true
            throw TailscaleControlError.frameTooLarge(readBuffer.count)
        }
    }

    /// Reads until the buffer holds at least `count` bytes.
    ///
    /// - Parameter count: The number of bytes wanted.
    /// - Throws: ``TailscaleControlError/streamClosed`` when the stream ends
    ///   first.
    private func fill(until count: Int) async throws {
        while readBuffer.count < count {
            try await fill()
        }
    }

    /// Consumes the server's optional early payload, once.
    ///
    /// Tailscale and Headscale both write nine bytes — the magic `\xff\xff\xffTS`
    /// and a four byte big endian length — followed by JSON, immediately after
    /// the handshake and before the first record. The first byte of that magic
    /// is not a valid frame type, so the check is unambiguous; and because the
    /// payload is optional, the check is only made once there is something to
    /// look at rather than blocking for it.
    ///
    /// - Throws: ``TailscaleControlError/malformedFrame(_:)`` when the bytes
    ///   start with the magic but are not a well formed payload.
    private func consumeEarlyPayloadIfPresent() async throws {
        guard !checkedEarlyPayload else { return }

        try await fill(until: 1)
        guard readBuffer.first == TS2021.earlyPayloadMagic.first else {
            checkedEarlyPayload = true
            return
        }

        try await fill(until: TS2021.earlyPayloadHeaderSize)
        guard readBuffer.prefix(TS2021.earlyPayloadMagic.count) == TS2021.earlyPayloadMagic else {
            closed = true
            throw TailscaleControlError.malformedFrame("the stream does not start with a frame or an early payload")
        }
        let header = [UInt8](readBuffer.prefix(TS2021.earlyPayloadHeaderSize))
        let length = Int(header[5]) << 24 | Int(header[6]) << 16 | Int(header[7]) << 8 | Int(header[8])
        guard length <= TS2021Connection.maxEarlyPayloadSize else {
            closed = true
            throw TailscaleControlError.frameTooLarge(length)
        }
        try await fill(until: TS2021.earlyPayloadHeaderSize + length)

        let json = Data(readBuffer.dropFirst(TS2021.earlyPayloadHeaderSize).prefix(length))
        readBuffer.removeFirst(TS2021.earlyPayloadHeaderSize + length)
        checkedEarlyPayload = true
        earlyPayload = json
        log("tailscale: the server sent a \(length) byte early payload")
        onServerEarlyPayload?(json)
    }
}

/// Where a login server URL says to connect.
struct ConnectionTarget {

    /// The host name or address.
    let host: String

    /// The port to dial.
    let port: UInt16

    /// Whether to wrap the connection in TLS.
    let useTLS: Bool

    /// The value for the `Host` header: `host`, or `host:port` when the port is
    /// not the scheme's default.
    var hostHeader: String {
        let isDefaultPort = (useTLS && port == 443) || (!useTLS && port == 80)
        return isDefaultPort ? host : "\(host):\(port)"
    }

    /// Parses a login server URL.
    ///
    /// - Parameter loginServer: The URL.
    /// - Throws: ``TailscaleControlError/invalidLoginServer(_:)`` when it has no
    ///   usable host, or a scheme this engine does not speak.
    init(loginServer: URL) throws {
        guard let components = URLComponents(url: loginServer, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              let urlHost = components.host, !urlHost.isEmpty else {
            throw TailscaleControlError.invalidLoginServer(loginServer.absoluteString)
        }

        switch scheme {
        case "https", "wss":
            self.useTLS = true
            self.port = UInt16(components.port ?? 443) ?? 443
        case "http", "ws":
            self.useTLS = false
            self.port = UInt16(components.port ?? 80) ?? 80
        default:
            throw TailscaleControlError.invalidLoginServer(
                "unsupported scheme \(scheme); use http, https, ws or wss")
        }
        self.host = urlHost
    }
}
