//
//  TailscaleControlTestServer.swift
//  VPNEngine
//
//  The *server* half of the ts2021 control protocol, in process, so the client
//  can be driven end to end without Go, Headscale, a certificate or a network.
//
//  It is a faithful peer rather than a mock: it serves `GET /key`, it accepts
//  the HTTP/1.1 upgrade, it runs the Noise responder side of the handshake, and
//  it frames records exactly as `control/controlbase` does. What it does *not*
//  do is anything above the record layer — there is no HTTP/2, no registration
//  and no map stream. Records are bytes in and bytes out.
//
//  Two details are deliberately hostile, because they are the ones a client
//  gets wrong:
//
//   * The `101 Switching Protocols` headers, the Noise response frame and the
//     first record are written in a **single** `send`, so a client that reads
//     the headers with one `receive` and throws the rest away loses data.
//   * The optional early payload can be switched on with
//     ``sendsEarlyPayload``, so the client has to cope with bytes that precede
//     the first record.
//
//  References:
//   * `control/controlhttp/controlhttpserver/controlhttpserver.go` and
//     `control/controlbase/handshake.go` in
//     https://github.com/tailscale/tailscale (BSD-3-Clause)
//   * Headscale's `hscontrol/noise.go` and `hscontrol/handlers.go` in
//     https://github.com/juanfont/headscale (BSD-3-Clause)
//

import Foundation
import Network

/// A `tailcfg.RegisterRequest`-shaped record, decoded leniently.
///
/// Every field is optional because this type exists to let a test assert on
/// what a client sent, not to validate it. The JSON keys are `tailcfg`'s Go
/// spelling.
public struct TS2021RegisterRequest: Codable, Sendable, Equatable {

    /// The `Auth` object, which carries a pre-authorisation key.
    public struct Auth: Codable, Sendable, Equatable {

        /// The pre-authorisation key, if the client sent one.
        public var authKey: String?

        /// Creates an auth object.
        ///
        /// - Parameter authKey: The pre-authorisation key.
        public init(authKey: String? = nil) {
            self.authKey = authKey
        }

        enum CodingKeys: String, CodingKey {
            case authKey = "AuthKey"
        }
    }

    /// The client's capability version.
    public var version: Int?

    /// The client's node public key, as `tailcfg` spells it.
    public var nodeKey: String?

    /// The node key being replaced, when the client is re-registering.
    public var oldNodeKey: String?

    /// The authentication material.
    public var auth: Auth?

    /// How the client wants to follow up: `"authURL"` or `"restart"`.
    public var followup: String?

    /// Whether the node is ephemeral.
    public var ephemeral: Bool?

    /// Creates a register request.
    ///
    /// - Parameters:
    ///   - version: The capability version.
    ///   - nodeKey: The node public key.
    ///   - oldNodeKey: The previous node key.
    ///   - auth: The authentication material.
    ///   - followup: The follow-up mode.
    ///   - ephemeral: Whether the node is ephemeral.
    public init(version: Int? = nil,
                nodeKey: String? = nil,
                oldNodeKey: String? = nil,
                auth: Auth? = nil,
                followup: String? = nil,
                ephemeral: Bool? = nil) {
        self.version = version
        self.nodeKey = nodeKey
        self.oldNodeKey = oldNodeKey
        self.auth = auth
        self.followup = followup
        self.ephemeral = ephemeral
    }

    enum CodingKeys: String, CodingKey {
        case version = "Version"
        case nodeKey = "NodeKey"
        case oldNodeKey = "OldNodeKey"
        case auth = "Auth"
        case followup = "Followup"
        case ephemeral = "Ephemeral"
    }

    /// Decodes a record that looks like a register request.
    ///
    /// `tailcfg` has no discriminator: a register request and a map request are
    /// both bare JSON objects, and the only structural difference is which
    /// fields they carry. A record is taken to be a register request when it
    /// has a `NodeKey` and no `Stream` field, which is how the two are told
    /// apart here.
    ///
    /// - Parameter record: The record payload.
    /// - Returns: The decoded request, or `nil` when the record is not one.
    public static func decode(from record: Data) -> TS2021RegisterRequest? {
        guard let object = try? JSONSerialization.jsonObject(with: record) as? [String: Any] else {
            return nil
        }
        guard object["NodeKey"] != nil, object["Stream"] == nil else { return nil }
        return try? JSONDecoder().decode(TS2021RegisterRequest.self, from: record)
    }
}

/// An in-process Tailscale control server.
///
/// The server listens on a plain TCP socket: no TLS, so the tests need no
/// certificates. The client's TLS path is exercised separately by
/// ``TailscaleHTTPUpgrade``'s `useTLS` parameter and its `tlsTrust` handler.
///
/// The type is safe to call from several threads; every piece of mutable state
/// is behind one lock, and the blocking socket helpers live on their own
/// threads.
public final class TailscaleControlTestServer: @unchecked Sendable {

    // MARK: - Configuration

    /// The host the listener is bound to.
    public let host: String

    /// The port the listener is bound to.
    public let port: UInt16

    /// The server's Noise static key pair.
    public let serverKeyPair: (privateKey: Data, publicKey: Data)

    /// The server's Noise static public key, as served from `/key`.
    public var serverKey: TailscaleServerKey {
        TailscaleServerKey(publicKey: serverKeyPair.publicKey)
    }

    /// The base URL a client should be pointed at.
    public var loginServerURL: URL {
        URL(string: "http://\(host):\(port)")!
    }

    /// Whether the server writes the optional early payload after the
    /// handshake.
    ///
    /// Set before the client connects. Tailscale and Headscale both do send
    /// one, so a client has to cope with it.
    public var sendsEarlyPayload: Bool = true

    /// Whether the server answers the upgrade with a status other than 101.
    ///
    /// Set to, say, `403` to check that a client fails with a typed error
    /// rather than hanging.
    public var rejectUpgradeWithStatus: Int?

    /// The JSON the server sends as its early payload.
    public var earlyPayload: Data = Data(
        #"{"nodeKeyChallenge":"chalpub:0000000000000000000000000000000000000000000000000000000000000000"}"#.utf8)

    /// The protocol version the server saw in the initiation frame.
    public private(set) var observedProtocolVersion: UInt16?

    /// The prologue the server mixed, for asserting that both sides agreed.
    public private(set) var observedPrologue: Data?

    // MARK: - State

    /// Everything mutable, behind one lock.
    private final class State: @unchecked Sendable {
        let lock = NSCondition()
        var records: [Data] = []
        var pongs: [Data] = []
        var queued: [Data] = []
        var connectionCount = 0
    }

    private let state = State()

    /// The listener.
    private let listener: NWListener

    /// The queue the listener delivers on.
    private let listenerQueue = DispatchQueue(label: "com.vpnengine.tailscale.testserver.listener")

    /// The live connection, if any.
    private let live = LiveConnection()

    /// A reference-counted box for the connection the server is serving.
    private final class LiveConnection: @unchecked Sendable {
        let lock = NSLock()
        var connection: ServerConnection?
    }

    // MARK: - Creation

    /// Starts a server on `host`, on a port the system picks.
    ///
    /// - Parameter host: The interface to bind. Defaults to loopback.
    /// - Throws: ``TailscaleControlError/upgradeFailed(_:)`` when the listener
    ///   cannot start.
    public init(host: String = "127.0.0.1") throws {
        self.host = host
        self.serverKeyPair = NoiseIKHandshake.generateStatic()

        let parameters = NWParameters(tls: nil, tcp: NWProtocolTCP.Options())
        parameters.allowLocalEndpointReuse = true
        let listener: NWListener
        do {
            listener = try NWListener(using: parameters, on: .any)
        } catch {
            throw TailscaleControlError.upgradeFailed("the test listener could not be created: \(error)")
        }
        let ready = DispatchSemaphore(value: 0)
        let boundPort = PortBox()
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                boundPort.set(listener.port?.rawValue ?? 0)
                ready.signal()
            case .failed(let error):
                boundPort.setFailure("the test listener failed: \(error)")
                ready.signal()
            default:
                break
            }
        }
        self.listener = listener
        listener.start(queue: listenerQueue)

        guard ready.wait(timeout: .now() + 10) == .success else {
            listener.cancel()
            throw TailscaleControlError.upgradeFailed("the test listener did not start")
        }
        if let failure = boundPort.failure {
            listener.cancel()
            throw TailscaleControlError.upgradeFailed(failure)
        }
        guard let port = UInt16(exactly: boundPort.value), port != 0 else {
            listener.cancel()
            throw TailscaleControlError.upgradeFailed("the test listener bound no port")
        }
        self.port = port

        // Wired only now: capturing `self` before `port` was assigned is what the
        // compiler rejects, and there is no reason for the handler to exist earlier.
        listener.newConnectionHandler = { [weak self] connection in
            self?.accept(connection)
        }
    }

    /// The port the listener bound, shared with the state handler.
    private final class PortBox: @unchecked Sendable {
        private let lock = NSLock()
        private var storedValue = 0
        private var storedFailure: String?

        var value: Int {
            lock.lock(); defer { lock.unlock() }
            return storedValue
        }

        var failure: String? {
            lock.lock(); defer { lock.unlock() }
            return storedFailure
        }

        func set(_ newValue: UInt16) {
            lock.lock(); defer { lock.unlock() }
            storedValue = Int(newValue)
        }

        func setFailure(_ message: String) {
            lock.lock(); defer { lock.unlock() }
            storedFailure = message
        }
    }

    // MARK: - Test hooks

    /// The records the server has received, in order.
    public var receivedRecords: [Data] {
        state.lock.lock(); defer { state.lock.unlock() }
        return state.records
    }

    /// The ping payloads the server has seen echoed back, in order.
    public var receivedPongs: [Data] {
        state.lock.lock(); defer { state.lock.unlock() }
        return state.pongs
    }

    /// The register requests the server has received, in order.
    public var registerRequests: [TS2021RegisterRequest] {
        receivedRecords.compactMap { TS2021RegisterRequest.decode(from: $0) }
    }

    /// The most recent register request, if any.
    public var lastRegisterRequest: TS2021RegisterRequest? {
        registerRequests.last
    }

    /// How many connections the server has accepted.
    public var connectionCount: Int {
        state.lock.lock(); defer { state.lock.unlock() }
        return state.connectionCount
    }

    /// Queues records to send once the client's handshake completes.
    ///
    /// Call before the client connects. The records are sealed with the
    /// connection's sending key and written immediately after the Noise
    /// response frame, in the same socket write as the `101` response headers,
    /// which is the packed-segment case.
    ///
    /// - Parameter records: The record payloads.
    public func enqueue(_ records: [Data]) {
        state.lock.lock()
        state.queued.append(contentsOf: records)
        state.lock.unlock()
    }

    /// Sends records on the live connection, right now.
    ///
    /// - Parameter records: The record payloads.
    /// - Returns: `true` when they were written.
    @discardableResult
    public func send(_ records: [Data]) -> Bool {
        guard let connection = currentConnection() else { return false }
        for record in records {
            guard connection.sendRecord(record) else { return false }
        }
        return true
    }

    /// Sends a keepalive and expects the client to echo the payload back.
    ///
    /// The control protocol itself has no ping frame; this exercises the
    /// engine's keepalive handling.
    ///
    /// - Parameter payload: The eight byte payload to have echoed.
    /// - Returns: `true` when it was written.
    @discardableResult
    public func sendPing(_ payload: Data) -> Bool {
        guard let connection = currentConnection() else { return false }
        return connection.sendPing(payload)
    }

    /// Closes the live connection, leaving the listener up.
    ///
    /// This is how a test exercises reconnection: the client's next
    /// ``TailscaleControlTransport/receiveRecord()`` fails rather than hanging.
    public func dropConnection() {
        live.lock.lock()
        let connection = live.connection
        live.lock.unlock()
        connection?.close()
    }

    /// Waits until the server has received at least `count` records.
    ///
    /// - Parameters:
    ///   - count: How many records to wait for.
    ///   - timeout: How long to wait.
    /// - Returns: `true` when the records arrived.
    public func waitForRecords(_ count: Int, timeout: TimeInterval = 5) -> Bool {
        state.lock.lock()
        defer { state.lock.unlock() }
        let deadline = Date().addingTimeInterval(timeout)
        while state.records.count < count {
            guard state.lock.wait(until: deadline) else { return state.records.count >= count }
        }
        return true
    }

    /// Waits until the server has received at least `count` pongs.
    ///
    /// - Parameters:
    ///   - count: How many pongs to wait for.
    ///   - timeout: How long to wait.
    /// - Returns: `true` when the pongs arrived.
    public func waitForPongs(_ count: Int, timeout: TimeInterval = 5) -> Bool {
        state.lock.lock()
        defer { state.lock.unlock() }
        let deadline = Date().addingTimeInterval(timeout)
        while state.pongs.count < count {
            guard state.lock.wait(until: deadline) else { return state.pongs.count >= count }
        }
        return true
    }

    /// Stops the listener and closes any live connection.
    public func stop() {
        listener.cancel()
        dropConnection()
    }

    // MARK: - Internals

    /// The live connection, if the server has one.
    private func currentConnection() -> ServerConnection? {
        live.lock.lock()
        defer { live.lock.unlock() }
        return live.connection
    }

    /// Accepts a new connection and serves it on its own thread.
    ///
    /// A thread rather than a task, because the server half reads its socket
    /// with blocking calls; that keeps the request/response flow in one place
    /// instead of spread over continuation callbacks.
    private func accept(_ connection: NWConnection) {
        state.lock.lock()
        state.connectionCount += 1
        state.lock.unlock()

        let server = ServerConnection(connection: connection,
                                      server: self,
                                      serverKeyPair: serverKeyPair)
        live.lock.lock()
        live.connection = server
        live.lock.unlock()

        let thread = Thread { [weak self] in
            server.serve()
            self?.live.lock.lock()
            if self?.live.connection === server {
                self?.live.connection = nil
            }
            self?.live.lock.unlock()
        }
        thread.stackSize = 1 << 20
        thread.start()
    }

    /// Records a received record and wakes anybody waiting.
    fileprivate func recordReceived(_ record: Data) {
        state.lock.lock()
        state.records.append(record)
        state.lock.broadcast()
        state.lock.unlock()
    }

    /// Records a received pong and wakes anybody waiting.
    fileprivate func pongReceived(_ payload: Data) {
        state.lock.lock()
        state.pongs.append(payload)
        state.lock.broadcast()
        state.lock.unlock()
    }

    /// Takes the queued records, leaving the queue empty.
    fileprivate func drainQueued() -> [Data] {
        state.lock.lock()
        defer { state.lock.unlock() }
        let queued = state.queued
        state.queued = []
        return queued
    }

    /// Records what the handshake saw, for assertions.
    fileprivate func noteHandshake(protocolVersion: UInt16, prologue: Data) {
        observedProtocolVersion = protocolVersion
        observedPrologue = prologue
    }
}

/// One accepted connection, served on a dedicated thread.
///
/// The socket calls are `NWConnection`'s asynchronous ones; the blocking
/// wrappers below use a condition variable, with `NWConnection`'s callbacks
/// arriving on a queue of their own so that the two never wait on each other.
private final class ServerConnection: @unchecked Sendable {

    private let connection: NWConnection
    private weak var server: TailscaleControlTestServer?
    private let serverKeyPair: (privateKey: Data, publicKey: Data)

    /// The queue `NWConnection` delivers reads on.
    private let callbackQueue = DispatchQueue(label: "com.vpnengine.tailscale.testserver.connection")

    /// Guards ``buffer``, ``incoming``, ``ended``, ``writeError``.
    private let condition = NSCondition()

    /// Bytes read and not yet consumed.
    private var buffer = Data()

    /// Chunks delivered by the callback and not yet moved into ``buffer``.
    private var incoming: [Data] = []

    /// Whether the stream has ended.
    private var ended = false

    /// Serialises writes, so that two threads cannot interleave frames.
    private let writeLock = NSLock()

    /// The state to seal outbound records with, once the handshake has run.
    private var sendState: NoiseCipherState?

    /// The state to open inbound records with.
    private var receiveState: NoiseCipherState?

    /// How long a blocking read waits before giving up.
    private let readTimeout: TimeInterval = 10

    init(connection: NWConnection,
         server: TailscaleControlTestServer,
         serverKeyPair: (privateKey: Data, publicKey: Data)) {
        self.connection = connection
        self.server = server
        self.serverKeyPair = serverKeyPair
    }

    // MARK: - Serving

    /// Runs the whole connection: request, upgrade, handshake, then records.
    func serve() {
        pump()
        connection.start(queue: callbackQueue)
        defer { close() }

        guard let head = readRequestHead() else { return }
        guard let request = HTTPRequestHead(head: head) else { return }

        if request.path.hasPrefix(TS2021.keyPath) {
            respondWithServerKey()
            return
        }
        guard request.path.hasPrefix(TS2021.upgradePath) else {
            write(Data("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".utf8))
            return
        }
        guard request.header("upgrade")?.lowercased() == TS2021.upgradeHeaderValue else {
            write(Data("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".utf8))
            return
        }
        if let status = server?.rejectUpgradeWithStatus {
            write(Data("HTTP/1.1 \(status) Rejected\r\nContent-Length: 0\r\n\r\n".utf8))
            return
        }
        guard let headerValue = request.header(TS2021.handshakeHeaderName.lowercased()),
              let initiation = Data(base64Encoded: headerValue) else {
            write(Data("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".utf8))
            return
        }
        upgrade(with: initiation)
    }

    /// Answers `GET /key`.
    private func respondWithServerKey() {
        let hex = serverKeyPair.publicKey.map { String(format: "%02x", $0) }.joined()
        let body = Data(#"{"publicKey":"mkey:\#(hex)"}"#.utf8)
        var response = "HTTP/1.1 200 OK\r\n"
        response += "Content-Type: application/json\r\n"
        response += "Content-Length: \(body.count)\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"
        var bytes = Data(response.utf8)
        bytes.append(body)
        write(bytes)
    }

    /// Runs the Noise responder handshake and the record loop.
    ///
    /// - Parameter initiation: The 101 byte initiation frame from the header.
    private func upgrade(with initiation: Data) {
        let version: UInt16
        let message1: Data
        do {
            let parsed = try TS2021HandshakeMessage.parseInitiation(initiation)
            version = parsed.protocolVersion
            message1 = parsed.payload
        } catch {
            write(Data("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".utf8))
            return
        }

        let prologue = TS2021.prologue(protocolVersion: Int(version))
        let parameters = NoiseIKParameters(protocolName: NoiseIKHandshake.protocolName,
                                           prologue: prologue,
                                           localStatic: serverKeyPair.privateKey,
                                           remoteStatic: Data(),
                                           isInitiator: false)
        let handshake: NoiseIKHandshake
        do {
            handshake = try NoiseIKHandshake(parameters: parameters)
            _ = try handshake.readMessage1(message1)
            let message2 = try handshake.writeMessage2()
            let responseFrame = try TS2021HandshakeMessage.response(payload: message2)
            let keys = try handshake.split()
            sendState = keys.send
            receiveState = keys.receive

            server?.noteHandshake(protocolVersion: version, prologue: prologue)

            // Everything the client needs in one write: the 101 headers, the
            // Noise response, the optional early payload, and any records that
            // were queued before the client connected.
            var out = Data("HTTP/1.1 101 Switching Protocols\r\n".utf8)
            out.append(Data("Upgrade: \(TS2021.upgradeHeaderValue)\r\n".utf8))
            out.append(Data("Connection: upgrade\r\n".utf8))
            out.append(Data("\r\n".utf8))
            out.append(responseFrame)
            if server?.sendsEarlyPayload ?? false, let payload = server?.earlyPayload {
                out.append(TS2021.earlyPayloadMagic)
                let length = UInt32(payload.count)
                out.append(UInt8(truncatingIfNeeded: length >> 24))
                out.append(UInt8(truncatingIfNeeded: length >> 16))
                out.append(UInt8(truncatingIfNeeded: length >> 8))
                out.append(UInt8(truncatingIfNeeded: length))
                out.append(payload)
            }
            for record in server?.drainQueued() ?? [] {
                if let frame = try? seal(record) { out.append(frame) }
            }
            write(out)
        } catch {
            write(Data("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".utf8))
            return
        }

        recordLoop()
    }

    /// Reads frames until the stream ends, answering pings.
    private func recordLoop() {
        while true {
            guard let header = readExact(TailscaleControlFrameCodec.headerSize) else { return }
            guard let type = TailscaleControlFrameType(rawValue: header[header.startIndex]),
                  let length = UInt16(exactly: 0) else { return }
            let payloadLength = Int(header[header.startIndex + 1]) << 8 | Int(header[header.startIndex + 2])
            _ = length
            guard let payload = readExact(payloadLength) else { return }

            switch type {
            case .record:
                guard let plaintext = decrypt(payload) else { return }
                server?.recordReceived(plaintext)
            case .ping:
                _ = sendPing(payload)
            case .pong:
                server?.pongReceived(payload)
            case .initiation, .response, .error:
                return
            }
        }
    }

    // MARK: - Frames

    /// Seals a record into a frame.
    private func seal(_ record: Data) throws -> Data {
        guard let sendState else { throw TailscaleControlError.closed }
        let ciphertext = try sendState.encryptWithAd(record, ad: Data())
        return try TailscaleControlFrameCodec.encode(.record(ciphertext))
    }

    /// Opens a record frame.
    private func decrypt(_ ciphertext: Data) -> Data? {
        guard let receiveState else { return nil }
        return try? receiveState.decryptWithAd(ciphertext, ad: Data())
    }

    /// Sends a record on the live connection.
    ///
    /// - Parameter record: The payload.
    /// - Returns: `true` when it was written.
    func sendRecord(_ record: Data) -> Bool {
        guard let frame = try? seal(record) else { return false }
        return write(frame)
    }

    /// Sends a keepalive frame.
    ///
    /// - Parameter payload: The payload to have echoed.
    /// - Returns: `true` when it was written.
    func sendPing(_ payload: Data) -> Bool {
        guard let frame = try? TailscaleControlFrameCodec.encode(.ping(payload)) else { return false }
        return write(frame)
    }

    /// Closes the connection.
    func close() {
        condition.lock()
        ended = true
        condition.broadcast()
        condition.unlock()
        connection.cancel()
    }

    // MARK: - Blocking socket helpers

    /// Starts the receive loop that fills ``incoming``.
    private func pump() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            condition.lock()
            if let data, !data.isEmpty { incoming.append(data) }
            if error != nil || isComplete { ended = true }
            condition.broadcast()
            condition.unlock()
            if error == nil, !isComplete { pump() }
        }
    }

    /// Reads exactly `count` bytes, or `nil` on end of stream or timeout.
    private func readExact(_ count: Int) -> Data? {
        guard count > 0 else { return Data() }
        let deadline = Date().addingTimeInterval(readTimeout)
        condition.lock()
        defer { condition.unlock() }
        while buffer.count < count {
            while buffer.count < count, !incoming.isEmpty {
                buffer.append(incoming.removeFirst())
            }
            if buffer.count >= count { break }
            if ended { return nil }
            guard condition.wait(until: deadline) else { return nil }
        }
        let out = Data(buffer.prefix(count))
        buffer.removeFirst(count)
        return out
    }

    /// Reads until the buffer holds a complete request head.
    private func readRequestHead() -> Data? {
        let deadline = Date().addingTimeInterval(readTimeout)
        condition.lock()
        defer { condition.unlock() }
        while true {
            if let range = buffer.range(of: Data("\r\n\r\n".utf8)) {
                let head = Data(buffer[buffer.startIndex ..< range.upperBound])
                buffer.removeSubrange(buffer.startIndex ..< range.upperBound)
                return head
            }
            while !incoming.isEmpty { buffer.append(incoming.removeFirst()) }
            if let range = buffer.range(of: Data("\r\n\r\n".utf8)) {
                let head = Data(buffer[buffer.startIndex ..< range.upperBound])
                buffer.removeSubrange(buffer.startIndex ..< range.upperBound)
                return head
            }
            if ended { return nil }
            guard condition.wait(until: deadline) else { return nil }
        }
    }

    /// Writes bytes, blocking until the socket has taken them.
    ///
    /// - Parameter data: The bytes.
    /// - Returns: `true` when they were written.
    @discardableResult
    private func write(_ data: Data) -> Bool {
        let done = DispatchSemaphore(value: 0)
        let failed = Flag()
        writeLock.lock()
        connection.send(content: data, completion: .contentProcessed { error in
            failed.value = error != nil
            done.signal()
        })
        writeLock.unlock()
        guard done.wait(timeout: .now() + readTimeout) == .success else { return false }
        return !failed.value
    }

    /// A `Bool` that can be set from a callback.
    private final class Flag: @unchecked Sendable {
        private let lock = NSLock()
        private var stored = false

        var value: Bool {
            get { lock.lock(); defer { lock.unlock() }; return stored }
            set { lock.lock(); stored = newValue; lock.unlock() }
        }
    }
}

/// A parsed HTTP request line and header block.
private struct HTTPRequestHead {

    let method: String
    let path: String
    let headers: [String: String]

    init?(head: Data) {
        let text = String(decoding: head, as: UTF8.self)
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        guard let first = lines.first else { return nil }
        let parts = first.trimmingCharacters(in: .whitespaces).split(separator: " ")
        guard parts.count >= 2 else { return nil }
        method = String(parts[0])
        path = String(parts[1])

        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, let colon = trimmed.firstIndex(of: ":") else { continue }
            let name = trimmed[trimmed.startIndex ..< colon].lowercased()
            let value = trimmed[trimmed.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            headers[name] = value
        }
        self.headers = headers
    }

    /// Looks up a header field.
    ///
    /// - Parameter name: The field name, lowercased.
    /// - Returns: The value, or `nil`.
    func header(_ name: String) -> String? {
        headers[name.lowercased()]
    }
}
