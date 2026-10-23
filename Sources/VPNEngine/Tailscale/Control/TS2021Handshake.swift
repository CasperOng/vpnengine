//
//  TS2021Handshake.swift
//  VPNEngine
//
//  The Tailscale 2021 control protocol handshake, outside the Noise state
//  machine itself: the server key exchange, the HTTP upgrade header, and the
//  fixed size frames the two Noise handshake messages travel in.
//
//  The pieces, in the order a client uses them:
//
//   1. `GET https://<loginServer>/key?v=<capabilityVersion>` returns the
//      server's Noise static public key as JSON:
//
//          {"legacyPublicKey": "mkey:…", "publicKey": "mkey:…"}
//
//      This exchange is deliberately *not* protected by Noise, which is why
//      Tailscale calls the type `OverTLSPublicKeyResponse` and warns that it
//      "doesn't happen over Noise and can be intercepted/MITM'ed by
//      enterprise/corp proxies".
//
//   2. The client builds Noise message 1 and sends it base64-encoded in the
//      `X-Tailscale-Handshake` header of an HTTP/1.1 upgrade request. Sending
//      it inside the request rather than after the 101 response saves a round
//      trip, which is why `ClientDeferred` exists in the Go client.
//
//   3. The server answers `101 Switching Protocols` and writes Noise message 2
//      as raw bytes on the same socket, immediately after the response headers
//      and *not* in a header of its own.
//
//   4. The server may then write an optional "early payload" before any
//      records: nine bytes of `FF FF FF 54 53` (the ASCII string `\xff\xff\xffTS`)
//      followed by a four byte big endian length and that many bytes of JSON.
//
//  References:
//   * `control/controlbase/handshake.go` and `control/controlbase/messages.go`
//     in https://github.com/tailscale/tailscale (BSD-3-Clause)
//   * `control/controlhttp/client.go` and `control/controlhttp/controlhttpcommon`
//     in the same repository
//   * `control/ts2021/conn.go` for the early payload
//   * `tailcfg.OverTLSPublicKeyResponse` in `tailcfg/tailcfg.go`
//   * Headscale's server half: `hscontrol/noise.go` and `hscontrol/handlers.go`
//     in https://github.com/juanfont/headscale (BSD-3-Clause)
//

import Foundation

/// Everything that can go wrong talking to a Tailscale or Headscale control
/// server.
///
/// Malformed network input always produces one of these rather than a trap, and
/// a broken stream always produces one rather than a hang.
public enum TailscaleControlError: Error, Equatable, Sendable {

    /// The login server URL is not something this engine can dial.
    case invalidLoginServer(String)

    /// The `/key` response was not a usable server public key.
    case invalidServerKey(String)

    /// The `/key` request failed.
    case serverKeyFetchFailed(status: Int, body: String?)

    /// The HTTP upgrade was answered with something other than 101.
    case upgradeRejected(status: Int, reason: String?)

    /// The HTTP upgrade could not be completed (connection, TLS, or parsing).
    case upgradeFailed(String)

    /// The server's upgrade response did not have the headers the protocol
    /// requires.
    case invalidUpgradeResponse(String)

    /// The Noise handshake failed.
    case handshakeFailed(String)

    /// A frame's type byte is not one this protocol defines.
    case unexpectedFrameType(UInt8)

    /// A frame claims a payload larger than the protocol allows.
    case frameTooLarge(Int)

    /// A frame was structurally impossible.
    case malformedFrame(String)

    /// A record from the transport was not a control message of any known type.
    ///
    /// - Parameter excerpt: The first characters of the record, for diagnosis.
    ///   Only ever a prefix: a record can be megabytes.
    case malformedRecord(String)

    /// A record looked like the one-key envelope form, but the inner value could
    /// not be re-encoded for decoding.
    ///
    /// - Parameter key: The envelope key that was found.
    case malformedEnvelope(String)

    /// The transport closed or failed while the session needed it.
    ///
    /// - Parameter reason: A human readable explanation.
    case transportFailure(String)

    /// The caller asked to send a record that does not fit one frame.
    case recordTooLarge(Int)

    /// The stream ended. The caller reconnects.
    case streamClosed

    /// The underlying connection failed.
    case transportFailed(String)

    /// The transport has been closed locally.
    case closed
}

/// The server's Noise static public key, as returned by `/key`.
public struct TailscaleServerKey: Sendable, Equatable {

    /// The server's 32 byte X25519 static public key.
    public let publicKey: Data

    /// When the key expires, when the server said.
    ///
    /// Current Tailscale and Headscale servers do not send an expiry at all, so
    /// this is normally `nil`.
    public let expiry: Date?

    /// Creates a server key.
    ///
    /// - Parameters:
    ///   - publicKey: The 32 byte public key.
    ///   - expiry: The optional expiry.
    public init(publicKey: Data, expiry: Date? = nil) {
        self.publicKey = publicKey
        self.expiry = expiry
    }
}

/// The JSON payload the *initiator* may place inside Noise message 1.
///
/// The field names match `tailcfg`'s Go spelling, because they are the JSON
/// keys on the wire.
///
/// Note that Tailscale's own client sends an **empty** payload here, and
/// Tailscale's server rejects an initiation whose length is not exactly 96
/// bytes, so a payload supplied here will only be understood by a peer that
/// agrees to it. The in-repo test server does, which is what the round trip
/// test uses. Leaving it `nil` is what interoperates.
public struct TS2021EarlyPayload: Codable, Sendable, Equatable {

    /// The client's node public key, in the hex form `tailcfg` uses.
    public var nodeKey: String

    /// The client's capability version.
    public var version: Int

    /// Creates an early payload.
    ///
    /// - Parameters:
    ///   - nodeKey: The node public key, hex encoded.
    ///   - version: The capability version.
    public init(nodeKey: String, version: Int) {
        self.nodeKey = nodeKey
        self.version = version
    }

    enum CodingKeys: String, CodingKey {
        case nodeKey = "NodeKey"
        case version = "Version"
    }

    /// Encodes the payload as the JSON that travels inside the Noise message.
    ///
    /// - Throws: An encoding error.
    /// - Returns: The JSON bytes.
    public func encoded() throws -> Data {
        try JSONEncoder().encode(self)
    }
}

/// The JSON the *server* may send as its early payload, after the handshake and
/// before any records.
///
/// This is the real early payload (`tailcfg.EarlyNoise`), and it is a different
/// shape from ``TS2021EarlyPayload``: the server sends a per-connection public
/// key the client later proves possession of its node key against. The
/// transport hands the bytes to the caller and does not interpret them.
public struct TS2021ServerEarlyPayload: Codable, Sendable, Equatable {

    /// The per-connection challenge public key, in the `chalpub:` hex form.
    public var nodeKeyChallenge: String?

    /// Creates a server early payload.
    ///
    /// - Parameter nodeKeyChallenge: The challenge public key.
    public init(nodeKeyChallenge: String? = nil) {
        self.nodeKeyChallenge = nodeKeyChallenge
    }

    enum CodingKeys: String, CodingKey {
        case nodeKeyChallenge
    }
}

/// A client handshake in progress: the Noise state machine plus the framed
/// first message that has already been built from it.
public struct TS2021ClientHandshake: Sendable {

    /// The Noise handshake, positioned after message 1.
    public let handshake: NoiseIKHandshake

    /// The framed 101 byte initiation message.
    public let message1: Data

    /// `message1`, base64 encoded, for the `X-Tailscale-Handshake` header.
    public let headerValue: String
}

/// The ts2021 protocol's fixed points: paths, header names, message sizes and
/// the two calls that need no connection state.
public enum TS2021 {

    // MARK: - Paths and header names

    /// The path the upgrade request goes to.
    public static let upgradePath = "/ts2021"

    /// The path the server's Noise static key is fetched from.
    public static let keyPath = "/key"

    /// The `Upgrade` header value that selects the control protocol.
    public static let upgradeHeaderValue = "tailscale-control-protocol"

    /// The request header that carries base64 message 1.
    public static let handshakeHeaderName = "X-Tailscale-Handshake"

    // MARK: - Handshake messages

    /// The Noise handshake initiation is 96 bytes of payload plus a five byte
    /// header.
    public static let initiationSize = 101

    /// The initiation's payload: `e ‖ enc(s) ‖ tag`.
    public static let initiationPayloadSize = 96

    /// The Noise handshake response is 48 bytes of payload plus a three byte
    /// header.
    public static let responseSize = 51

    /// The response's payload: `e ‖ tag`.
    public static let responsePayloadSize = 48

    // MARK: - Early payload

    /// The five byte magic that marks the server's early payload.
    ///
    /// Chosen so that it cannot be confused with an HTTP/2 frame: the first
    /// byte is not a valid HTTP/2 frame type. `control/ts2021/conn.go` spells it
    /// `"\xff\xff\xffTS"`.
    public static let earlyPayloadMagic = Data([0xFF, 0xFF, 0xFF, 0x54, 0x53])

    /// The early payload header is the five byte magic plus a four byte big
    /// endian length.
    public static let earlyPayloadHeaderSize = 9

    // MARK: - Prologue

    /// The prologue prefix both sides mix into the transcript.
    ///
    /// The prologue is *not* a constant: it is this prefix followed by the
    /// decimal protocol version, which for a control client is its capability
    /// version. `control/controlbase/handshake.go` builds it with
    /// `protocolVersionPrologue`, and comments that mixing it "verifies that
    /// both clients agree that they're executing the control protocol at a
    /// specific version that matches the advertised version in the cleartext
    /// packet header".
    public static let prologuePrefix = "Tailscale Control Protocol v"

    /// The prologue for a given protocol version.
    ///
    /// - Parameter protocolVersion: The version, which the initiation frame
    ///   also carries as a two byte field.
    /// - Returns: `"Tailscale Control Protocol v" ‖ decimal version`.
    public static func prologue(protocolVersion: Int) -> Data {
        Data((prologuePrefix + String(protocolVersion)).utf8)
    }

    /// The prologue of protocol version 1.
    ///
    /// This is the version-independent *first* version of the protocol, and the
    /// value an implementation that ignores capability versions uses. Prefer
    /// ``prologue(protocolVersion:)``: Tailscale and Headscale both put the
    /// client's capability version here, and Headscale refuses a handshake from
    /// a version below its floor.
    public static let prologue = Data("Tailscale Control Protocol v1".utf8)

    // MARK: - Server key

    /// Fetches the server's Noise static public key.
    ///
    /// This is a plain HTTPS `GET`; the response is JSON and is *not*
    /// authenticated by Noise, so a caller that cares should pin the key it
    /// expects rather than trusting the first answer it gets.
    ///
    /// - Parameters:
    ///   - loginServer: The control server's base URL, for example
    ///     `https://headscale.example.com`.
    ///   - capabilityVersion: The client's capability version, sent as `?v=`.
    ///   - session: The URL session to use. Inject one with a delegate to trust
    ///     a private CA.
    /// - Throws: ``TailscaleControlError`` when the URL is unusable, the
    ///   request fails, or the response is not a server key.
    /// - Returns: The server's static public key.
    public static func fetchServerKey(loginServer: URL,
                                      capabilityVersion: Int,
                                      session: URLSession = .shared) async throws -> TailscaleServerKey {
        guard var components = URLComponents(url: loginServer, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              let host = components.host, !host.isEmpty else {
            throw TailscaleControlError.invalidLoginServer(loginServer.absoluteString)
        }
        guard capabilityVersion > 0, capabilityVersion <= Int(UInt16.max) else {
            throw TailscaleControlError.invalidLoginServer("capability version \(capabilityVersion) does not fit the protocol's two byte field")
        }

        components.path = (components.path.hasSuffix("/")
            ? String(components.path.dropLast())
            : components.path) + keyPath
        components.queryItems = [URLQueryItem(name: "v", value: String(capabilityVersion))]
        components.fragment = nil
        guard let url = components.url else {
            throw TailscaleControlError.invalidLoginServer(loginServer.absoluteString)
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw TailscaleControlError.serverKeyFetchFailed(status: 0, body: error.localizedDescription)
        }

        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard status == 200 else {
            let body = String(data: data.prefix(512), encoding: .utf8)
            throw TailscaleControlError.serverKeyFetchFailed(status: status, body: body)
        }
        return try parseServerKeyResponse(data)
    }

    /// Parses a `/key` response body.
    ///
    /// Two shapes are accepted, matching `loadServerPubKeys` in the Go client:
    ///
    ///  * the current JSON, `{"publicKey": "mkey:…"}` (with `legacyPublicKey`
    ///    alongside it, which this engine ignores because it only speaks the
    ///    Noise transport), and
    ///  * the pre-JSON format, which was a bare hex key in the body.
    ///
    /// Go's `encoding/json` matches field names case-insensitively, so a server
    /// may spell the key `publicKey`, `PublicKey` or `publickey`; all three are
    /// accepted here.
    ///
    /// - Parameter data: The response body.
    /// - Throws: ``TailscaleControlError/invalidServerKey(_:)`` when no key can
    ///   be found or it is not 32 bytes.
    /// - Returns: The server key.
    public static func parseServerKeyResponse(_ data: Data) throws -> TailscaleServerKey {
        let trimmed = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)

        if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            let lowered = Dictionary(uniqueKeysWithValues: object.map { ($0.key.lowercased(), $0.value) })
            if let raw = lowered["publickey"] as? String {
                return TailscaleServerKey(publicKey: try parseMachinePublic(raw),
                                          expiry: parseExpiry(lowered["expiry"]))
            }
            if let raw = lowered["legacypublickey"] as? String, !raw.isEmpty {
                return TailscaleServerKey(publicKey: try parseMachinePublic(raw),
                                          expiry: parseExpiry(lowered["expiry"]))
            }
            throw TailscaleControlError.invalidServerKey("the /key response has no publicKey field")
        }

        // The pre-JSON format: the body *is* the key.
        guard !trimmed.isEmpty else {
            throw TailscaleControlError.invalidServerKey("the /key response was empty")
        }
        return TailscaleServerKey(publicKey: try parseMachinePublic(trimmed))
    }

    /// Parses a `key.MachinePublic` as it appears in JSON.
    ///
    /// The typed form is `mkey:` followed by 64 hex digits. The untyped form,
    /// which older servers used, is the 64 hex digits on their own; the Go
    /// client accepts it through `key.ParseMachinePublicUntyped`.
    ///
    /// - Parameter text: The encoded key.
    /// - Throws: ``TailscaleControlError/invalidServerKey(_:)`` when the text
    ///   is not a 32 byte key.
    /// - Returns: 32 bytes.
    public static func parseMachinePublic(_ text: String) throws -> Data {
        var hex = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if hex.lowercased().hasPrefix("mkey:") {
            hex = String(hex.dropFirst("mkey:".count))
        }
        guard hex.count == 64 else {
            throw TailscaleControlError.invalidServerKey("a machine public key is 64 hex digits, got \(hex.count)")
        }
        var bytes = [UInt8]()
        bytes.reserveCapacity(32)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index ..< next], radix: 16) else {
                throw TailscaleControlError.invalidServerKey("a machine public key is hex")
            }
            bytes.append(byte)
            index = next
        }
        return Data(bytes)
    }

    /// Reads the optional `expiry` field, which only older servers sent.
    ///
    /// - Parameter value: The decoded JSON value, if any.
    /// - Returns: The date, or `nil`.
    private static func parseExpiry(_ value: Any?) -> Date? {
        guard let text = value as? String, !text.isEmpty else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: text) { return date }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: text)
    }

    // MARK: - The upgrade request

    /// Builds the `X-Tailscale-Handshake` header value and the Noise handshake
    /// behind it.
    ///
    /// The returned handshake has already written message 1, so the caller only
    /// has to read message 2 from the socket afterwards.
    ///
    /// - Parameters:
    ///   - nodeKey: The client's node public key, 32 bytes. Used only when
    ///     `earlyPayload` is `true`.
    ///   - capabilityVersion: The client's capability version. It is mixed into
    ///     the prologue *and* written into the initiation frame's version
    ///     field, and the two must agree or the server's transcript diverges.
    ///   - localStaticPrivate: The client's Noise (machine) static private key,
    ///     32 bytes.
    ///   - serverKey: The server's static public key from
    ///     ``fetchServerKey(loginServer:capabilityVersion:session:)``.
    ///   - earlyPayload: Whether to place a ``TS2021EarlyPayload`` in message
    ///     1's Noise payload. Defaults to `false`, which is what interoperates.
    /// - Throws: ``TailscaleControlError`` when a key or version is unusable.
    /// - Returns: The handshake context.
    public static func beginClientHandshake(nodeKey: Data,
                                            capabilityVersion: Int,
                                            localStaticPrivate: Data,
                                            serverKey: Data,
                                            earlyPayload: Bool = false) throws -> TS2021ClientHandshake {
        guard capabilityVersion > 0, capabilityVersion <= Int(UInt16.max) else {
            throw TailscaleControlError.handshakeFailed("capability version \(capabilityVersion) does not fit the protocol's two byte field")
        }
        guard serverKey.count == NoiseIKHandshake.publicKeySize else {
            throw TailscaleControlError.invalidServerKey("the server key is \(serverKey.count) bytes, not 32")
        }

        let parameters = NoiseIKParameters(protocolName: NoiseIKHandshake.protocolName,
                                           prologue: prologue(protocolVersion: capabilityVersion),
                                           localStatic: localStaticPrivate,
                                           remoteStatic: serverKey,
                                           isInitiator: true)
        let handshake: NoiseIKHandshake
        do {
            handshake = try NoiseIKHandshake(parameters: parameters)
        } catch {
            throw TailscaleControlError.handshakeFailed(String(describing: error))
        }

        var payload = Data()
        if earlyPayload {
            let hex = nodeKey.map { String(format: "%02x", $0) }.joined()
            let encoded = try TS2021EarlyPayload(nodeKey: hex, version: capabilityVersion).encoded()
            payload = encoded
        }

        let message1: Data
        do {
            let noiseMessage = try handshake.writeMessage1(payload: payload)
            message1 = try TS2021HandshakeMessage.initiation(protocolVersion: UInt16(capabilityVersion),
                                                             payload: noiseMessage)
        } catch {
            throw TailscaleControlError.handshakeFailed(String(describing: error))
        }

        return TS2021ClientHandshake(handshake: handshake,
                                     message1: message1,
                                     headerValue: message1.base64EncodedString())
    }

    /// The value for the `X-Tailscale-Handshake` header: base64 of message 1.
    ///
    /// - Parameters:
    ///   - nodeKey: The client's node public key.
    ///   - capabilityVersion: The client's capability version.
    ///   - localStaticPrivate: The client's static private key.
    ///   - serverKey: The server's static public key.
    ///   - earlyPayload: Whether to send a ``TS2021EarlyPayload``.
    /// - Throws: ``TailscaleControlError`` when a key or version is unusable.
    /// - Returns: The base64 header value.
    public static func clientHandshakeHeader(nodeKey: Data,
                                             capabilityVersion: Int,
                                             localStaticPrivate: Data,
                                             serverKey: Data,
                                             earlyPayload: Bool = false) throws -> String {
        try beginClientHandshake(nodeKey: nodeKey,
                                 capabilityVersion: capabilityVersion,
                                 localStaticPrivate: localStaticPrivate,
                                 serverKey: serverKey,
                                 earlyPayload: earlyPayload).headerValue
    }

    /// Builds the HTTP/1.1 upgrade request for a login server.
    ///
    /// The request is a `POST` to `/ts2021`; the Go client switched from `GET`
    /// to `POST` when it gained the ability to send a request body, and
    /// Headscale's handler does not look at the method at all.
    ///
    /// - Parameters:
    ///   - loginServer: The control server's base URL.
    ///   - host: The value for the `Host` header, normally `host[:port]`.
    ///   - handshakeHeaderValue: Base64 message 1.
    /// - Throws: ``TailscaleControlError/invalidLoginServer(_:)`` when the URL
    ///   is unusable.
    /// - Returns: The request, ready to write to a socket.
    public static func upgradeRequest(loginServer: URL,
                                      host: String,
                                      handshakeHeaderValue: String) throws -> Data {
        guard let components = URLComponents(url: loginServer, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              scheme == "http" || scheme == "https" || scheme == "ws" || scheme == "wss" else {
            throw TailscaleControlError.invalidLoginServer(loginServer.absoluteString)
        }

        let basePath = components.path.hasSuffix("/")
            ? String(components.path.dropLast())
            : components.path
        var request = ""
        request += "POST \(basePath)\(upgradePath) HTTP/1.1\r\n"
        request += "Host: \(host)\r\n"
        request += "Upgrade: \(upgradeHeaderValue)\r\n"
        request += "Connection: upgrade\r\n"
        request += "\(handshakeHeaderName): \(handshakeHeaderValue)\r\n"
        request += "Content-Length: 0\r\n"
        request += "\r\n"
        return Data(request.utf8)
    }
}

/// The framing of the two Noise handshake messages.
///
/// These are the only frames in the protocol whose payload is not encrypted as
/// a record, and the initiation is the only frame that carries a protocol
/// version. Both are fixed size, so a peer cannot make the reader allocate:
/// `controlbase` declares them as `[101]byte` and `[51]byte`.
public enum TS2021HandshakeMessage {

    /// Serialises the handshake initiation.
    ///
    /// - Parameters:
    ///   - protocolVersion: The client's capability version, two bytes big
    ///     endian.
    ///   - payload: The 96 byte Noise message.
    /// - Throws: ``TailscaleControlError/malformedFrame(_:)`` when the payload
    ///   is not 96 bytes.
    /// - Returns: The 101 byte frame.
    public static func initiation(protocolVersion: UInt16, payload: Data) throws -> Data {
        guard payload.count == TS2021.initiationPayloadSize else {
            throw TailscaleControlError.malformedFrame(
                "a handshake initiation payload is \(TS2021.initiationPayloadSize) bytes, got \(payload.count)")
        }
        var bytes = [UInt8]()
        bytes.reserveCapacity(TS2021.initiationSize)
        bytes.append(UInt8(truncatingIfNeeded: protocolVersion >> 8))
        bytes.append(UInt8(truncatingIfNeeded: protocolVersion))
        bytes.append(TailscaleControlFrameType.initiation.rawValue)
        bytes.append(UInt8(truncatingIfNeeded: payload.count >> 8))
        bytes.append(UInt8(truncatingIfNeeded: payload.count))
        bytes.append(contentsOf: payload)
        return Data(bytes)
    }

    /// Parses the handshake initiation.
    ///
    /// - Parameter data: The 101 byte frame.
    /// - Throws: ``TailscaleControlError/malformedFrame(_:)`` when the frame is
    ///   the wrong size or carries the wrong type or length.
    /// - Returns: The protocol version and the 96 byte Noise payload.
    public static func parseInitiation(_ data: Data) throws -> (protocolVersion: UInt16, payload: Data) {
        guard data.count == TS2021.initiationSize else {
            throw TailscaleControlError.malformedFrame(
                "a handshake initiation is \(TS2021.initiationSize) bytes, got \(data.count)")
        }
        let bytes = [UInt8](data)
        guard bytes[2] == TailscaleControlFrameType.initiation.rawValue else {
            throw TailscaleControlError.unexpectedFrameType(bytes[2])
        }
        let length = Int(bytes[3]) << 8 | Int(bytes[4])
        guard length == TS2021.initiationPayloadSize else {
            throw TailscaleControlError.malformedFrame(
                "a handshake initiation payload is \(TS2021.initiationPayloadSize) bytes, got \(length)")
        }
        let version = UInt16(bytes[0]) << 8 | UInt16(bytes[1])
        return (version, Data(bytes[5...]))
    }

    /// Serialises the handshake response.
    ///
    /// - Parameter payload: The 48 byte Noise message.
    /// - Throws: ``TailscaleControlError/malformedFrame(_:)`` when the payload
    ///   is not 48 bytes.
    /// - Returns: The 51 byte frame.
    public static func response(payload: Data) throws -> Data {
        guard payload.count == TS2021.responsePayloadSize else {
            throw TailscaleControlError.malformedFrame(
                "a handshake response payload is \(TS2021.responsePayloadSize) bytes, got \(payload.count)")
        }
        var bytes = [UInt8]()
        bytes.reserveCapacity(TS2021.responseSize)
        bytes.append(TailscaleControlFrameType.response.rawValue)
        bytes.append(UInt8(truncatingIfNeeded: payload.count >> 8))
        bytes.append(UInt8(truncatingIfNeeded: payload.count))
        bytes.append(contentsOf: payload)
        return Data(bytes)
    }

    /// Parses the handshake response.
    ///
    /// - Parameter data: The 51 byte frame.
    /// - Throws: ``TailscaleControlError`` when the frame is the wrong size or
    ///   type, or when it is an unauthenticated error frame, whose cleartext
    ///   text is then reported.
    /// - Returns: The 48 byte Noise payload.
    public static func parseResponse(_ data: Data) throws -> Data {
        guard data.count >= TailscaleControlFrameCodec.headerSize else {
            throw TailscaleControlError.malformedFrame("a handshake response is at least 3 bytes")
        }
        let bytes = [UInt8](data)
        switch TailscaleControlFrameType(rawValue: bytes[0]) {
        case .response:
            guard data.count == TS2021.responseSize else {
                throw TailscaleControlError.malformedFrame(
                    "a handshake response is \(TS2021.responseSize) bytes, got \(data.count)")
            }
            let length = Int(bytes[1]) << 8 | Int(bytes[2])
            guard length == TS2021.responsePayloadSize else {
                throw TailscaleControlError.malformedFrame(
                    "a handshake response payload is \(TS2021.responsePayloadSize) bytes, got \(length)")
            }
            return Data(bytes[3...])
        case .error:
            let length = Int(bytes[1]) << 8 | Int(bytes[2])
            let text = String(decoding: bytes.dropFirst(3).prefix(length), as: UTF8.self)
            throw TailscaleControlError.handshakeFailed("the server refused the handshake: \(text)")
        case .initiation, .record, .ping, .pong:
            throw TailscaleControlError.unexpectedFrameType(bytes[0])
        case nil:
            throw TailscaleControlError.unexpectedFrameType(bytes[0])
        }
    }
}
