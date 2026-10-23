import Foundation

/// Where the tunnel currently is in its life cycle.
///
/// The sequence for a TLS connection is
/// `idle -> resolving -> connecting -> tlsHandshake -> authenticating -> connected`
/// with `reconnecting(reason:)` whenever the control channel has to be rebuilt
/// (SIGUSR1-style soft reset, `--ping-restart` expiry, renegotiation failure)
/// and `failed(_:)` when the configuration cannot work.
public enum OVPNState: Sendable, Equatable {
    /// Not started, or stopped.
    case idle
    /// Looking up the remote host (`resolving`).
    case resolving
    /// Transport created, first packet not yet sent.
    case connecting
    /// Control channel handshake in progress (TLS records flowing).
    case tlsHandshake
    /// TLS is up; waiting for `PUSH_REPLY` and the data channel keys.
    case authenticating
    /// Data channel up.
    case connected
    /// Restarting because of `reason`.
    case reconnecting(reason: String)
    /// Gave up. `reason` explains why.
    case failed(String)

    /// `true` for ``connected``.
    public var isConnected: Bool { self == .connected }
}

/// Counters and current state of a tunnel session.
public struct OVPNTunnelStatistics: Sendable, Equatable {
    /// Decrypted bytes received from the tunnel.
    public var bytesIn: UInt64
    /// Encrypted bytes sent to the server.
    public var bytesOut: UInt64
    /// When the data channel came up.
    public var connectedSince: Date?
    /// Current state.
    public var state: OVPNState
    /// Number of transport datagrams received.
    public var datagramsIn: UInt64 = 0
    /// Number of transport datagrams sent.
    public var datagramsOut: UInt64 = 0
    /// Number of packets dropped because the data channel had no keys yet.
    public var droppedOutbound: UInt64 = 0

    /// Create a statistics value.
    public init(
        bytesIn: UInt64 = 0,
        bytesOut: UInt64 = 0,
        connectedSince: Date? = nil,
        state: OVPNState = .idle
    ) {
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.connectedSince = connectedSince
        self.state = state
    }
}

/// Creates the datagram transport for a chosen remote.
///
/// The engine deliberately does not open sockets itself: on Apple platforms the
/// UDP socket belongs to the `NEPacketTunnelProvider`, and a test harness wants
/// an in-memory pipe. Provide a factory and the session will resolve/select the
/// remote and ask for a transport; omit it and the session uses the transport
/// that was injected at init.
public protocol OVPNTransportFactory: AnyObject, Sendable {
    /// Create a transport connected to `host:port`.
    func makeTransport(host: String, port: UInt16, proto: OVPNProto) async throws -> DatagramTransport
}

/// The host app's TLS stack, seen as an opaque byte pipe.
///
/// The engine never parses TLS; it feeds the peer's TLS records in with
/// ``writeTLS(_:)`` and sends whatever the stack produces from ``onTLSData``.
public protocol OVPNTLSProvider: AnyObject {
    /// Start a TLS client session.
    ///
    /// - Parameters:
    ///   - serverName: SNI / the name to verify against.
    ///   - caCertificates: DER or PEM CA certificates from the config.
    ///   - clientCertificate: PEM client certificate, if the config has one.
    ///   - clientKey: PEM private key, if the config has one.
    ///   - tlsAuthRemoteName: `tls-remote` / `verify-x509-name` value.
    func startTLS(
        serverName: String?,
        caCertificates: [Data],
        clientCertificate: Data?,
        clientKey: Data?,
        tlsAuthRemoteName: String?
    ) async throws

    /// Hand TLS records received from the peer to the TLS stack.
    func writeTLS(_ data: Data) async throws

    /// Set by the session: the TLS stack produced these records, send them to
    /// the peer.
    var onTLSData: (([Data]) -> Void)? { get set }

    /// The negotiated cipher suite, for logging.
    var negotiatedCipherSuite: String? { get }
}

/// Optional TLS provider capability: application data and handshake state.
///
/// OpenVPN's `PUSH_REQUEST`/`PUSH_REPLY` exchange happens *inside* TLS, so a
/// provider that implements this protocol lets ``OVPNTunnelSession`` drive it
/// without help. A provider that does not implement it must exchange the push
/// messages itself and call ``OVPNTunnelSession/handlePushReply(_:)``.
public protocol OVPNTLSApplicationData: OVPNTLSProvider {
    /// Send application data (a control channel string) through TLS.
    func writeApplicationData(_ data: Data) async throws
    /// Set by the session: application data received from inside TLS.
    var onApplicationData: (([Data]) -> Void)? { get set }
    /// `true` when the TLS handshake has completed.
    var isHandshakeComplete: Bool { get }
}

/// Optional TLS provider capability: OpenVPN's data channel key derivation.
///
/// OpenVPN derives the data channel keys from the TLS session (the
/// `OpenVPN key expansion` PRF over the master secret in `key-method 2`, or
/// the `EXPORT_KEYING_MATERIAL` exporter with `key-derivation tls-ekm`). An
/// opaque TLS stack does not expose either, so a provider that *can* export
/// them implements this and returns the **256 bytes** of `struct key2`
/// material; otherwise the host calls
/// ``OVPNTunnelSession/installDataChannelKeyMaterial(_:)`` itself.
public protocol OVPNTLSSessionKeyMaterial: OVPNTLSProvider {
    /// 256 bytes of OpenVPN key material for the negotiated `cipher`.
    func openVPNKeyMaterial(cipher: String) async throws -> Data
}

/// Drives a complete OpenVPN session over a `DatagramTransport`.
///
/// Everything that touches the network is asynchronous and cancellable; every
/// state change is reported through ``onStateChange``. The session is
/// transport agnostic (``OVPNTransportFactory``) and TLS agnostic
/// (``OVPNTLSProvider``), so it can be dropped on top of
/// `NEPacketTunnelProvider` or an in-memory test pipe.
public final class OVPNTunnelSession: @unchecked Sendable {

    // MARK: - Public configuration

    /// The parsed configuration.
    public let configuration: OVPNConfiguration

    /// Called with decrypted packets received from the tunnel.
    public var onInboundPackets: (@Sendable ([Data]) -> Void)?

    /// Called on every state change.
    public var onStateChange: (@Sendable (OVPNState) -> Void)?

    /// Called when a `PUSH_REPLY` was parsed.
    public var onPushReply: (@Sendable (OVPNPushReply) -> Void)?

    /// Called with every log line the session produces.
    public var onLog: (@Sendable (String) -> Void)?

    // MARK: - Private state

    private let tls: OVPNTLSProvider
    private let log: @Sendable (String) -> Void
    private let transportFactory: OVPNTransportFactory?

    private let lock = OVPNMutex()
    private var transport: DatagramTransport
    private var ownsTransport = false
    private var state: OVPNState = .idle
    private var stats = OVPNTunnelStatistics()

    /// The OpenVPN session id.
    ///
    /// It is generated once and reused by every key state: `tls_session_init()`
    /// randomises it when the session is created, and a renegotiation only
    /// allocates a new key id.
    private(set) var sessionID: OVPNSessionID = .random()

    /// Control channel for the current key state, if TLS is in use.
    private var reliability: OVPNReliabilityLayer?
    /// Control channel layers of older key states, kept so late ACKs and
    /// retransmissions of a previous key state are still answered.
    private var retiredReliability: [OVPNReliabilityLayer] = []
    /// Data channel codecs by key id.
    private var codecs: [UInt8: OVPNPacketCodec] = [:]
    /// Key id of the data channel currently in use.
    private var activeDataKeyID: UInt8 = 0
    /// Key material for key states that are being negotiated.
    private var pendingKeyMaterial: [UInt8: Data] = [:]

    private var receiveTask: Task<Void, Never>?
    private var timerTask: Task<Void, Never>?

    private var lastInboundAt: Date?
    private var lastOutboundAt: Date?
    private var connectedAt: Date?
    private var handshakeStartedAt: Date?
    private var pushRequestSentAt: Date?
    private var pushedReply: OVPNPushReply?
    private var lastPingAt: Date?
    private var renegotiatedKeyStates: Set<UInt8> = []

    // MARK: - Init

    /// Create a session.
    ///
    /// - Parameters:
    ///   - configuration: parsed `.ovpn` configuration.
    ///   - transport: fallback transport, used when no ``OVPNTransportFactory``
    ///     is supplied. It must already be pointed at the server.
    ///   - tls: the host's TLS stack (unused in `--secret` mode).
    ///   - transportFactory: optional factory that creates the transport for
    ///     the selected remote (this is what performs "resolve then connect").
    ///   - log: log sink.
    public init(
        configuration: OVPNConfiguration,
        transport: DatagramTransport,
        tls: OVPNTLSProvider,
        transportFactory: OVPNTransportFactory? = nil,
        log: @escaping @Sendable (String) -> Void = { _ in }
    ) {
        self.configuration = configuration
        self.transport = transport
        self.tls = tls
        self.transportFactory = transportFactory
        self.log = log
    }

    // MARK: - Life cycle

    /// Statistics snapshot. Safe to call at any time.
    public var statistics: OVPNTunnelStatistics {
        lock.lock()
        defer { lock.unlock() }
        var snapshot = stats
        snapshot.state = state
        return snapshot
    }

    /// Current state.
    public var currentState: OVPNState {
        lock.lock()
        defer { lock.unlock() }
        return state
    }

    /// The `PUSH_REPLY` the server sent, once it arrived.
    public var pushReply: OVPNPushReply? {
        lock.lock()
        defer { lock.unlock() }
        return pushedReply
    }

    /// Resolve/select a remote, bring up the control channel and, in
    /// `--secret` mode, the data channel.
    ///
    /// - Throws: ``OVPNError`` when the configuration is unusable, when the
    ///   transport factory fails, or when the TLS stack rejects the handshake.
    public func start() async throws {
        guard state == .idle || isReconnecting(state) else {
            throw OVPNError.invalidState("start() called while \(state)")
        }
        setState(.resolving)

        guard let remote = selectRemote() else {
            let error = OVPNError.missingRequiredDirective("remote")
            setState(.failed(error.localizedDescription))
            throw error
        }
        let proto = remote.proto ?? configuration.proto
        log("selected remote \(remote.host):\(remote.port) via \(proto.token)")

        if let transportFactory {
            transport = try await transportFactory.makeTransport(host: remote.host, port: remote.port, proto: proto)
            ownsTransport = true
        }

        setState(.connecting)
        lastInboundAt = Date()
        lastOutboundAt = Date()

        if configuration.isStaticKeyMode {
            try startStaticKeyMode()
        } else {
            try await startTLSMode()
        }

        startReceiveLoop()
        startTimerLoop()
    }

    /// Stop the session and release the transport if the session created it.
    public func stop() async {
        lock.lock()
        receiveTask?.cancel()
        timerTask?.cancel()
        receiveTask = nil
        timerTask = nil
        let shouldClose = ownsTransport
        ownsTransport = false
        lock.unlock()

        if let applicationData = tls as? OVPNTLSApplicationData {
            applicationData.onApplicationData = nil
        }
        tls.onTLSData = nil
        if shouldClose { await transport.close() }
        setState(.idle)
        log("session stopped")
    }

    /// Encrypt and send IP packets to the server.
    ///
    /// Packets are silently dropped (and counted in
    /// ``OVPNTunnelStatistics/droppedOutbound``) while the data channel has no
    /// keys, which happens between `start()` and the key exchange.
    public func writeOutbound(_ packets: [Data]) {
        lock.lock()
        // The codec is a value, but its packet-id counter and replay window are
        // reference types shared by every copy, so encoding advances the shared
        // state and no write-back is needed.
        let codec = codecs[activeDataKeyID]
        lock.unlock()

        guard let codec else {
            lock.lock()
            stats.droppedOutbound += UInt64(packets.count)
            lock.unlock()
            return
        }
        for packet in packets {
            do {
                let datagram = try codec.encodeNext(packet: packet)
                lock.lock()
                stats.bytesOut += UInt64(packet.count)
                lock.unlock()
                sendFireAndForget(datagram)
            } catch {
                log("outbound packet dropped: \(error)")
            }
        }
    }

    /// Install the 256 bytes of OpenVPN key material for the active key state.
    ///
    /// Call this from ``OVPNTLSSessionKeyMaterial`` or by hand after the key
    /// exchange; it builds the data channel codec and moves the session to
    /// ``OVPNState/connected``.
    public func installDataChannelKeyMaterial(_ material: Data, keyID: UInt8? = nil) throws {
        let id = keyID ?? activeDataKeyID
        let cipherName = pushedReply?.cipher ?? configuration.cipher
        let (cipher, hmac) = try OVPNKeyDerivation.negotiatedCipher(
            configuration: configuration,
            pushedCipher: cipherName
        )
        let keys = try OVPNKeyDerivation.dataKeys(
            fromKeyMaterial: material,
            isServer: false,
            cipher: cipher,
            hmac: hmac
        )
        var codec = try OVPNPacketCodec(
            cipher: cipher.name,
            digest: hmac?.openVPNName,
            staticKeyMode: false,
            senderKeyId: id
        )
        codec.installKeys(keys)
        if let peerID = pushedReply?.peerID, cipher.isAEAD {
            codec.useDataV2 = true
            codec.peerID = peerID
        }

        lock.lock()
        codecs[id] = codec
        activeDataKeyID = id
        connectedAt = Date()
        stats.connectedSince = Date()
        pendingKeyMaterial[id] = material
        lock.unlock()
        log("data channel ready: \(cipher.name) key id \(id)")
        setState(.connected)
    }

    /// Handle a `PUSH_REPLY` (or `PUSH_UPDATE`) message.
    ///
    /// A host whose TLS stack implements ``OVPNTLSApplicationData`` never needs
    /// to call this; everybody else calls it with the message text, either with
    /// or without the `PUSH_REPLY,` prefix and trailing NUL.
    public func handlePushReply(_ text: String) async {
        let reply = OVPNPushReply.parse(text, filters: configuration.typedPullFilters)
        lock.lock()
        pushedReply = reply
        lock.unlock()

        if !reply.ignoredOptions.isEmpty {
            log("pull filters ignored \(reply.ignoredOptions.count) option(s)")
        }
        if !reply.rejectedOptions.isEmpty {
            log("pull filters rejected: \(reply.rejectedOptions.joined(separator: ", "))")
        }
        if let ifconfig = reply.ifconfig {
            log("ifconfig \(ifconfig.localAddress) \(ifconfig.secondArgument)")
        }
        if let cipher = reply.cipher { log("server chose cipher \(cipher)") }
        if let peerID = reply.peerID { log("peer-id \(peerID)") }

        // A server that pushes `auth-token` expects the client to reuse it.
        onPushReply?(reply)

        if let keySource = tls as? OVPNTLSSessionKeyMaterial {
            do {
                let material = try await keySource.openVPNKeyMaterial(
                    cipher: reply.cipher ?? configuration.cipher ?? "AES-256-GCM"
                )
                try installDataChannelKeyMaterial(material)
            } catch {
                log("could not obtain data channel keys from the TLS stack: \(error)")
                setState(.connected)
            }
        } else {
            log("TLS stack does not export OpenVPN key material; call installDataChannelKeyMaterial(_:) to bring the data channel up")
            setState(.connected)
        }
    }

    // MARK: - Modes

    /// `--secret`: no TLS, no negotiation, the static key is the data channel
    /// key in both directions.
    private func startStaticKeyMode() throws {
        let keyFile = try configuration.loadStaticKeyFile()
        let (cipher, hmac) = try OVPNKeyDerivation.negotiatedCipher(configuration: configuration)
        let keys = try OVPNKeyDerivation.dataKeys(fromStaticKeyFile: keyFile, cipher: cipher, hmac: hmac)
        var codec = try OVPNPacketCodec(
            cipher: cipher.name,
            digest: hmac?.openVPNName,
            staticKeyMode: true,
            senderKeyId: 0
        )
        codec.installKeys(keys)
        codec.packetMode = configuration.devType == .tap ? .tap : .tun

        lock.lock()
        codecs[0] = codec
        activeDataKeyID = 0
        connectedAt = Date()
        stats.connectedSince = connectedAt
        lock.unlock()
        log("static key mode: \(cipher.name) with \(configuration.devType.rawValue)")
        setState(.connected)
    }

    /// TLS mode: hard reset, TLS records through the reliability layer, then
    /// the push exchange.
    private func startTLSMode() async throws {
        let crypto = try controlCrypto()
        let wrappedKey = try configuration.loadTLSCryptV2ClientKey()?.wrappedClientKey
        let layer = OVPNReliabilityLayer(
            keyID: 0,
            isServer: false,
            crypto: crypto,
            localSessionID: sessionID,
            initialOpcode: OVPNControlOpcode.initialOpcode(isServer: false, hasTLSCryptV2: wrappedKey != nil),
            tlsCryptV2WrappedKey: wrappedKey
        )
        lock.lock()
        reliability = layer
        handshakeStartedAt = Date()
        lock.unlock()

        if let degraded = layer.degradedReason { log("warning: \(degraded)") }

        // Pipe TLS records produced by the TLS stack into the control channel.
        tls.onTLSData = { [weak self] records in
            self?.sendTLSRecords(records)
        }
        if let applicationData = tls as? OVPNTLSApplicationData {
            applicationData.onApplicationData = { [weak self] messages in
                for message in messages {
                    let text = String(decoding: message, as: UTF8.self)
                    if text.hasPrefix("PUSH_REPLY") || text.hasPrefix("PUSH_UPDATE") {
                        Task { await self?.handlePushReply(text) }
                    } else if text.hasPrefix("AUTH_FAILED") {
                        self?.log("server rejected authentication: \(text)")
                        self?.setState(.failed(text))
                    }
                }
            }
        }

        // Send the hard reset before the TLS stack starts, exactly like
        // OpenVPN (the reset is the first packet on the wire).
        let reset = try layer.beginHandshake()
        sendFireAndForget(reset)

        let bundle = certificateBundle()
        try await tls.startTLS(
            serverName: configuration.remotes.first?.host,
            caCertificates: bundle.ca,
            clientCertificate: bundle.certificate,
            clientKey: bundle.key,
            tlsAuthRemoteName: configuration.tlsRemote ?? configuration.verifyX509Name
        )
        setState(.tlsHandshake)
        log("TLS handshake started (control channel \(describe(crypto.mode)))")
    }

    /// The control channel crypto the configuration asks for.
    private func controlCrypto() throws -> OVPNControlCrypto {
        let tlsAuthKey = try configuration.loadTLSAuthKeyFile()
        let tlsCryptKey = try configuration.loadTLSCryptKeyFile()
        let tlsCryptV2 = try configuration.loadTLSCryptV2ClientKey()
        if tlsCryptV2 != nil || tlsCryptKey != nil {
            return try OVPNControlCrypto(
                tlsAuthKey: nil,
                tlsCryptKey: tlsCryptKey,
                tlsCryptV2ClientKey: tlsCryptV2
            )
        }
        // tls-auth defaults to SHA-256 on OpenVPN 2.6; `auth` selects the
        // digest for older peers.
        let digest = OVPNHMACAlgorithm.parse(configuration.auth) ?? .sha256
        return try OVPNControlCrypto(tlsAuthKey: tlsAuthKey, tlsCryptKey: nil, digest: digest)
    }

    private func describe(_ mode: OVPNControlCrypto.Mode) -> String {
        switch mode {
        case .none: return "TLS_WRAP_NONE"
        case .tlsAuth: return "tls-auth"
        case .tlsCrypt: return "tls-crypt"
        }
    }

    /// Inline PEM material from the configuration, reading files when needed.
    private func certificateBundle() -> (ca: [Data], certificate: Data?, key: Data?) {
        func material(inline: String?, path: String?) -> Data? {
            if let inline { return Data(inline.utf8) }
            guard let path, let contents = try? String(contentsOfFile: path, encoding: .utf8) else { return nil }
            return Data(contents.utf8)
        }
        let ca = material(inline: configuration.ca, path: configuration.caPath)
        return (
            ca.map { [$0] } ?? [],
            material(inline: configuration.cert, path: configuration.certPath),
            material(inline: configuration.key, path: configuration.keyPath)
        )
    }

    // MARK: - Remote selection

    /// Pick a remote: randomly among the `remote-random` pool, else the first.
    private func selectRemote() -> OVPNRemote? {
        guard !configuration.remotes.isEmpty else { return nil }
        guard configuration.remoteRandom else { return configuration.remotes.first }
        var generator = SystemRandomNumberGenerator()
        return configuration.remotes.randomElement(using: &generator)
    }

    // MARK: - Loops

    private func startReceiveLoop() {
        lock.lock()
        let transport = self.transport
        receiveTask?.cancel()
        lock.unlock()

        receiveTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                do {
                    let datagram = try await transport.receive()
                    await self.handle(datagram: datagram)
                } catch {
                    if Task.isCancelled { return }
                    self.log("transport receive failed: \(error)")
                    self.setState(.reconnecting(reason: "transport error"))
                    return
                }
            }
        }
    }

    private func startTimerLoop() {
        lock.lock()
        timerTask?.cancel()
        lock.unlock()

        timerTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 250_000_000)
                guard let self else { return }
                if Task.isCancelled { return }
                await self.tick()
            }
        }
    }

    /// Periodic work: retransmissions, acks, keepalives, renegotiation.
    private func tick() async {
        let now = Date()

        lock.lock()
        let layer = reliability
        let currentState = state
        let reply = pushedReply
        let lastPushRequest = pushRequestSentAt
        lock.unlock()

        // Control channel maintenance.
        if let layer {
            let datagrams = (try? layer.tick(now: now)) ?? []
            for datagram in datagrams { sendFireAndForget(datagram) }
            for datagram in layer.pendingAcks(now: now) { sendFireAndForget(datagram) }
            handleControlEvents(layer.drainEvents(), layer: layer)
        }

        // Push exchange.
        if currentState == .tlsHandshake, let applicationData = tls as? OVPNTLSApplicationData,
           applicationData.isHandshakeComplete {
            setState(.authenticating)
            await sendPushRequest()
        }
        if currentState == .authenticating, reply == nil,
           let last = lastPushRequest, now.timeIntervalSince(last) > 5 {
            await sendPushRequest()
        }

        // Keepalives and timeouts.
        lock.lock()
        let stateNow = state
        let lastInbound = lastInboundAt
        let lastOutbound = lastOutboundAt
        let connectedSince = connectedAt
        lock.unlock()

        guard stateNow == .connected else { return }

        if let pingInterval = configuration.pingInterval,
           let lastOutbound, now.timeIntervalSince(lastOutbound) >= TimeInterval(pingInterval) {
            sendKeepalive()
        }
        if let pingRestart = configuration.pingRestart, pingRestart > 0,
           let lastInbound, now.timeIntervalSince(lastInbound) > TimeInterval(pingRestart) {
            log("no packet received for \(pingRestart)s, reconnecting")
            setState(.reconnecting(reason: "ping-restart"))
            restartControlChannel()
            return
        }
        if let limit = configuration.renegSec, limit > 0,
           let connectedSince, now.timeIntervalSince(connectedSince) > TimeInterval(limit) {
            log("renegotiating after \(limit)s")
            beginRenegotiation(reason: "reneg-sec")
        }
    }

    /// Send `PUSH_REQUEST` through the TLS session.
    private func sendPushRequest() async {
        guard let applicationData = tls as? OVPNTLSApplicationData else { return }
        do {
            try await applicationData.writeApplicationData(OVPNPushReply.pushRequestPayload)
            lock.lock()
            pushRequestSentAt = Date()
            lock.unlock()
            log("PUSH_REQUEST sent")
        } catch {
            log("could not send PUSH_REQUEST: \(error)")
        }
    }

    // MARK: - Transport plumbing

    private func sendFireAndForget(_ datagram: Data) {
        lock.lock()
        let transport = self.transport
        stats.datagramsOut += 1
        lastOutboundAt = Date()
        lock.unlock()
        Task { [weak self] in
            do {
                try await transport.send(datagram)
            } catch {
                self?.log("transport send failed: \(error)")
            }
        }
    }

    /// An empty `P_DATA_V1` packet: OpenVPN's keepalive.
    private func sendKeepalive() {
        lock.lock()
        let codec = codecs[activeDataKeyID]
        lock.unlock()
        guard let codec else { return }
        // The payload is empty, so the packet is `[opcode][HMAC][IV][padding]`.
        if let datagram = try? codec.encodeNext(packet: Data()) {
            sendFireAndForget(datagram)
        }
    }

    // MARK: - Receiving

    private func handle(datagram: Data) async {
        let now = Date()
        lock.lock()
        stats.datagramsIn += 1
        stats.bytesIn += UInt64(datagram.count)
        lastInboundAt = now
        let layer = reliability
        let retired = retiredReliability
        let codec = codecs[activeDataKeyID]
        lock.unlock()

        guard let first = datagram.first else { return }
        let opcodeValue = first >> OVPNControlOpcode.shift
        guard let opcode = OVPNControlOpcode(rawValue: opcodeValue) else {
            log("ignoring datagram with unknown opcode \(opcodeValue)")
            return
        }

        if opcode.isControl {
            // Answer packets for older key states too, so a late
            // retransmission is not left hanging.
            if first & OVPNControlOpcode.keyIDMask != layer?.keyID {
                for candidate in [layer].compactMap({ $0 }) + retired
                where candidate.keyID == first & OVPNControlOpcode.keyIDMask {
                    await pumpControl(datagram, through: candidate)
                    return
                }
                log("ignoring control packet for unmanaged key id \(first & OVPNControlOpcode.keyIDMask)")
                return
            }
            if let layer { await pumpControl(datagram, through: layer) }
            return
        }

        guard let codec else { return }
        do {
            let inbound = try codec.decodeAnnotated(datagram)
            guard inbound.payload.isEmpty == false else { return }
            onInboundPackets?([inbound.payload])
        } catch let error as OVPNError {
            switch error {
            case .replayDetected, .authenticationFailed, .decryptionFailed:
                // Expected on a lossy link: drop silently.
                break
            default:
                log("inbound packet dropped: \(error)")
            }
        } catch {
            log("inbound packet dropped: \(error)")
        }
    }

    private func pumpControl(_ datagram: Data, through layer: OVPNReliabilityLayer) async {
        do {
            let payloads = try layer.receive(datagram).filter { !$0.isEmpty }
            if !payloads.isEmpty {
                let combined = payloads.reduce(into: Data()) { $0.append($1) }
                try await tls.writeTLS(combined)
            }
        } catch {
            log("control packet dropped: \(error)")
        }
        handleControlEvents(layer.drainEvents(), layer: layer)
    }

    private func handleControlEvents(_ events: [OVPNControlEvent], layer: OVPNReliabilityLayer) {
        for event in events {
            switch event {
            case let .hardResetReceived(keyID):
                log("hard reset received for key id \(keyID)")
                if let sessionID = layer.remoteSessionID {
                    log("server session id \(sessionID)")
                }
            case let .softResetReceived(keyID):
                log("soft reset received for key id \(keyID)")
                beginRenegotiation(reason: "server soft reset", requestedKeyID: keyID)
            case let .ackReceived(ids):
                log("acknowledged \(ids)")
            case let .peerSessionEstablished(sessionID):
                log("peer session established \(sessionID)")
            case let .packetForOtherKeyState(keyID, opcode):
                log("packet \(opcode.name) for key id \(keyID) has no key state yet")
                beginRenegotiation(reason: "peer started key id \(keyID)", requestedKeyID: keyID)
            case .wkcReceived:
                log("wrapped key confirmation received")
            case let .dropped(reason):
                log("control packet dropped: \(reason)")
            }
        }
    }

    private func sendTLSRecords(_ records: [Data]) {
        lock.lock()
        let layer = reliability
        lock.unlock()
        guard let layer else { return }
        for record in records {
            for datagram in layer.wrapOutgoingTLS(record) {
                sendFireAndForget(datagram)
            }
        }
    }

    /// Drop the current control channel and start a fresh key state.
    private func beginRenegotiation(reason: String, requestedKeyID: UInt8? = nil) {
        lock.lock()
        let current = reliability
        let nextKeyID: UInt8 = requestedKeyID ?? ((current?.keyID ?? 0) &+ 1)
        if let current, !retiredReliability.contains(where: { $0 === current }) {
            retiredReliability.append(current)
            if retiredReliability.count > 3 { retiredReliability.removeFirst() }
        }
        let alreadyRenegotiating = renegotiatedKeyStates.contains(nextKeyID)
        renegotiatedKeyStates.insert(nextKeyID)
        lock.unlock()

        log("renegotiating (\(reason)) with key id \(nextKeyID)")
        setState(.reconnecting(reason: reason))

        if alreadyRenegotiating { return }
        Task { [weak self] in
            await self?.startKeyState(keyID: nextKeyID, opcode: .softResetV1)
        }
    }

    /// Rebuild the control channel from scratch after a timeout.
    private func restartControlChannel() {
        lock.lock()
        reliability = nil
        codecs.removeAll()
        pushedReply = nil
        // A fresh control channel is a fresh session, so the session id is
        // regenerated (OpenVPN does the same when it re-creates the session).
        sessionID = .random()
        let hadTLS = !configuration.isStaticKeyMode
        lock.unlock()

        if !hadTLS {
            // Static key mode: nothing to rebuild.
            do { try startStaticKeyMode() } catch { setState(.failed("\(error)")) }
            return
        }
        Task { [weak self] in
            await self?.startKeyState(keyID: 0, opcode: nil)
        }
    }

    /// Create a fresh reliability layer and (re)start the TLS handshake for it.
    private func startKeyState(keyID: UInt8, opcode: OVPNControlOpcode?) async {
        do {
            let crypto = try controlCrypto()
            let wrappedKey = try configuration.loadTLSCryptV2ClientKey()?.wrappedClientKey
            let layer = OVPNReliabilityLayer(
                keyID: keyID,
                isServer: false,
                crypto: crypto,
                localSessionID: sessionID,
                initialOpcode: opcode
                    ?? OVPNControlOpcode.initialOpcode(isServer: false, hasTLSCryptV2: wrappedKey != nil),
                tlsCryptV2WrappedKey: wrappedKey
            )
            lock.lock()
            reliability = layer
            handshakeStartedAt = Date()
            pushRequestSentAt = nil
            lock.unlock()

            let datagram = opcode == .softResetV1
                ? try layer.sendSoftReset()
                : try layer.beginHandshake()
            sendFireAndForget(datagram)

            let bundle = certificateBundle()
            try await tls.startTLS(
                serverName: configuration.remotes.first?.host,
                caCertificates: bundle.ca,
                clientCertificate: bundle.certificate,
                clientKey: bundle.key,
                tlsAuthRemoteName: configuration.tlsRemote ?? configuration.verifyX509Name
            )
            setState(.tlsHandshake)
        } catch {
            log("could not start key state \(keyID): \(error)")
            setState(.failed("\(error)"))
        }
    }

    // MARK: - State

    private func isReconnecting(_ state: OVPNState) -> Bool {
        if case .reconnecting = state { return true }
        return false
    }

    private func setState(_ newState: OVPNState) {
        lock.lock()
        guard state != newState else {
            lock.unlock()
            return
        }
        state = newState
        stats.state = newState
        lock.unlock()
        onStateChange?(newState)
    }
}
