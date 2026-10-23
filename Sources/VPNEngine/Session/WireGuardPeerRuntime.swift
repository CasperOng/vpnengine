//
//  WireGuardPeerRuntime.swift
//  VPNEngine
//
//  Per-peer session state: the handshake attempt in flight, the current sending
//  key and counter, the receiving sessions still able to decrypt, and the
//  timers that decide when to rekey or tear down.
//
//  Everything here is serialised by one lock per peer, including the data path,
//  because the transport data counter must never be handed out twice for the
//  same key: reusing a counter would reuse a ChaCha20 nonce, which is a total
//  loss of confidentiality for the session. Allocation and use of the counter
//  therefore happen inside a single critical section.
//

import Foundation

/// Timers and message limits from the whitepaper, section 6.
///
/// The defaults are the ones this engine is specified to use: rekey and reject
/// after 180 seconds, and a handshake retry every five seconds.
public struct WireGuardSessionTimers: Sendable, Equatable {

    /// How often the session's timer loop runs.
    public var tickInterval: TimeInterval

    /// Start a new handshake once the current session is this old.
    ///
    /// The whitepaper calls this `Rekey-After-Time` and uses 120 seconds; this
    /// engine is specified to use 180.
    public var rekeyAfterTime: TimeInterval

    /// Stop using a session once it is this old.
    ///
    /// The whitepaper's `Reject-After-Time` is also 180 seconds, which is why
    /// rekeying starts exactly when the old key stops being usable.
    public var rejectAfterTime: TimeInterval

    /// Retransmit a handshake this often while it is outstanding.
    ///
    /// The whitepaper calls this `Rekey-Timeout` and uses 5 seconds; no
    /// initiation is ever sent more often than this.
    public var handshakeRetryInterval: TimeInterval

    /// Give up, and report failure, when a handshake has been outstanding this
    /// long.
    public var handshakeAttemptTimeout: TimeInterval

    /// The whitepaper's `Keepalive-Timeout`: after receiving data with nothing
    /// to send back, send an empty packet after this long.
    public var keepaliveTimeout: TimeInterval

    /// Rekey after sending this many transport messages (`Rekey-After-Messages`).
    public var rekeyAfterMessages: UInt64

    /// Refuse to send after this many transport messages (`Reject-After-Messages`).
    public var rejectAfterMessages: UInt64

    /// Timers with the engine's defaults.
    public init(tickInterval: TimeInterval = 0.25,
                rekeyAfterTime: TimeInterval = 180,
                rejectAfterTime: TimeInterval = 180,
                handshakeRetryInterval: TimeInterval = 5,
                handshakeAttemptTimeout: TimeInterval = 180,
                keepaliveTimeout: TimeInterval = 10,
                rekeyAfterMessages: UInt64 = 1 << 60,
                rejectAfterMessages: UInt64 = UInt64.max - (1 << 13)) {
        self.tickInterval = tickInterval
        self.rekeyAfterTime = rekeyAfterTime
        self.rejectAfterTime = rejectAfterTime
        self.handshakeRetryInterval = handshakeRetryInterval
        self.handshakeAttemptTimeout = handshakeAttemptTimeout
        self.keepaliveTimeout = keepaliveTimeout
        self.rekeyAfterMessages = rekeyAfterMessages
        self.rejectAfterMessages = rejectAfterMessages
    }
}

/// One peer's session state machine.
final class WireGuardPeerRuntime: @unchecked Sendable {

    /// A receiving session: the key to decrypt with and the counters seen.
    struct ReceivingSession {
        var key: [UInt8]
        var window: ReplayWindow
        let createdAt: Date
    }

    /// What a handshake message produced.
    enum HandshakeOutcome: Equatable {

        /// The message was not for this peer, or it failed to authenticate.
        case none

        /// Send this message back.
        case send(Data)

        /// The handshake completed and the session keys are installed.
        case established

        /// A cookie reply was consumed; nothing to send.
        case cookieStored
    }

    /// What the session's timer loop should do for this peer.
    struct TimerDecision: Equatable {
        var initiateHandshake = false
        var sendKeepalive = false
        var teardown = false
        var failureReason: String?
    }

    /// The peer this runtime serves.
    let peer: WireGuardPeer

    private let localStaticPrivate: Data
    private let localStaticPublic: Data
    private let mtu: Int
    private let timers: WireGuardSessionTimers
    private let log: @Sendable (String) -> Void
    private let lock = NSLock()

    private var handshake: WireGuardHandshake?
    private var handshakeStartedAt: Date?
    private var lastHandshakeMessageAt: Date?

    private var sendingKey: [UInt8]?
    private var sendingCounter: UInt64 = 0
    private var sendingRemoteIndex: UInt32 = 0
    private var sendingSessionCreatedAt: Date?
    private var sendingSessionIsInitiator = false
    private var activeReceivingIndex: UInt32?
    private var receivingSessions: [UInt32: ReceivingSession] = [:]

    private var lastHandshakeCompletedAt: Date?
    private var lastInboundActivityAt: Date?
    private var lastOutboundAt: Date?
    private var passiveKeepaliveDeadline: Date?
    private var needsKeepaliveAfterHandshake = false
    private var bytesSent: UInt64 = 0
    private var bytesReceived: UInt64 = 0

    /// Creates a runtime for one peer.
    ///
    /// The session validates the keys before creating runtimes, so an empty
    /// public key here means the peer cannot handshake and every operation will
    /// fail rather than misbehave.
    ///
    /// - Parameters:
    ///   - peer: The peer configuration.
    ///   - localStaticPrivate: The interface's 32 byte private key.
    ///   - mtu: The tunnel MTU, used to bound padding.
    ///   - timers: The timer configuration.
    ///   - log: A sink for diagnostics.
    init(peer: WireGuardPeer,
         localStaticPrivate: Data,
         mtu: Int,
         timers: WireGuardSessionTimers,
         log: @escaping @Sendable (String) -> Void) {
        self.peer = peer
        self.localStaticPrivate = localStaticPrivate
        self.localStaticPublic = Data((try? X25519.publicKey(for: [UInt8](localStaticPrivate))) ?? [])
        self.mtu = mtu
        self.timers = timers
        self.log = log
    }

    // MARK: - Queries

    /// The peer's public key, used as the routing key for sessions.
    var publicKey: Data { peer.publicKey }

    /// Whether this peer has an endpoint, and so can be initiated to.
    var canInitiate: Bool {
        guard let endpoint = peer.endpoint else { return false }
        return !endpoint.isEmpty
    }

    /// Whether a handshake attempt is outstanding.
    var isHandshakeInFlight: Bool {
        lock.lock()
        defer { lock.unlock() }
        return handshake != nil
    }

    /// The number of transport data messages the sending counter has reached.
    var sendingMessageCount: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return sendingCounter
    }

    /// Whether the current session can still be used to send.
    ///
    /// - Parameter now: The current time.
    /// - Returns: `true` when a key exists, is younger than `rejectAfterTime`
    ///   and has not exhausted its message budget.
    func hasUsableSendingSession(now: Date) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return hasUsableSendingSessionLocked(now: now)
    }

    /// Whether any receiving session exists.
    var hasReceivingSession: Bool {
        lock.lock()
        defer { lock.unlock() }
        return !receivingSessions.isEmpty
    }

    /// When the current session's keys were established.
    var establishedAt: Date? {
        lock.lock()
        defer { lock.unlock() }
        return lastHandshakeCompletedAt
    }

    /// The most recent sign of life from this peer: when the session was
    /// established, or when the last transport message was decrypted from it.
    ///
    /// This is what a "latest handshake" readout should show: a tunnel whose
    /// keys are minutes old but which is carrying traffic right now is not
    /// stale.
    var lastHandshake: Date? {
        lock.lock()
        defer { lock.unlock() }
        switch (lastHandshakeCompletedAt, lastInboundActivityAt) {
        case let (completed?, inbound?): return Swift.max(completed, inbound)
        case let (completed?, nil): return completed
        case let (nil, inbound?): return inbound
        default: return nil
        }
    }

    /// Whether the current session was established by this side initiating it.
    var isInitiatorSession: Bool {
        lock.lock()
        defer { lock.unlock() }
        return sendingSessionIsInitiator
    }

    /// The session's traffic counters, in wire bytes.
    var statistics: (sent: UInt64, received: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        return (bytesSent, bytesReceived)
    }

    /// The number of receiving sessions currently held.
    var receivingSessionCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return receivingSessions.count
    }

    /// Whether this peer's handshake attempt owns a handshake message.
    ///
    /// - Parameter message: A datagram that might be a handshake response or a
    ///   cookie reply.
    /// - Returns: `true` when the message names the index of the attempt in
    ///   flight.
    func ownsHandshakeMessage(_ message: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return handshake?.matches(message) ?? false
    }

    // MARK: - Timer driven decisions

    /// Decides what the session should do for this peer at this moment.
    ///
    /// - Parameter now: The current time.
    /// - Returns: The actions to take.
    func timerDecision(now: Date) -> TimerDecision {
        lock.lock()
        defer { lock.unlock() }

        var decision = TimerDecision()

        if hasUsableSendingSessionLocked(now: now) {
            // Rekey when the key ages out or runs out of messages. Only the
            // initiator of the current session rekeys, which prevents both ends
            // from starting a handshake at the same time (whitepaper, 6.2).
            let age = sendingSessionCreatedAt.map { now.timeIntervalSince($0) } ?? 0
            if sendingSessionIsInitiator,
               handshake == nil,
               (age >= timers.rekeyAfterTime || sendingCounter >= timers.rekeyAfterMessages) {
                decision.initiateHandshake = true
            }

            if let interval = peer.persistentKeepalive, interval > 0 {
                let reference = lastOutboundAt ?? lastHandshakeCompletedAt ?? now
                if now.timeIntervalSince(reference) >= TimeInterval(interval) {
                    decision.sendKeepalive = true
                }
            } else if let deadline = passiveKeepaliveDeadline, now >= deadline {
                decision.sendKeepalive = true
            }

            if needsKeepaliveAfterHandshake {
                decision.sendKeepalive = true
            }
            return decision
        }

        // No usable session: keep a handshake attempt alive, or start one.
        if let started = handshakeStartedAt {
            if now.timeIntervalSince(started) >= timers.handshakeAttemptTimeout {
                decision.teardown = true
                decision.failureReason = "the handshake did not complete within "
                    + "\(Int(timers.handshakeAttemptTimeout)) seconds"
            } else if let lastSent = lastHandshakeMessageAt,
                      now.timeIntervalSince(lastSent) >= timers.handshakeRetryInterval {
                decision.initiateHandshake = true
            }
            return decision
        }

        if canInitiate {
            decision.initiateHandshake = true
        }
        return decision
    }

    /// Marks the "send one empty packet after the handshake" obligation as met.
    ///
    /// - Parameter now: The current time.
    func keepaliveSent(now: Date) {
        lock.lock()
        needsKeepaliveAfterHandshake = false
        passiveKeepaliveDeadline = nil
        lastOutboundAt = now
        lock.unlock()
    }

    /// Marks the peer as needing a keepalive once the session is up.
    func requestKeepaliveAfterHandshake() {
        lock.lock()
        needsKeepaliveAfterHandshake = true
        lock.unlock()
    }

    // MARK: - Handshake

    /// Starts a handshake attempt and returns the initiation to send.
    ///
    /// - Parameter now: The current time.
    /// - Returns: The 148 byte initiation, or `nil` when the attempt could not
    ///   be started.
    func startHandshake(now: Date) -> Data? {
        lock.lock()
        defer { lock.unlock() }

        let attempt = WireGuardHandshake(localStatic: localStaticPrivate,
                                        remotePublic: peer.publicKey,
                                        presharedKey: peer.presharedKey,
                                        isInitiator: true)
        do {
            let message = try attempt.createInitiation()
            handshake = attempt
            if handshakeStartedAt == nil {
                handshakeStartedAt = now
            }
            lastHandshakeMessageAt = now
            return message
        } catch {
            log("could not create a handshake initiation: \(error)")
            return nil
        }
    }

    /// Handles a handshake message addressed to this peer.
    ///
    /// - Parameters:
    ///   - message: The datagram.
    ///   - now: The current time.
    /// - Returns: What to do next.
    func handleHandshakeMessage(_ message: Data, now: Date) -> HandshakeOutcome {
        guard let type = wireGuardMessageType(of: message) else { return .none }
        switch type {
        case .handshakeInitiation:
            return handleInitiation(message, now: now)
        case .handshakeResponse:
            return handleResponse(message, now: now)
        case .cookieReply:
            return handleCookieReply(message)
        case .transportData:
            return .none
        }
    }

    /// Consumes an initiation and produces a response, installing the session.
    ///
    /// - Parameters:
    ///   - message: The 148 byte initiation.
    ///   - now: The current time.
    /// - Returns: `.send(response)` on success, `.none` when the message is not
    ///   acceptable.
    private func handleInitiation(_ message: Data, now: Date) -> HandshakeOutcome {
        lock.lock()
        defer { lock.unlock() }

        // Our public key is passed in so that an unauthenticated datagram costs
        // no scalar multiplication before its `mac1` is checked.
        let attempt = WireGuardHandshake(localStatic: localStaticPrivate,
                                        localStaticPublic: localStaticPublic,
                                        remotePublic: peer.publicKey,
                                        presharedKey: peer.presharedKey,
                                        isInitiator: false)
        do {
            let response = try attempt.consumeInitiation(message)
            // A responder can decrypt as soon as the response exists. Unlike
            // the reference implementation this engine also allows sending
            // immediately, because the session's keepalive only fires for the
            // initiating side (see WireGuardSession).
            installSession(attempt.sessionKeys, isInitiator: false, now: now)
            handshake = attempt
            lastHandshakeMessageAt = now
            log("accepted a handshake initiation from \(peer.publicKey.hexSummary)")
            return .send(response)
        } catch {
            log("dropped a handshake initiation: \(error)")
            return .none
        }
    }

    /// Consumes a response and installs the session.
    ///
    /// - Parameters:
    ///   - message: The 92 byte response.
    ///   - now: The current time.
    /// - Returns: `.established` on success, `.none` when the message is not
    ///   acceptable.
    private func handleResponse(_ message: Data, now: Date) -> HandshakeOutcome {
        lock.lock()
        defer { lock.unlock() }

        guard let attempt = handshake, attempt.isInitiator, attempt.matches(message) else {
            return .none
        }
        do {
            let result = try attempt.consumeResponse(message)
            installSession(result, isInitiator: true, now: now)
            log("handshake with \(peer.publicKey.hexSummary) complete")
            return .established
        } catch {
            log("dropped a handshake response: \(error)")
            return .none
        }
    }

    /// Stores the cookie from a cookie reply.
    ///
    /// - Parameter message: The 64 byte cookie reply.
    /// - Returns: `.cookieStored` on success, `.none` otherwise.
    private func handleCookieReply(_ message: Data) -> HandshakeOutcome {
        lock.lock()
        defer { lock.unlock() }

        guard let attempt = handshake else { return .none }
        do {
            _ = try attempt.consumeCookieReply(message)
            log("stored a cookie from \(peer.publicKey.hexSummary)")
            return .cookieStored
        } catch {
            log("dropped a cookie reply: \(error)")
            return .none
        }
    }

    /// Installs the keys from a completed handshake.
    ///
    /// - Parameters:
    ///   - keys: The handshake result, or `nil` when the handshake produced
    ///     nothing usable.
    ///   - isInitiator: Whether this side initiated.
    ///   - now: The current time.
    private func installSession(_ keys: WireGuardHandshake.Result?, isInitiator: Bool, now: Date) {
        guard let keys else { return }

        sendingKey = keys.sendKey
        sendingCounter = 0
        sendingRemoteIndex = keys.remoteIndex
        sendingSessionCreatedAt = now
        sendingSessionIsInitiator = isInitiator
        lastHandshakeCompletedAt = now
        lastInboundActivityAt = nil
        lastOutboundAt = nil
        passiveKeepaliveDeadline = nil
        // The initiator sends one empty packet as soon as the session exists, so
        // that the responder knows the handshake succeeded and any NAT binding
        // along the way stays open. The responder waits for the initiator's
        // first message instead (whitepaper, section 6.2).
        needsKeepaliveAfterHandshake = isInitiator
        activeReceivingIndex = keys.localIndex
        receivingSessions[keys.localIndex] = ReceivingSession(key: keys.receiveKey,
                                                             window: ReplayWindow(),
                                                             createdAt: now)
        handshake = nil
        handshakeStartedAt = nil
        pruneReceivingSessions(now: now)
    }

    // MARK: - Data path

    /// Encrypts one inner IP packet into a transport data message.
    ///
    /// - Parameters:
    ///   - packet: The inner IP packet.
    ///   - now: The current time.
    /// - Returns: The datagram to send, or `nil` when there is no usable
    ///   session.
    func seal(packet: Data, now: Date) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return sealLocked(packet: packet, now: now)
    }

    /// Encrypts an empty payload, producing a keepalive.
    ///
    /// - Parameter now: The current time.
    /// - Returns: The 32 byte datagram, or `nil` when there is no usable
    ///   session.
    func sealKeepalive(now: Date) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        let message = sealLocked(packet: Data(), now: now)
        if message != nil {
            needsKeepaliveAfterHandshake = false
            passiveKeepaliveDeadline = nil
        }
        return message
    }

    /// Encrypts a payload with the current session.
    ///
    /// - Parameters:
    ///   - packet: The plaintext, possibly empty.
    ///   - now: The current time.
    /// - Returns: The datagram to send, or `nil`.
    private func sealLocked(packet: Data, now: Date) -> Data? {
        guard let key = sendingKey,
              let created = sendingSessionCreatedAt,
              now.timeIntervalSince(created) < timers.rejectAfterTime,
              sendingCounter < timers.rejectAfterMessages else {
            return nil
        }

        let counter = sendingCounter
        var plaintext = [UInt8](packet)
        let padding = WireGuardPeerRuntime.paddingSize(forPacketSize: plaintext.count, mtu: mtu)
        if padding > 0 {
            plaintext.append(contentsOf: [UInt8](repeating: 0, count: padding))
        }

        let nonce = LittleEndian.transportNonce(counter: counter)
        guard let sealed = try? ChaChaPolyAEAD.seal(key: key,
                                                   nonce: nonce,
                                                   plaintext: plaintext,
                                                   authenticatedData: []) else {
            return nil
        }

        // Only consume the counter once the message exists: a failure above must
        // not leave a hole in the sequence the peer expects.
        sendingCounter = counter + 1

        let message = WireGuardTransportData(receiverIndex: sendingRemoteIndex,
                                             counter: counter,
                                             encryptedPacket: Data(sealed))
        lastOutboundAt = now
        passiveKeepaliveDeadline = nil
        bytesSent += UInt64(sealed.count + WireGuardWireFormat.transportHeaderSize)
        return message.serialized()
    }

    /// Decrypts a transport data message.
    ///
    /// Failures are silent by design: a forged, replayed or unknown packet is
    /// simply dropped, exactly as the protocol requires.
    ///
    /// - Parameters:
    ///   - message: The parsed message.
    ///   - now: The current time.
    /// - Returns: The inner IP packet with any transport padding removed, or
    ///   `nil` when the message must be dropped.
    func open(message: WireGuardTransportData, now: Date) -> Data? {
        lock.lock()
        defer { lock.unlock() }

        guard var session = receivingSessions[message.receiverIndex] else { return nil }

        let nonce = LittleEndian.transportNonce(counter: message.counter)
        guard let plaintext = try? ChaChaPolyAEAD.open(key: session.key,
                                                       nonce: nonce,
                                                       ciphertext: [UInt8](message.encryptedPacket),
                                                       authenticatedData: []) else {
            return nil
        }

        // The replay window is applied only after the tag verified, as the
        // whitepaper requires, so that forged counters cannot poison it.
        guard session.window.accept(message.counter) else { return nil }
        receivingSessions[message.receiverIndex] = session

        bytesReceived += UInt64(message.encryptedPacket.count + WireGuardWireFormat.transportHeaderSize)
        lastInboundActivityAt = now

        // Receiving anything confirms the session, and means the peer is alive:
        // if nothing is sent back soon, a passive keepalive keeps the NAT
        // binding open (whitepaper, section 6.5).
        if let interval = peer.persistentKeepalive, interval > 0 {
            passiveKeepaliveDeadline = nil
        } else if !plaintext.isEmpty {
            passiveKeepaliveDeadline = now.addingTimeInterval(timers.keepaliveTimeout)
        }

        pruneReceivingSessions(now: now)
        return WireGuardPeerRuntime.stripTransportPadding(Data(plaintext))
    }

    /// Tears the peer's sessions down, for example after a timer failure.
    ///
    /// - Parameter now: The current time.
    func reset(now: Date) {
        lock.lock()
        sendingKey = nil
        sendingSessionCreatedAt = nil
        sendingCounter = 0
        receivingSessions.removeAll()
        activeReceivingIndex = nil
        handshake = nil
        handshakeStartedAt = nil
        passiveKeepaliveDeadline = nil
        needsKeepaliveAfterHandshake = false
        lock.unlock()
    }

    // MARK: - Internals

    /// Whether the sending session can be used, with the lock already held.
    ///
    /// - Parameter now: The current time.
    /// - Returns: `true` when a usable key exists.
    private func hasUsableSendingSessionLocked(now: Date) -> Bool {
        guard sendingKey != nil, let created = sendingSessionCreatedAt else { return false }
        return now.timeIntervalSince(created) < timers.rejectAfterTime
            && sendingCounter < timers.rejectAfterMessages
    }

    /// Drops receiving sessions that are too old or too numerous.
    ///
    /// - Parameter now: The current time.
    private func pruneReceivingSessions(now: Date) {
        for (index, session) in receivingSessions
        where index != activeReceivingIndex
            && now.timeIntervalSince(session.createdAt) >= timers.rejectAfterTime {
            receivingSessions.removeValue(forKey: index)
        }
        while receivingSessions.count > 4 {
            guard let oldest = receivingSessions
                .filter({ $0.key != activeReceivingIndex })
                .min(by: { $0.value.createdAt < $1.value.createdAt }) else { break }
            receivingSessions.removeValue(forKey: oldest.key)
        }
    }

    /// How much zero padding to add to a plaintext before encryption.
    ///
    /// The whitepaper (section 5.4.6) asks for the encapsulated packet to be
    /// padded to a multiple of sixteen bytes *without* changing the packet's
    /// own length field, "though that zero padding should never increase the
    /// UDP packet size beyond the maximum transmission unit length". This
    /// mirrors the reference implementation's calculation.
    ///
    /// - Parameters:
    ///   - size: The plaintext size in bytes.
    ///   - mtu: The tunnel MTU, or zero to always pad to the next multiple.
    /// - Returns: How many zero bytes to append.
    static func paddingSize(forPacketSize size: Int, mtu: Int) -> Int {
        guard size > 0 else { return 0 }
        let lastUnit = (mtu > 0 && size > mtu) ? size % mtu : size
        var paddedSize = (lastUnit + 15) / 16 * 16
        if mtu > 0, paddedSize > mtu {
            paddedSize = mtu
        }
        return Swift.max(0, paddedSize - lastUnit)
    }

    /// Removes the zero padding a peer added before encryption.
    ///
    /// The inner IP packet's own length field says where the real packet ends.
    ///
    /// - Parameter plaintext: The decrypted payload.
    /// - Returns: The packet, trimmed, or the input unchanged when it does not
    ///   parse (a keepalive, for example, is legitimately empty).
    static func stripTransportPadding(_ plaintext: Data) -> Data {
        guard plaintext.count > 1 else { return Data(plaintext) }
        guard let declared = IPPacket.declaredLength(plaintext),
              declared > 0,
              declared < plaintext.count else {
            return Data(plaintext)
        }
        return Data(plaintext.prefix(declared))
    }
}

extension Data {

    /// A short identifier for logs: the first four bytes in hex.
    var hexSummary: String {
        prefix(4).map { String(format: "%02x", $0) }.joined()
    }
}
