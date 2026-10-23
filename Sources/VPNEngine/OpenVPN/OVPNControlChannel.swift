import Foundation

/// Something the reliability layer noticed about a received control packet
/// that is not TLS bytes.
///
/// `receive(_:)` returns the TLS records the peer sent; everything else a
/// caller needs to drive the handshake (resets, acknowledgements, packets for
/// another key state, packets that were dropped) is delivered here and drained
/// with ``OVPNReliabilityLayer/drainEvents()``.
public enum OVPNControlEvent: Sendable, Equatable {
    /// The peer's `P_CONTROL_HARD_RESET_*` arrived: the control channel is up.
    case hardResetReceived(keyID: UInt8)
    /// The peer asked for a renegotiation with `P_CONTROL_SOFT_RESET_V1`.
    case softResetReceived(keyID: UInt8)
    /// The peer acknowledged these of our packet ids.
    case ackReceived([UInt32])
    /// The peer's session id was learned from its first packet.
    case peerSessionEstablished(OVPNSessionID)
    /// A packet arrived for a key id this layer does not own (a new key state
    /// started by the peer, typically right after a soft reset).
    case packetForOtherKeyState(keyID: UInt8, opcode: OVPNControlOpcode)
    /// `P_CONTROL_WKC_V1` arrived (tls-crypt-v2 key confirmation).
    case wkcReceived
    /// The packet was structurally valid but was dropped, with the reason.
    case dropped(reason: String)
}

/// The OpenVPN control channel reliability layer.
///
/// This is a faithful reimplementation of the "reliable" layer that
/// `src/openvpn/reliable.c` provides and `src/openvpn/ssl_pkt.c` puts on the
/// wire. It moves **opaque bytes**: it never looks inside a TLS record, so the
/// host app is free to pair it with any TLS stack.
///
/// ## What it does
///
/// * Wraps outgoing TLS bytes in `P_CONTROL_V1` packets, one packet id per
///   packet, chunked to fit the link MTU.
/// * Retransmits unacknowledged packets with an exponential backoff
///   (1 s, doubling, capped at 8 s) until the peer acknowledges them or the
///   60-second handshake window expires.
/// * Produces `P_ACK_V1` packets and piggybacks acknowledgements on outgoing
///   packets, remembering the last few acknowledgements so a lost one can be
///   resent (`reliable_ack_write`/`ack_mru`).
/// * Delivers inbound payloads strictly in packet-id order, remembering up to
///   `RELIABLE_CAPACITY` (12) packets that arrived early.
/// * Retries `P_CONTROL_HARD_RESET_CLIENT_V2` until the server's hard reset
///   arrives.
/// * Applies `--tls-auth` HMACs or `--tls-crypt` wrapping through
///   ``OVPNControlCrypto``.
///
/// ## Wire format of a control packet
///
/// ```
///   +----------+------------+---------------+-----------+--------------------+
///   | op/keyid | session id | [tls-auth MAC | [packet   | ack array          |
///   | 1 byte   | 8 bytes    |  or tls-crypt |  id]      | 1 + 4n (+8) bytes  |
///   +----------+------------+  tag]         | 8 bytes   |                    |
///                            +---------------+-----------+--------------------+
///                                              then (unless P_ACK_V1):
///                              message packet id (4) || TLS bytes
/// ```
///
/// The packet id after the MAC is the *crypto* packet id (`tls_wrap.opt.
/// packet_id` in OpenVPN) used for replay protection; the "message packet id"
/// before the payload is the *reliability* packet id `reliable.c` prepends in
/// `reliable_mark_active_outgoing()`. They are different counters and both
/// exist with `--tls-auth`.
public final class OVPNReliabilityLayer: @unchecked Sendable {

    // MARK: - Configuration

    /// Key id of this key state (0 for the first handshake, then 1, 2, ...).
    public let keyID: UInt8
    /// `true` when this layer runs on the server side.
    public let isServer: Bool
    /// Packet authentication/encryption for the control channel.
    public let crypto: OVPNControlCrypto
    /// Set when the crypto could not be built from the supplied keys; the
    /// layer then falls back to an unauthenticated control channel.
    public let degradedReason: String?

    /// Opcode used for the first packet of this key state.
    public var initialOpcode: OVPNControlOpcode
    /// Wrapped client key appended to `P_CONTROL_HARD_RESET_CLIENT_V3` and
    /// `P_CONTROL_WKC_V1` packets (`--tls-crypt-v2`).
    public var tlsCryptV2WrappedKey: Data?

    /// Maximum size of the reliable payload of one control packet. Kept below
    /// a typical 1500-byte link MTU by default so control packets never
    /// fragment.
    public var maxPayloadSize: Int = 1200

    /// Maximum number of acknowledgements in one packet. OpenVPN caps this at
    /// four for clients without tls-auth/tls-crypt because old SoftEther
    /// servers drop packets with more (see `write_control_auth`).
    public var maxAcksPerPacket: Int = 4

    /// First retransmission timeout (`--tls-timeout`, default 1 s).
    public var initialRetransmitTimeout: TimeInterval = 1
    /// Ceiling for the exponential backoff (`RELIABLE_MAX_TIMEOUT`, 8 s).
    public var maxRetransmitTimeout: TimeInterval = 8
    /// How long the handshake may take before `tick` reports a timeout
    /// (`--hand-window`, 60 s).
    public var handshakeTimeout: TimeInterval = 60
    /// How many out-of-order packets to remember (`RELIABLE_CAPACITY`, 12).
    public var capacity: Int = 12

    // MARK: - State

    /// One unacknowledged outgoing packet.
    private struct SendEntry {
        var packetID: UInt32
        var opcode: OVPNControlOpcode
        var payload: Data
        var timeout: TimeInterval
        var nextRetry: Date
        var firstSent: Date
    }

    private let lock = OVPNMutex()
    private var sendQueue: [SendEntry] = []
    private var pendingInbound: [UInt32: Data] = [:]
    private var ackQueue: [UInt32] = []
    private var ackMRU: [UInt32] = []
    private var nextSendID: UInt32 = 0
    private var nextInboundID: UInt32 = 0
    private var cryptoSequence: UInt32 = 0
    private var events: [OVPNControlEvent] = []
    private var started: Date?
    private var resetAcknowledged = false
    private var sawRemoteReset = false
    private var didEstablishPeerSession = false

    /// Our session id; constant for the life of the session, shared by every
    /// key state.
    public let localSessionID: OVPNSessionID

    /// The peer's session id, learned from its first packet.
    public private(set) var remoteSessionID: OVPNSessionID?

    // MARK: - Init

    /// Create a reliability layer for one key state.
    ///
    /// - Parameters:
    ///   - keyID: key id this layer owns (low three bits of the opcode byte).
    ///   - isServer: run the server side of the handshake.
    ///   - tlsAuthKey: `--tls-auth` key, if configured.
    ///   - tlsCryptKey: `--tls-crypt` key, if configured.
    public init(
        keyID: UInt8,
        isServer: Bool,
        tlsAuthKey: OVPNStaticKeyFile?,
        tlsCryptKey: OVPNStaticKeyFile?
    ) {
        self.keyID = keyID
        self.isServer = isServer
        if let built = try? OVPNControlCrypto(tlsAuthKey: tlsAuthKey, tlsCryptKey: tlsCryptKey) {
            self.crypto = built
            self.degradedReason = nil
        } else {
            self.crypto = .unprotected
            self.degradedReason = "control channel keys were rejected; falling back to TLS_WRAP_NONE"
        }
        self.localSessionID = .random()
        self.initialOpcode = OVPNControlOpcode.initialOpcode(isServer: isServer, hasTLSCryptV2: false)
    }

    /// Create a reliability layer with explicit crypto settings, used by the
    /// session driver once it knows whether `--tls-crypt-v2` is in play.
    public init(
        keyID: UInt8,
        isServer: Bool,
        crypto: OVPNControlCrypto,
        localSessionID: OVPNSessionID = .random(),
        initialOpcode: OVPNControlOpcode? = nil,
        tlsCryptV2WrappedKey: Data? = nil
    ) {
        self.keyID = keyID
        self.isServer = isServer
        self.crypto = crypto
        self.degradedReason = nil
        self.localSessionID = localSessionID
        self.initialOpcode = initialOpcode
            ?? OVPNControlOpcode.initialOpcode(isServer: isServer, hasTLSCryptV2: tlsCryptV2WrappedKey != nil)
        self.tlsCryptV2WrappedKey = tlsCryptV2WrappedKey
    }

    // MARK: - Handshake

    /// Retry `P_CONTROL_HARD_RESET_CLIENT_V2` until the server's hard reset
    /// arrives, and return the first datagram to send.
    ///
    /// OpenVPN's first packet is a *null* reliable buffer, i.e. it carries no
    /// TLS bytes at all — only its message packet id 0 (see
    /// `session_move_pre_start()` in `ssl.c`).
    @discardableResult
    public func beginHandshake(now: Date = Date()) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        if started == nil { started = now }
        let opcode = initialOpcode
        if let existing = sendQueue.first(where: { $0.packetID == 0 && $0.opcode == opcode }) {
            // Already queued: just retransmit it.
            return try transmitLocked(existing, now: now)
        }
        let entry = SendEntry(
            packetID: nextSendID,
            opcode: opcode,
            payload: Data(),
            timeout: initialRetransmitTimeout,
            nextRetry: now.addingTimeInterval(initialRetransmitTimeout),
            firstSent: now
        )
        nextSendID &+= 1
        sendQueue.append(entry)
        return try transmitLocked(entry, now: now)
    }

    /// Start a renegotiation by sending `P_CONTROL_SOFT_RESET_V1` with this
    /// layer's key id (the caller creates a layer with the new key id first).
    @discardableResult
    public func sendSoftReset(now: Date = Date()) throws -> Data {
        initialOpcode = .softResetV1
        return try beginHandshake(now: now)
    }

    /// `true` once the peer's hard reset has been seen and our own reset has
    /// been acknowledged.
    public var isHandshakeComplete: Bool {
        lock.lock()
        defer { lock.unlock() }
        return sawRemoteReset && resetAcknowledged
    }

    /// `true` once the peer acknowledged our reset packet.
    public var isResetAcknowledged: Bool {
        lock.lock()
        defer { lock.unlock() }
        return resetAcknowledged
    }

    /// Number of packets waiting for an acknowledgement.
    public var outstandingPacketCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return sendQueue.count
    }

    // MARK: - Sending

    /// Wrap an outgoing TLS record chunk into one or more control packets.
    ///
    /// - Parameter data: TLS bytes produced by the host's TLS stack. Large
    ///   blobs are split into ``maxPayloadSize`` chunks, each with its own
    ///   packet id, so they can be retransmitted independently.
    /// - Returns: datagrams to send, in order.
    public func wrapOutgoingTLS(_ data: Data, now: Date = Date()) -> [Data] {
        lock.lock()
        defer { lock.unlock() }
        guard !data.isEmpty else { return [] }
        if started == nil { started = now }

        var datagrams: [Data] = []
        var offset = 0
        let chunkSize = max(64, maxPayloadSize)
        while offset < data.count {
            let end = min(offset + chunkSize, data.count)
            let chunk = data.subdata(in: offset..<end)
            offset = end

            let entry = SendEntry(
                packetID: nextSendID,
                opcode: .controlV1,
                payload: chunk,
                timeout: initialRetransmitTimeout,
                nextRetry: now.addingTimeInterval(initialRetransmitTimeout),
                firstSent: now
            )
            nextSendID &+= 1
            sendQueue.append(entry)
            if let datagram = try? transmitLocked(entry, now: now) {
                datagrams.append(datagram)
            }
        }
        return datagrams
    }

    /// Send an arbitrary control channel payload (used for the OpenVPN
    /// control channel strings such as `PUSH_REQUEST` when they are not
    /// carried inside TLS).
    public func wrapOutgoingControl(
        payload: Data,
        opcode: OVPNControlOpcode = .controlV1,
        now: Date = Date()
    ) throws -> [Data] {
        lock.lock()
        defer { lock.unlock() }
        if started == nil { started = now }
        guard payload.count <= maxPayloadSize else {
            throw OVPNError.malformedControlPacket("control payload of \(payload.count) bytes exceeds the MTU budget")
        }
        let entry = SendEntry(
            packetID: nextSendID,
            opcode: opcode,
            payload: payload,
            timeout: initialRetransmitTimeout,
            nextRetry: now.addingTimeInterval(initialRetransmitTimeout),
            firstSent: now
        )
        nextSendID &+= 1
        sendQueue.append(entry)
        return [try transmitLocked(entry, now: now)]
    }

    /// ACK-only packets that are due.
    ///
    /// Each returned datagram carries up to ``maxAcksPerPacket`` acknowledgements
    /// and clears them from the queue; the ids stay in the "most recently
    /// used" list and are repeated on subsequent packets, exactly like
    /// `reliable_ack_write()` does.
    public func pendingAcks(now: Date = Date()) -> [Data] {
        lock.lock()
        defer { lock.unlock() }
        guard remoteSessionID != nil else { return [] }

        var datagrams: [Data] = []
        while !ackQueue.isEmpty {
            let block = ackBlockLocked(limit: maxAcksPerPacket)
            let datagram = (try? buildDatagramLocked(
                opcode: .ackV1,
                payload: Data(),
                messagePacketID: nil,
                ackBlock: block,
                appended: nil,
                now: now
            )) ?? nil
            guard let datagram else { break }
            datagrams.append(datagram)
        }
        return datagrams
    }

    /// Retransmissions and handshake retries that are due at `now`.
    ///
    /// - Throws: ``OVPNError/controlChannelTimeout(seconds:)`` when the
    ///   handshake has not completed within ``handshakeTimeout``.
    public func tick(now: Date = Date()) throws -> [Data] {
        lock.lock()
        defer { lock.unlock() }

        if let started, !isHandshakeCompleteLocked,
           now.timeIntervalSince(started) > handshakeTimeout {
            throw OVPNError.controlChannelTimeout(seconds: Int(handshakeTimeout))
        }

        var datagrams: [Data] = []
        for index in sendQueue.indices {
            guard sendQueue[index].nextRetry <= now else { continue }
            let entry = sendQueue[index]
            if let datagram = try? transmitLocked(entry, now: now) {
                datagrams.append(datagram)
            }
            sendQueue[index].timeout = min(sendQueue[index].timeout * 2, maxRetransmitTimeout)
            sendQueue[index].nextRetry = now.addingTimeInterval(sendQueue[index].timeout)
        }
        return datagrams
    }

    // MARK: - Receiving

    /// Feed a received control packet in.
    ///
    /// - Parameter datagram: the raw UDP payload.
    /// - Returns: TLS bytes the packet carried, already put back in packet-id
    ///   order. One element per reliability message; concatenate them (or
    ///   append each to your TLS stack in order) before parsing.
    /// - Throws: ``OVPNError`` when the packet cannot be authenticated or is
    ///   structurally invalid. Packets that are valid but not interesting
    ///   (duplicates, another key state, another session) are reported through
    ///   ``drainEvents()`` and return an empty array.
    public func receive(_ datagram: Data, now: Date = Date()) throws -> [Data] {
        let unwrapped = try crypto.unwrap(datagram)

        lock.lock()
        defer { lock.unlock() }
        if started == nil { started = now }

        guard unwrapped.keyID == keyID else {
            events.append(.packetForOtherKeyState(keyID: unwrapped.keyID, opcode: unwrapped.opcode))
            return []
        }
        guard unwrapped.sessionID != localSessionID else {
            events.append(.dropped(reason: "packet echoed back from our own session id"))
            return []
        }
        if let remoteSessionID, remoteSessionID != unwrapped.sessionID {
            events.append(.dropped(reason: "session id mismatch"))
            return []
        }

        let (ack, afterAck) = try OVPNControlAck.decode(unwrapped.plaintext, at: 0)
        var cursor = afterAck
        var messagePacketID: UInt32?
        var payload = Data()
        if unwrapped.opcode != .ackV1 {
            messagePacketID = try OVPNWire.readUInt32(unwrapped.plaintext, at: cursor, field: "message packet id")
            cursor += 4
            payload = try OVPNWire.readRemainder(unwrapped.plaintext, after: cursor, field: "control payload")
        }

        // Learn the peer's session id from its first packet, and insist on it
        // from then on.
        if remoteSessionID == nil {
            remoteSessionID = unwrapped.sessionID
            events.append(.peerSessionEstablished(unwrapped.sessionID))
            didEstablishPeerSession = true
        } else if didEstablishPeerSession, !ack.ids.isEmpty,
                  let ackSessionID = ack.remoteSessionID, ackSessionID != localSessionID.bytes {
            events.append(.dropped(reason: "acknowledgement for another session id"))
            return []
        }

        // Process acknowledgements of our own packets.
        if !ack.ids.isEmpty {
            for packetID in ack.ids {
                sendQueue.removeAll { $0.packetID == packetID }
                if packetID == 0 { resetAcknowledged = true }
            }
            events.append(.ackReceived(ack.ids))
        }

        switch unwrapped.opcode {
        case .hardResetClientV2, .hardResetClientV3, .hardResetServerV2,
             .hardResetClientV1, .hardResetServerV1:
            sawRemoteReset = true
            events.append(.hardResetReceived(keyID: unwrapped.keyID))
        case .softResetV1:
            sawRemoteReset = true
            events.append(.softResetReceived(keyID: unwrapped.keyID))
        case .wkcV1:
            events.append(.wkcReceived)
        default:
            break
        }

        guard let messagePacketID else { return [] }
        return try acceptLocked(packetID: messagePacketID, payload: payload)
    }

    /// Hand a reliable message to the ordering buffer.
    private func acceptLocked(packetID: UInt32, payload: Data) throws -> [Data] {
        if packetID < nextInboundID {
            // Duplicate or retransmission: acknowledge it again so the peer
            // stops retrying, but do not deliver the bytes twice.
            enqueueAckLocked(packetID)
            return []
        }
        if packetID >= nextInboundID &+ UInt32(max(1, capacity)) {
            // Too far ahead to be useful; OpenVPN drops these instead of
            // buffering them (reliable_wont_break_sequentiality).
            events.append(.dropped(reason: "packet id \(packetID) is outside the reassembly window"))
            return []
        }
        if pendingInbound[packetID] == nil {
            pendingInbound[packetID] = payload
        }
        enqueueAckLocked(packetID)

        var delivered: [Data] = []
        while let next = pendingInbound.removeValue(forKey: nextInboundID) {
            // A `P_CONTROL_HARD_RESET_*` (and a soft reset) is a *null* reliable
            // buffer: it carries a packet id but no bytes at all, so it is
            // acknowledged and then dropped instead of being reported as an
            // empty TLS chunk.
            if !next.isEmpty { delivered.append(next) }
            nextInboundID &+= 1
        }
        return delivered
    }

    private func enqueueAckLocked(_ packetID: UInt32) {
        if !ackQueue.contains(packetID) { ackQueue.append(packetID) }
    }

    // MARK: - Events

    /// Take everything that happened since the last call.
    public func drainEvents() -> [OVPNControlEvent] {
        lock.lock()
        defer { lock.unlock() }
        let drained = events
        events.removeAll()
        return drained
    }

    // MARK: - Internals

    private var isHandshakeCompleteLocked: Bool { sawRemoteReset && resetAcknowledged }

    /// Promote new acknowledgements into the MRU list and build the ack block.
    private func ackBlockLocked(limit: Int) -> OVPNControlAck {
        let promotedCount = min(limit, ackQueue.count)
        if promotedCount > 0 {
            let promoted = Array(ackQueue.prefix(promotedCount))
            ackQueue.removeFirst(promotedCount)
            ackMRU = promoted + ackMRU.filter { !promoted.contains($0) }
            if ackMRU.count > maxAcksPerPacket * 2 {
                ackMRU = Array(ackMRU.prefix(maxAcksPerPacket * 2))
            }
        }
        let ids = Array(ackMRU.prefix(limit))
        return OVPNControlAck(ids: ids, remoteSessionID: ids.isEmpty ? nil : remoteSessionID?.bytes)
    }

    private func transmitLocked(_ entry: SendEntry, now: Date) throws -> Data {
        let ackBlock = ackBlockLocked(limit: maxAcksPerPacket)
        let appended: Data? = {
            guard entry.opcode == .hardResetClientV3 || entry.opcode == .wkcV1 else { return nil }
            return tlsCryptV2WrappedKey
        }()
        return try buildDatagramLocked(
            opcode: entry.opcode,
            payload: entry.payload,
            messagePacketID: entry.opcode == .ackV1 ? nil : entry.packetID,
            ackBlock: ackBlock,
            appended: appended,
            now: now
        )
    }

    private func buildDatagramLocked(
        opcode: OVPNControlOpcode,
        payload: Data,
        messagePacketID: UInt32?,
        ackBlock: OVPNControlAck,
        appended: Data?,
        now: Date
    ) throws -> Data {
        var plaintext = ackBlock.encode()
        if let messagePacketID {
            OVPNWire.append(messagePacketID, to: &plaintext)
            plaintext.append(payload)
        }

        let packetID = OVPNPacketID(
            sequence: cryptoSequence,
            timestamp: crypto.mode == .none ? nil : UInt32(clamping: Int(now.timeIntervalSince1970))
        )
        if crypto.mode != .none { cryptoSequence &+= 1 }

        return try crypto.wrap(
            opcodeByte: OVPNControlOpcode.opcodeByte(opcode, keyID: keyID),
            sessionID: localSessionID,
            packetID: packetID,
            payload: plaintext,
            appended: appended ?? Data()
        )
    }
}

extension OVPNControlCrypto {
    /// A control channel with no authentication at all (`TLS_WRAP_NONE`).
    public static var unprotected: OVPNControlCrypto {
        OVPNControlCrypto(
            mode: .none,
            digest: .sha256,
            sendHMACKey: Data(),
            receiveHMACKey: Data(),
            sendCipherKey: Data(),
            receiveCipherKey: Data()
        )
    }
}
