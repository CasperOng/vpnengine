import Foundation

/// OpenVPN packet opcodes (`struct_send`/`P_*` in `src/openvpn/ssl_pkt.h`).
///
/// The first byte of *every* OpenVPN packet is `(opcode << 3) | key_id`, so
/// the low three bits identify which key state of the session the packet
/// belongs to (`key_id` is 0 for the first handshake, then 1, 2, ... for each
/// renegotiation).
public enum OVPNControlOpcode: UInt8, Sendable, Equatable, CaseIterable {
    /// `P_CONTROL_HARD_RESET_CLIENT_V1` (1) — obsolete, pre-2.0.
    case hardResetClientV1 = 1
    /// `P_CONTROL_HARD_RESET_SERVER_V1` (2) — obsolete, pre-2.0.
    case hardResetServerV1 = 2
    /// `P_CONTROL_SOFT_RESET_V1` (3) — starts a renegotiation.
    case softResetV1 = 3
    /// `P_CONTROL_V1` (4) — carries TLS records.
    case controlV1 = 4
    /// `P_ACK_V1` (5) — acknowledgement only, no payload.
    case ackV1 = 5
    /// `P_DATA_V1` (6) — data channel packet.
    case dataV1 = 6
    /// `P_CONTROL_HARD_RESET_CLIENT_V2` (7) — first packet from a client.
    case hardResetClientV2 = 7
    /// `P_CONTROL_HARD_RESET_SERVER_V2` (8) — first packet from a server.
    case hardResetServerV2 = 8
    /// `P_DATA_V2` (9) — data channel packet carrying a 3-byte peer id.
    case dataV2 = 9
    /// `P_CONTROL_HARD_RESET_CLIENT_V3` (10) — first packet with
    /// `--tls-crypt-v2`, carrying the wrapped client key.
    case hardResetClientV3 = 10
    /// `P_CONTROL_WKC_V1` (11) — wrapped key confirmation.
    case wkcV1 = 11

    /// Shift applied to the opcode to build the first byte.
    public static let shift: UInt8 = 3

    /// Mask for the key id in the first byte.
    public static let keyIDMask: UInt8 = 0x07

    /// Build the first byte of a packet.
    public static func opcodeByte(_ opcode: OVPNControlOpcode, keyID: UInt8) -> UInt8 {
        (opcode.rawValue << shift) | (keyID & keyIDMask)
    }

    /// Decode the first byte of a packet.
    public static func parse(_ byte: UInt8) -> (opcode: OVPNControlOpcode, keyID: UInt8)? {
        guard let opcode = OVPNControlOpcode(rawValue: byte >> shift) else { return nil }
        return (opcode, byte & keyIDMask)
    }

    /// Control channel opcode (goes through the reliability layer).
    public var isControl: Bool {
        switch self {
        case .hardResetClientV1, .hardResetServerV1, .softResetV1, .controlV1, .ackV1,
             .hardResetClientV2, .hardResetServerV2, .hardResetClientV3, .wkcV1:
            return true
        case .dataV1, .dataV2:
            return false
        }
    }

    /// Data channel opcode.
    public var isData: Bool { !isControl }

    /// Any of the `P_CONTROL_HARD_RESET_*` variants.
    public var isHardReset: Bool {
        switch self {
        case .hardResetClientV1, .hardResetServerV1, .hardResetClientV2, .hardResetServerV2, .hardResetClientV3:
            return true
        case .softResetV1, .controlV1, .ackV1, .dataV1, .dataV2, .wkcV1:
            return false
        }
    }

    /// The name OpenVPN uses in its debug output.
    public var name: String {
        switch self {
        case .hardResetClientV1: return "P_CONTROL_HARD_RESET_CLIENT_V1"
        case .hardResetServerV1: return "P_CONTROL_HARD_RESET_SERVER_V1"
        case .softResetV1: return "P_CONTROL_SOFT_RESET_V1"
        case .controlV1: return "P_CONTROL_V1"
        case .ackV1: return "P_ACK_V1"
        case .dataV1: return "P_DATA_V1"
        case .hardResetClientV2: return "P_CONTROL_HARD_RESET_CLIENT_V2"
        case .hardResetServerV2: return "P_CONTROL_HARD_RESET_SERVER_V2"
        case .dataV2: return "P_DATA_V2"
        case .hardResetClientV3: return "P_CONTROL_HARD_RESET_CLIENT_V3"
        case .wkcV1: return "P_CONTROL_WKC_V1"
        }
    }

    /// The reset opcode this side of the connection starts a session with.
    public static func initialOpcode(isServer: Bool, hasTLSCryptV2: Bool) -> OVPNControlOpcode {
        if isServer { return .hardResetServerV2 }
        return hasTLSCryptV2 ? .hardResetClientV3 : .hardResetClientV2
    }
}

/// A control channel packet id: 4-byte sequence, optionally with the 4-byte
/// timestamp OpenVPN calls the *long form*.
///
/// `packet_id_write()` in `src/openvpn/packet_id.c` writes both fields in
/// network order and, when it prepends them (`prepend = true`, the path the
/// data channel and tls-auth use), the sequence ends up first:
///
/// ```c
/// buf_write_prepend(buf, &net_time, 4);  /* then */
/// buf_write_prepend(buf, &net_id, 4);    /* so id is at the front */
/// ```
///
/// The tls-crypt path appends with `prepend = false` and reaches the same
/// order (`id` then `time`) — `TLS_CRYPT_PID_SIZE` is `4 + 4` bytes at offset
/// `1 + 8`.
public struct OVPNPacketID: Sendable, Equatable {
    /// The sequence number.
    public var sequence: UInt32
    /// Timestamp, present only in the long form.
    public var timestamp: UInt32?

    /// Create a packet id.
    public init(sequence: UInt32, timestamp: UInt32? = nil) {
        self.sequence = sequence
        self.timestamp = timestamp
    }

    /// The bytes this packet id occupies on the wire.
    public var wireBytes: Data {
        var out = Data()
        OVPNWire.append(sequence, to: &out)
        if let timestamp {
            OVPNWire.append(timestamp, to: &out)
        }
        return out
    }

    /// Number of bytes this packet id occupies.
    public var wireLength: Int { timestamp == nil ? 4 : 8 }

    /// Read a packet id at `offset`.
    public static func decode(_ data: Data, at offset: Int, longForm: Bool) throws -> (packetID: OVPNPacketID, nextOffset: Int) {
        let sequence = try OVPNWire.readUInt32(data, at: offset, field: "packet id")
        guard longForm else {
            return (OVPNPacketID(sequence: sequence), offset + 4)
        }
        let timestamp = try OVPNWire.readUInt32(data, at: offset + 4, field: "packet timestamp")
        return (OVPNPacketID(sequence: sequence, timestamp: timestamp), offset + 8)
    }
}

/// The acknowledgement array that prefixes the reliable payload of every
/// control packet.
///
/// `reliable_ack_write()` / `reliable_ack_parse()` in `src/openvpn/reliable.c`:
///
/// ```
///  [count: 1 byte][packet ids: 4 bytes each][remote session id: 8 bytes]
///                                             ^ only when count > 0
/// ```
///
/// The session id comes *after* the ids, not before, which is easy to get
/// wrong: `ACK_SIZE(n)` in `reliable.h` documents the total size.
struct OVPNControlAck: Sendable, Equatable {
    /// Acknowledged packet ids, most recent first.
    var ids: [UInt32]
    /// The sender's view of our session id, present when `ids` is not empty.
    var remoteSessionID: Data?

    static let empty = OVPNControlAck(ids: [], remoteSessionID: nil)

    /// Bytes this ack block occupies.
    var wireLength: Int { 1 + ids.count * 4 + (ids.isEmpty ? 0 : 8) }

    /// Serialise the block.
    func encode() -> Data {
        var out = Data()
        out.append(UInt8(truncatingIfNeeded: ids.count))
        for id in ids {
            OVPNWire.append(id, to: &out)
        }
        if !ids.isEmpty, let remoteSessionID, remoteSessionID.count == 8 {
            out.append(remoteSessionID)
        }
        return out
    }

    /// Parse the block at `offset`.
    static func decode(_ data: Data, at offset: Int) throws -> (ack: OVPNControlAck, nextOffset: Int) {
        guard offset >= 0, data.count > offset else {
            throw OVPNError.packetTooShort(field: "ack array length", need: offset + 1, have: data.count)
        }
        let count = Int(data[data.startIndex + offset])
        // `reliable_ack_parse` refuses more than RELIABLE_ACK_SIZE ids.
        guard count <= 8 else {
            throw OVPNError.malformedControlPacket("ack array of \(count) entries exceeds RELIABLE_ACK_SIZE")
        }
        var cursor = offset + 1
        var ids: [UInt32] = []
        ids.reserveCapacity(count)
        for _ in 0..<count {
            ids.append(try OVPNWire.readUInt32(data, at: cursor, field: "ack packet id"))
            cursor += 4
        }
        var remoteSessionID: Data?
        if count > 0 {
            remoteSessionID = try OVPNWire.readBytes(data, at: cursor, count: 8, field: "ack remote session id")
            cursor += 8
        }
        return (OVPNControlAck(ids: ids, remoteSessionID: remoteSessionID), cursor)
    }
}

/// An OpenVPN session id: eight opaque bytes, random at session start and
/// constant across renegotiations of that session.
public struct OVPNSessionID: Sendable, Equatable, CustomStringConvertible {
    /// The eight raw bytes.
    public let bytes: Data

    /// Wrap eight bytes.
    public init?(_ bytes: Data) {
        guard bytes.count == 8 else { return nil }
        self.bytes = bytes
    }

    /// Internal bypass used when the length is already known.
    init(unchecked bytes: Data) {
        self.bytes = bytes
    }

    /// Generate a fresh random session id (`session_id_random`).
    public static func random() -> OVPNSessionID {
        let bytes = OVPNWire.randomBytes(8)
        return OVPNSessionID(bytes) ?? OVPNSessionID(unchecked: bytes.prefix(8))
    }

    /// Lower-case hex, as OpenVPN logs it.
    public var description: String { OVPNWire.encodeHex(bytes) }
}
