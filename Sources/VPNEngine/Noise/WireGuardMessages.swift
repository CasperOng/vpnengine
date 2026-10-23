//
//  WireGuardMessages.swift
//  VPNEngine
//
//  The four WireGuard message types and their wire format (whitepaper, sections
//  5.4.2, 5.4.3, 5.4.6 and 5.4.7).
//
//  Every field is little endian except the TAI64N timestamp, which is a byte
//  string with its own defined order, and the two MACs, which are opaque. The
//  message type is a 32 bit little endian value that is really a one byte type
//  followed by three zero reserved bytes, which is why the reserved bytes
//  appear as part of the type field here.
//
//  Parsing is total: every function returns `nil` rather than trapping, because
//  these messages arrive from the network.
//

import Foundation

/// The WireGuard message types.
public enum WireGuardMessageType: UInt32, Sendable, CaseIterable {

    /// Handshake initiation, sent by the initiator.
    case handshakeInitiation = 1

    /// Handshake response, sent by the responder.
    case handshakeResponse = 2

    /// Cookie reply, sent by a responder under load.
    case cookieReply = 3

    /// Transport data, used for everything after a handshake.
    case transportData = 4
}

/// Sizes and offsets of the WireGuard wire formats.
public enum WireGuardWireFormat {

    /// Size of a handshake initiation message.
    public static let initiationSize = 148

    /// Size of a handshake response message.
    public static let responseSize = 92

    /// Size of a cookie reply message.
    public static let cookieReplySize = 64

    /// Size of the header on a transport data message.
    public static let transportHeaderSize = 16

    /// Size of a transport data message carrying no payload: header plus tag.
    public static let keepaliveSize = transportHeaderSize + 16

    /// Offset of `mac1` within a handshake initiation.
    public static let initiationMAC1Offset = 116

    /// Offset of `mac2` within a handshake initiation.
    public static let initiationMAC2Offset = 132

    /// Offset of `mac1` within a handshake response.
    public static let responseMAC1Offset = 60

    /// Offset of `mac2` within a handshake response.
    public static let responseMAC2Offset = 76

    /// Offset of the receiver index within a transport data message.
    public static let transportReceiverOffset = 4

    /// Offset of the counter within a transport data message.
    public static let transportCounterOffset = 8

    /// Offset of the ciphertext within a transport data message.
    public static let transportContentOffset = 16

    /// Size of a message type field, including the reserved zero bytes.
    public static let typeFieldSize = 4

    /// Size of a MAC or a cookie.
    public static let macSize = 16

    /// Size of an X25519 public key.
    public static let publicKeySize = 32

    /// Size of the AEAD tag that follows every encrypted field.
    public static let tagSize = 16

    /// Size of a TAI64N timestamp.
    public static let timestampSize = 12

    /// Size of a cookie reply nonce.
    public static let cookieNonceSize = 24

    /// The all-zero nonce used for every handshake field.
    ///
    /// Each handshake AEAD key is used exactly once, so a constant nonce is
    /// safe there; transport data instead uses its counter.
    public static let zeroNonce = [UInt8](repeating: 0, count: 12)
}

/// A parsed handshake initiation message (type 1, 148 bytes).
public struct WireGuardInitiation: Sendable, Equatable {

    /// The sender's index, chosen randomly by the initiator.
    public var senderIndex: UInt32

    /// The initiator's ephemeral public key.
    public var ephemeral: Data

    /// The initiator's static public key, encrypted and authenticated.
    public var encryptedStatic: Data

    /// The current TAI64N timestamp, encrypted and authenticated.
    public var encryptedTimestamp: Data

    /// `MAC(HASH("mac1----" ‖ responder public key), message up to mac1)`.
    public var mac1: Data

    /// `MAC(cookie, message up to mac2)`, or sixteen zero bytes without a cookie.
    public var mac2: Data

    /// Parses a message.
    ///
    /// - Parameter data: At least 148 bytes.
    /// - Returns: The parsed message, or `nil` when the size or type is wrong.
    public static func parse(_ data: Data) -> WireGuardInitiation? {
        let bytes = [UInt8](data)
        guard bytes.count == WireGuardWireFormat.initiationSize else { return nil }
        guard LittleEndian.readUInt32(bytes, at: 0) == WireGuardMessageType.handshakeInitiation.rawValue else {
            return nil
        }
        return WireGuardInitiation(
            senderIndex: LittleEndian.readUInt32(bytes, at: 4) ?? 0,
            ephemeral: Data(bytes[8 ..< 40]),
            encryptedStatic: Data(bytes[40 ..< 88]),
            encryptedTimestamp: Data(bytes[88 ..< 116]),
            mac1: Data(bytes[116 ..< 132]),
            mac2: Data(bytes[132 ..< 148])
        )
    }

    /// Serialises the message.
    ///
    /// - Returns: Exactly 148 bytes.
    public func serialized() -> Data {
        var bytes = [UInt8]()
        bytes.reserveCapacity(WireGuardWireFormat.initiationSize)
        LittleEndian.append(WireGuardMessageType.handshakeInitiation.rawValue, to: &bytes)
        LittleEndian.append(senderIndex, to: &bytes)
        bytes.append(contentsOf: ephemeral)
        bytes.append(contentsOf: encryptedStatic)
        bytes.append(contentsOf: encryptedTimestamp)
        bytes.append(contentsOf: mac1)
        bytes.append(contentsOf: mac2)
        return Data(bytes)
    }

    /// The bytes `mac1` authenticates: everything before `mac1`.
    public static let mac1CoveredRange = 0 ..< WireGuardWireFormat.initiationMAC1Offset

    /// The bytes `mac2` authenticates: everything before `mac2`.
    public static let mac2CoveredRange = 0 ..< WireGuardWireFormat.initiationMAC2Offset
}

/// A parsed handshake response message (type 2, 92 bytes).
public struct WireGuardResponse: Sendable, Equatable {

    /// The responder's index, chosen randomly by the responder.
    public var senderIndex: UInt32

    /// The initiator's index, copied from the initiation.
    public var receiverIndex: UInt32

    /// The responder's ephemeral public key.
    public var ephemeral: Data

    /// The encrypted and authenticated empty field.
    public var encryptedEmpty: Data

    /// `MAC(HASH("mac1----" ‖ responder public key), message up to mac1)`.
    public var mac1: Data

    /// `MAC(cookie, message up to mac2)`, or sixteen zero bytes without a cookie.
    public var mac2: Data

    /// Parses a message.
    ///
    /// - Parameter data: At least 92 bytes.
    /// - Returns: The parsed message, or `nil` when the size or type is wrong.
    public static func parse(_ data: Data) -> WireGuardResponse? {
        let bytes = [UInt8](data)
        guard bytes.count == WireGuardWireFormat.responseSize else { return nil }
        guard LittleEndian.readUInt32(bytes, at: 0) == WireGuardMessageType.handshakeResponse.rawValue else {
            return nil
        }
        return WireGuardResponse(
            senderIndex: LittleEndian.readUInt32(bytes, at: 4) ?? 0,
            receiverIndex: LittleEndian.readUInt32(bytes, at: 8) ?? 0,
            ephemeral: Data(bytes[12 ..< 44]),
            encryptedEmpty: Data(bytes[44 ..< 60]),
            mac1: Data(bytes[60 ..< 76]),
            mac2: Data(bytes[76 ..< 92])
        )
    }

    /// Serialises the message.
    ///
    /// - Returns: Exactly 92 bytes.
    public func serialized() -> Data {
        var bytes = [UInt8]()
        bytes.reserveCapacity(WireGuardWireFormat.responseSize)
        LittleEndian.append(WireGuardMessageType.handshakeResponse.rawValue, to: &bytes)
        LittleEndian.append(senderIndex, to: &bytes)
        LittleEndian.append(receiverIndex, to: &bytes)
        bytes.append(contentsOf: ephemeral)
        bytes.append(contentsOf: encryptedEmpty)
        bytes.append(contentsOf: mac1)
        bytes.append(contentsOf: mac2)
        return Data(bytes)
    }

    /// The bytes `mac1` authenticates: everything before `mac1`.
    public static let mac1CoveredRange = 0 ..< WireGuardWireFormat.responseMAC1Offset

    /// The bytes `mac2` authenticates: everything before `mac2`.
    public static let mac2CoveredRange = 0 ..< WireGuardWireFormat.responseMAC2Offset
}

/// A parsed cookie reply message (type 3, 64 bytes).
public struct WireGuardCookieReply: Sendable, Equatable {

    /// The index of the message that prompted this reply.
    public var receiverIndex: UInt32

    /// The random nonce for the XChaCha20-Poly1305 encryption.
    public var nonce: Data

    /// The encrypted cookie.
    public var encryptedCookie: Data

    /// Parses a message.
    ///
    /// - Parameter data: At least 64 bytes.
    /// - Returns: The parsed message, or `nil` when the size or type is wrong.
    public static func parse(_ data: Data) -> WireGuardCookieReply? {
        let bytes = [UInt8](data)
        guard bytes.count == WireGuardWireFormat.cookieReplySize else { return nil }
        guard LittleEndian.readUInt32(bytes, at: 0) == WireGuardMessageType.cookieReply.rawValue else {
            return nil
        }
        return WireGuardCookieReply(
            receiverIndex: LittleEndian.readUInt32(bytes, at: 4) ?? 0,
            nonce: Data(bytes[8 ..< 32]),
            encryptedCookie: Data(bytes[32 ..< 64])
        )
    }

    /// Serialises the message.
    ///
    /// - Returns: Exactly 64 bytes.
    public func serialized() -> Data {
        var bytes = [UInt8]()
        bytes.reserveCapacity(WireGuardWireFormat.cookieReplySize)
        LittleEndian.append(WireGuardMessageType.cookieReply.rawValue, to: &bytes)
        LittleEndian.append(receiverIndex, to: &bytes)
        bytes.append(contentsOf: nonce)
        bytes.append(contentsOf: encryptedCookie)
        return Data(bytes)
    }
}

/// A parsed transport data message (type 4).
///
/// There is no length field: the AEAD tag decides whether the message is
/// genuine, and the encapsulated IP packet carries its own length.
public struct WireGuardTransportData: Sendable, Equatable {

    /// Our index, identifying which session should decrypt this.
    public var receiverIndex: UInt32

    /// The nonce: a strictly increasing per-session counter.
    public var counter: UInt64

    /// The encrypted IP packet, including the AEAD tag.
    public var encryptedPacket: Data

    /// Parses a message.
    ///
    /// - Parameter data: At least 32 bytes for a keepalive.
    /// - Returns: The parsed message, or `nil` when the size or type is wrong.
    public static func parse(_ data: Data) -> WireGuardTransportData? {
        let bytes = [UInt8](data)
        guard bytes.count >= WireGuardWireFormat.keepaliveSize else { return nil }
        guard LittleEndian.readUInt32(bytes, at: 0) == WireGuardMessageType.transportData.rawValue else {
            return nil
        }
        guard let receiver = LittleEndian.readUInt32(bytes, at: WireGuardWireFormat.transportReceiverOffset),
              let counter = LittleEndian.readUInt64(bytes, at: WireGuardWireFormat.transportCounterOffset) else {
            return nil
        }
        return WireGuardTransportData(
            receiverIndex: receiver,
            counter: counter,
            encryptedPacket: Data(bytes[WireGuardWireFormat.transportContentOffset...])
        )
    }

    /// Serialises the message.
    ///
    /// - Returns: The header followed by the encrypted packet.
    public func serialized() -> Data {
        var bytes = [UInt8]()
        bytes.reserveCapacity(WireGuardWireFormat.transportHeaderSize + encryptedPacket.count)
        LittleEndian.append(WireGuardMessageType.transportData.rawValue, to: &bytes)
        LittleEndian.append(receiverIndex, to: &bytes)
        LittleEndian.append(counter, to: &bytes)
        bytes.append(contentsOf: encryptedPacket)
        return Data(bytes)
    }

    /// Whether this message carries no payload, i.e. it is a keepalive.
    public var isKeepalive: Bool {
        encryptedPacket.count == WireGuardWireFormat.tagSize
    }
}

/// The message type of a datagram, if it is a WireGuard message at all.
///
/// - Parameter data: A datagram received from the tunnel socket.
/// - Returns: The type, or `nil` when the first four bytes are not a known
///   type or the reserved bytes are not zero.
public func wireGuardMessageType(of data: Data) -> WireGuardMessageType? {
    let bytes = [UInt8](data)
    guard bytes.count >= WireGuardWireFormat.typeFieldSize else { return nil }
    guard bytes[1] == 0, bytes[2] == 0, bytes[3] == 0 else { return nil }
    guard let raw = LittleEndian.readUInt32(bytes, at: 0) else { return nil }
    return WireGuardMessageType(rawValue: raw)
}

/// Little endian integer access for the WireGuard wire formats.
///
/// Every read is bounds checked and returns `nil` rather than trapping.
enum LittleEndian {

    /// Reads a 32 bit little endian integer.
    ///
    /// - Parameters:
    ///   - bytes: The buffer.
    ///   - offset: Where the integer starts.
    /// - Returns: The value, or `nil` when the buffer is too short.
    static func readUInt32(_ bytes: [UInt8], at offset: Int) -> UInt32? {
        guard offset >= 0, offset + 4 <= bytes.count else { return nil }
        return UInt32(bytes[offset])
            | UInt32(bytes[offset + 1]) << 8
            | UInt32(bytes[offset + 2]) << 16
            | UInt32(bytes[offset + 3]) << 24
    }

    /// Reads a 64 bit little endian integer.
    ///
    /// - Parameters:
    ///   - bytes: The buffer.
    ///   - offset: Where the integer starts.
    /// - Returns: The value, or `nil` when the buffer is too short.
    static func readUInt64(_ bytes: [UInt8], at offset: Int) -> UInt64? {
        guard offset >= 0, offset + 8 <= bytes.count else { return nil }
        var value: UInt64 = 0
        for index in 0 ..< 8 {
            value |= UInt64(bytes[offset + index]) << (8 * index)
        }
        return value
    }

    /// Appends a 32 bit little endian integer.
    ///
    /// - Parameters:
    ///   - value: The value to append.
    ///   - bytes: The buffer to append to.
    static func append(_ value: UInt32, to bytes: inout [UInt8]) {
        bytes.append(UInt8(truncatingIfNeeded: value))
        bytes.append(UInt8(truncatingIfNeeded: value >> 8))
        bytes.append(UInt8(truncatingIfNeeded: value >> 16))
        bytes.append(UInt8(truncatingIfNeeded: value >> 24))
    }

    /// Appends a 64 bit little endian integer.
    ///
    /// - Parameters:
    ///   - value: The value to append.
    ///   - bytes: The buffer to append to.
    static func append(_ value: UInt64, to bytes: inout [UInt8]) {
        for index in 0 ..< 8 {
            bytes.append(UInt8(truncatingIfNeeded: value >> (8 * index)))
        }
    }

    /// Builds the twelve byte AEAD nonce for a transport data message.
    ///
    /// The counter occupies the last eight bytes; the first four stay zero. The
    /// whitepaper (section 5.4.6) defines the counter as the nonce.
    ///
    /// - Parameter counter: The message counter.
    /// - Returns: Twelve bytes.
    static func transportNonce(counter: UInt64) -> [UInt8] {
        [0, 0, 0, 0] + (0 ..< 8).map { UInt8(truncatingIfNeeded: counter >> (8 * $0)) }
    }
}
