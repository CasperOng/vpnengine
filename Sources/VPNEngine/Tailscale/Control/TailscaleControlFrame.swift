//
//  TailscaleControlFrame.swift
//  VPNEngine
//
//  The message framing of the Tailscale 2021 control protocol, above the Noise
//  layer (`control/controlbase/messages.go` in the Tailscale client).
//
//  Every message on the wire is
//
//      +--------+------------------+---------------------+
//      |  type  |      length      |        payload      |
//      | 1 byte | 2 bytes, big-end |  `length` bytes     |
//      +--------+------------------+---------------------+
//
//  with the exception of the handshake initiation, which carries a two byte
//  protocol version in front of the type:
//
//      +---------+--------+------------------+---------------------+
//      | version |  type  |      length      |        payload      |
//      | 2 bytes | 1 byte | 2 bytes, big-end |  `length` bytes     |
//      +---------+--------+------------------+---------------------+
//
//  This is *not* the five byte header of DERP, and it is not WireGuard's
//  framing either; see ``TailscaleControlFrameType`` for the type byte values
//  and where each one came from.
//
//  References:
//   * `control/controlbase/messages.go` and `control/controlbase/conn.go` in
//     https://github.com/tailscale/tailscale (BSD-3-Clause)
//   * Headscale's server half: `hscontrol/noise.go` in
//     https://github.com/juanfont/headscale (BSD-3-Clause)
//

import Foundation

/// The message type byte that opens every control protocol frame.
///
/// The four values below are Tailscale's own, taken from
/// `control/controlbase/messages.go`:
///
/// ```go
/// const (
///     msgTypeInitiation = 1
///     msgTypeResponse   = 2
///     msgTypeError      = 3
///     msgTypeRecord     = 4
///     headerLen         = 3
/// )
/// ```
///
/// Note that the initiation is the odd one out: it is the only frame that
/// carries the protocol version, and the only one whose header is five bytes
/// (`initiationHeaderLen = 5`).
///
/// ``ping`` and ``pong`` are **not** part of Tailscale's control protocol, and
/// are not part of Headscale's either. They are defined here so the framing
/// layer can express a keepalive whose payload is echoed back verbatim, which
/// is the behaviour DERP's `FramePing`/`FramePong` (`0x12`/`0x13`, an eight
/// byte payload) has, and which the in-repo test server exercises. No real
/// control server sends them, and this engine never sends one unless a peer
/// sends one first.
public enum TailscaleControlFrameType: UInt8, Sendable, CaseIterable {

    /// The Noise handshake initiation: a five byte header, then 96 bytes.
    case initiation = 0x01

    /// The Noise handshake response: a three byte header, then 48 bytes.
    case response = 0x02

    /// An unauthenticated, cleartext, human readable error from the server.
    ///
    /// Tailscale's comment on this value is worth repeating: "Errors reported
    /// in this message type must be treated as public hints only. They are not
    /// encrypted or authenticated, and so can be seen and tampered with on the
    /// wire."
    case error = 0x03

    /// An encrypted session record.
    case record = 0x04

    /// A keepalive whose payload must be echoed back. Engine-local extension;
    /// see the type's documentation.
    case ping = 0x05

    /// The echo of a ``ping``. Engine-local extension; see the type's
    /// documentation.
    case pong = 0x06
}

/// One framed control protocol message, with the payload still encrypted where
/// that applies.
///
/// A ``record`` payload is ciphertext: the plaintext is sealed with the
/// session's sending ``NoiseCipherState`` and the 16 byte tag is included in
/// the frame's length field, so the length is always a multiple of nothing in
/// particular and is at least 16.
public enum TailscaleControlFrame: Sendable, Equatable {

    /// A session record: a JSON `tailcfg` message, encrypted.
    case record(Data)

    /// A keepalive to be echoed back as a ``pong``.
    case ping(Data)

    /// The echo of a ``ping``.
    case pong(Data)

    /// The payload, whatever the case.
    public var payload: Data {
        switch self {
        case .record(let payload), .ping(let payload), .pong(let payload):
            return payload
        }
    }

    /// The type byte this frame serialises with.
    public var type: TailscaleControlFrameType {
        switch self {
        case .record: return .record
        case .ping: return .ping
        case .pong: return .pong
        }
    }
}

/// Encodes and decodes control protocol frames.
///
/// The codec is a pure framing layer: it neither encrypts nor decrypts, so it
/// can be tested on its own and used for the cleartext handshake frames as well
/// as the encrypted records.
public enum TailscaleControlFrameCodec {

    /// Size of the header on every frame except the handshake initiation.
    public static let headerSize = 3

    /// Size of the handshake initiation's header.
    public static let initiationHeaderSize = 5

    /// The largest frame the protocol allows, header included.
    ///
    /// `controlbase`'s `maxMessageSize = 4096`; a peer that sends more is
    /// desynchronised or hostile and must not be buffered for.
    public static let maxFrameSize = 4096

    /// The largest ciphertext a record frame can carry.
    public static let maxRecordSize = maxFrameSize - headerSize

    /// The largest plaintext a record frame can carry.
    public static let maxRecordPayloadSize = maxRecordSize - NoiseCipherState.tagSize

    /// The length field is two bytes, so this is the absolute ceiling.
    public static let maxEncodablePayloadSize = Int(UInt16.max)

    /// Serialises a frame.
    ///
    /// - Parameter frame: The frame to write.
    /// - Throws: ``TailscaleControlError/frameTooLarge(_:)`` when the payload
    ///   does not fit the protocol's two byte length field or its 4096 byte
    ///   frame budget.
    /// - Returns: The header followed by the payload.
    public static func encode(_ frame: TailscaleControlFrame) throws -> Data {
        let payload = [UInt8](frame.payload)
        guard payload.count <= maxEncodablePayloadSize else {
            throw TailscaleControlError.frameTooLarge(payload.count)
        }
        guard payload.count + headerSize <= maxFrameSize else {
            throw TailscaleControlError.frameTooLarge(payload.count)
        }

        var bytes = [UInt8]()
        bytes.reserveCapacity(headerSize + payload.count)
        bytes.append(frame.type.rawValue)
        bytes.append(UInt8(truncatingIfNeeded: payload.count >> 8))
        bytes.append(UInt8(truncatingIfNeeded: payload.count))
        bytes.append(contentsOf: payload)
        return Data(bytes)
    }

    /// Decodes the first frame in a buffer, consuming it.
    ///
    /// The buffer is left untouched when the frame is incomplete, so a caller
    /// can keep reading and call again; that is the only way a frame that
    /// arrives in two TCP segments is handled correctly.
    ///
    /// - Parameter buffer: The bytes read so far. On success the first frame is
    ///   removed; on failure or on `nil` it is unchanged.
    /// - Throws: ``TailscaleControlError/malformedFrame(_:)`` for an unknown
    ///   type byte or a frame that is larger than ``maxFrameSize``.
    /// - Returns: The frame, or `nil` when more bytes are needed.
    public static func decode(_ buffer: inout Data) throws -> TailscaleControlFrame? {
        guard buffer.count >= headerSize else { return nil }

        let bytes = [UInt8](buffer.prefix(headerSize))
        guard let type = TailscaleControlFrameType(rawValue: bytes[0]) else {
            throw TailscaleControlError.unexpectedFrameType(bytes[0])
        }
        let length = Int(bytes[1]) << 8 | Int(bytes[2])
        guard length + headerSize <= maxFrameSize else {
            throw TailscaleControlError.frameTooLarge(length)
        }
        guard buffer.count >= headerSize + length else { return nil }

        let payload = Data(buffer.dropFirst(headerSize).prefix(length))
        buffer.removeFirst(headerSize + length)

        switch type {
        case .record: return .record(payload)
        case .ping: return .ping(payload)
        case .pong: return .pong(payload)
        case .initiation, .response, .error:
            // These only ever appear during the handshake, which reads them
            // through ``TS2021HandshakeMessage`` rather than through this
            // codec. Seeing one here means the peer is confused.
            throw TailscaleControlError.unexpectedFrameType(type.rawValue)
        }
    }

    /// Reads the type byte and length of a frame without consuming it.
    ///
    /// - Parameter buffer: The bytes read so far.
    /// - Returns: The header, or `nil` when fewer than ``headerSize`` bytes are
    ///   buffered.
    public static func peekHeader(_ buffer: Data) -> (type: TailscaleControlFrameType, length: Int)? {
        guard buffer.count >= headerSize else { return nil }
        let bytes = [UInt8](buffer.prefix(headerSize))
        guard let type = TailscaleControlFrameType(rawValue: bytes[0]) else { return nil }
        return (type, Int(bytes[1]) << 8 | Int(bytes[2]))
    }
}
