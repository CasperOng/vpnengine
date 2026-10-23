import Foundation

/// Every failure mode of the OpenVPN engine.
///
/// The engine never crashes on malformed network input: every parser and codec
/// in `Sources/VPNEngine/OpenVPN` validates lengths before touching a byte and
/// reports failures through this type. Errors carry enough context to be logged
/// without a debugger (which byte field failed and what was expected).
public enum OVPNError: Error, Equatable, Sendable {

    // MARK: - Configuration

    /// A line of `.ovpn` text could not be understood.
    case configSyntax(line: Int, detail: String)

    /// A directive that the engine requires for the requested mode is absent.
    case missingRequiredDirective(String)

    /// An `-----BEGIN OpenVPN Static key V1-----` block was malformed.
    case invalidStaticKey(String)

    // MARK: - Capability

    /// The cipher is not one this engine implements.
    case unsupportedCipher(String)

    /// The digest (HMAC) is not one this engine implements.
    case unsupportedDigest(String)

    /// The configuration asks for a feature that is intentionally not
    /// implemented (compression, proxies, scripts, tap, ...).
    case unsupportedFeature(String)

    // MARK: - Data channel

    /// No key material has been installed in the codec yet.
    case keyNotInstalled

    /// A datagram was shorter than the fixed prefix the layout requires.
    case packetTooShort(field: String, need: Int, have: Int)

    /// Structurally invalid packet (bad padding, bad opcode, truncated field).
    case malformedPacket(String)

    /// An HMAC or AEAD tag did not verify.
    case authenticationFailed

    /// The cipher rejected the ciphertext (e.g. CBC padding).
    case decryptionFailed

    /// The packet id was already seen (or is older than the replay window).
    case replayDetected(id: UInt32)

    /// The 32-bit packet-id counter wrapped.
    case packetIDRollover

    // MARK: - Control channel

    /// A control packet did not match the documented layout.
    case malformedControlPacket(String)

    /// Opcode byte carried an opcode this engine does not know.
    case unknownOpcode(UInt8)

    /// No ACK arrived before the hard timeout expired.
    case controlChannelTimeout(seconds: Int)

    // MARK: - Session

    /// A method was called in a state where it makes no sense.
    case invalidState(String)

    /// The tunnel is not up, so data packets cannot be routed.
    case notConnected

    /// The datagram transport itself failed.
    case transportFailure(String)
}

extension OVPNError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case let .configSyntax(line, detail):
            return "OpenVPN config syntax error on line \(line): \(detail)"
        case let .missingRequiredDirective(name):
            return "OpenVPN config is missing a required directive: \(name)"
        case let .invalidStaticKey(detail):
            return "Invalid OpenVPN static key: \(detail)"
        case let .unsupportedCipher(name):
            return "Unsupported OpenVPN cipher: \(name)"
        case let .unsupportedDigest(name):
            return "Unsupported OpenVPN digest: \(name)"
        case let .unsupportedFeature(name):
            return "Unsupported OpenVPN feature: \(name)"
        case .keyNotInstalled:
            return "No OpenVPN key material has been installed"
        case let .packetTooShort(field, need, have):
            return "OpenVPN packet too short for \(field): need \(need) bytes, have \(have)"
        case let .malformedPacket(detail):
            return "Malformed OpenVPN packet: \(detail)"
        case .authenticationFailed:
            return "OpenVPN packet authentication failed"
        case .decryptionFailed:
            return "OpenVPN packet decryption failed"
        case let .replayDetected(id):
            return "OpenVPN replay detected for packet id \(id)"
        case .packetIDRollover:
            return "OpenVPN packet id counter rolled over"
        case let .malformedControlPacket(detail):
            return "Malformed OpenVPN control packet: \(detail)"
        case let .unknownOpcode(op):
            return "Unknown OpenVPN opcode \(op)"
        case let .controlChannelTimeout(seconds):
            return "OpenVPN control channel timed out after \(seconds)s"
        case let .invalidState(detail):
            return "OpenVPN session in invalid state: \(detail)"
        case .notConnected:
            return "OpenVPN tunnel is not connected"
        case let .transportFailure(detail):
            return "OpenVPN transport failure: \(detail)"
        }
    }
}
