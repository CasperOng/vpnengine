//
//  WireGuardKey.swift
//  VPNEngine
//
//  A 32 byte WireGuard key in the standard textual form.
//
//  WireGuard keys are exchanged as 44 character crockford-ish base64 strings:
//  32 bytes encoded with the alphabet `A-Za-z0-9+/` and padded with `=` (the
//  whitepaper, section 5.1 calls these "the base64 encoding of the key").
//

import Foundation

/// A 32 byte WireGuard key (either a private scalar or a public u-coordinate).
public struct WireGuardKey: Hashable, Sendable, Codable, CustomStringConvertible {

    /// Key size in bytes.
    public static let size = 32

    /// The raw key material.
    public let rawValue: Data

    /// Length of the textual form: 44 characters including the trailing `=`.
    public static let base64Length = 44

    // MARK: - Creation

    /// Wraps raw key material.
    ///
    /// - Parameter rawValue: Exactly 32 bytes.
    /// - Returns: `nil` when the input is not 32 bytes.
    public init?(rawValue: Data) {
        guard rawValue.count == WireGuardKey.size else { return nil }
        self.rawValue = rawValue
    }

    /// Parses a key from its standard base64 form.
    ///
    /// - Parameter base64: A 44 character base64 string, with or without
    ///   surrounding whitespace.
    /// - Returns: `nil` when the text is not a valid 32 byte key.
    public init?(base64: String) {
        let trimmed = base64.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count == WireGuardKey.base64Length else { return nil }
        guard let decoded = Data(base64Encoded: trimmed, options: []) else { return nil }
        guard decoded.count == WireGuardKey.size else { return nil }
        self.rawValue = decoded
    }

    /// Wraps key material that is already known to be valid.
    ///
    /// - Parameter rawValue: Exactly 32 bytes.
    private init(unchecked rawValue: Data) {
        self.rawValue = rawValue
    }

    /// Generates a new private key.
    ///
    /// The scalar carries the standard X25519 clamping bits, matching the keys
    /// `wg genkey` produces.
    ///
    /// - Returns: A fresh private key.
    public static func generatePrivateKey() -> WireGuardKey {
        // `X25519.generatePrivateKey()` always returns exactly 32 bytes, which
        // is why the private initialiser above can be used unconditionally.
        WireGuardKey(unchecked: Data(X25519.generatePrivateKey()))
    }

    /// Derives the public key for this private key.
    ///
    /// - Returns: The public key, or `nil` when the key material cannot be used
    ///   as a scalar.
    public var derivedPublicKey: WireGuardKey? {
        guard let publicBytes = try? X25519.publicKey(for: [UInt8](rawValue)) else { return nil }
        return WireGuardKey(rawValue: Data(publicBytes))
    }

    // MARK: - Textual form

    /// The standard 44 character base64 form.
    public var base64String: String {
        rawValue.base64EncodedString()
    }

    /// The base64 form, so that logging a key produces something usable in a
    /// configuration file.
    ///
    /// Note that this is also true for private keys; do not log those.
    public var description: String {
        base64String
    }

    // MARK: - Codable

    /// Encodes the key as its base64 string, matching WireGuard configuration
    /// files.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(base64String)
    }

    /// Decodes a key from its base64 string.
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let text = try container.decode(String.self)
        guard let value = WireGuardKey(base64: text) else {
            throw DecodingError.dataCorruptedError(in: container,
                                                   debugDescription: "\"\(text)\" is not a 32 byte WireGuard key")
        }
        self = value
    }
}
