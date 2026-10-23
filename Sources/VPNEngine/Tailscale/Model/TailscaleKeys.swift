//
//  TailscaleKeys.swift
//  VPNEngine
//
//  The keys a Tailscale node owns, and the textual forms `tailcfg` gives them.
//
//  Tailscale has three live keys, each with a different job, and confusingly
//  they are all 32 byte Curve25519 values on the wire. What differs is what
//  signs them and how long they live:
//
//    * **machine key** (`key.MachinePrivate`, `tailcfg.RegisterRequest` carries
//      no field for it: it is implicit in the Noise handshake) identifies the
//      *device*. It survives node-key rotation, so the coordination server can
//      recognise a re-registering node as the same machine. Tailscale stores it
//      for the lifetime of the install.
//      Source: `types/key/machine.go` — `NewMachine` clamps a 32 byte scalar and
//      `Public` is `curve25519.ScalarBaseMult`. It is a Curve25519 key, *not*
//      Ed25519 (an easy thing to get wrong; the public prefix is `mkey:`).
//
//    * **node key** (`key.NodePrivate`, `tailcfg.Node.Key`) identifies the node
//      *within the tailnet* and is rotated on expiry. Its public half is what
//      peers put in their WireGuard `AllowedIPs` lookup table, and its private
//      half *is* the WireGuard private key: tailscale runs ordinary WireGuard
//      with the node key as the static key.
//      Source: `types/key/node.go` — `NewNode` clamps (for DERP, not for
//      WireGuard) and `Public` is `curve25519.ScalarBaseMult`.
//
//    * **disco key** (`key.DiscoPrivate`, `tailcfg.Node.DiscoKey`) is used by
//      the disco protocol for endpoint discovery and NAT traversal. This engine
//      does not implement disco yet, but the key must exist and be sent,
//      because the coordination server stores it and hands it to peers, and
//      because a peer will refuse a disco message that is not signed by the key
//      it was told about.
//      Source: `types/key/disco.go` — same clamped Curve25519 construction.
//
//  **Network lock key: deliberately omitted.** `tailcfg.RegisterRequest.NLKey`
//  (`key.TLPublic`, prefix `nlpub:`) only matters when tailnet lock is enabled
//  for the tailnet; a locked tailnet requires every node to sign its own node
//  key with a tailnet-lock key and to carry a `NodeKeySignature`, and a client
//  that has no such key cannot join one. Implementing lock would mean
//  implementing the whole AUM/authority chain, which is out of scope here, so
//  the session sends the zero `nlpub:` key exactly as tailscaled does when lock
//  is not in use, and never stores a lock key.
//
//  Textual forms. `tailcfg` serialises these keys through Go's
//  `encoding.TextMarshaler` (there is no `MarshalJSON` on `key.NodePublic`), so
//  `encoding/json` emits the *prefixed* form:
//
//      Node.Key      -> "nodekey:<64 lowercase hex chars>"
//      Node.Machine  -> "mkey:<64 hex chars>"
//      Node.DiscoKey -> "discokey:<64 hex chars>"
//
//  and the matching `UnmarshalText` (`types/key/util.go`, `parseHex`) *requires*
//  the prefix: a bare hex string fails to decode with "key hex string doesn't
//  have expected type prefix". Private keys marshal as `privkey:<hex>`
//  (`types/key/node.go`, `machine.go`), which is a trap rather than a feature,
//  and this engine never emits a private key in any textual form.
//
//  Where bare hex is used: `key.NodePublic`'s *binary* form is `np` + 32 raw
//  bytes (`MarshalBinary`), which is not hex at all; bare hex shows up in a few
//  local places (CLI arguments, `ipn/localapi` accepting a `nodekey:` argument,
//  tailnet-lock deeplinks). To be a good citizen this file *decodes* both forms
//  — prefixed, as the control protocol sends, and bare hex, as a human or a
//  log line might produce — and always *encodes* the prefixed form that the
//  protocol requires.
//

import Foundation

#if canImport(CryptoKit)
import CryptoKit
#endif

/// Which of a node's keys a value is.
///
/// The role is carried on the value so that a disco key can never be mistaken
/// for a node key: they are both 32 byte Curve25519 keys, and the compiler is
/// the only thing that can tell them apart.
public enum TailscaleKeyRole: String, Sendable, Codable, CaseIterable, Hashable {

    /// The device key (`key.MachinePrivate`). Prefixes: `mkey:`, `privkey:`.
    case machine

    /// The node key (`key.NodePrivate`), which is also the WireGuard key.
    /// Prefix: `nodekey:`.
    case node

    /// The disco key (`key.DiscoPrivate`). Prefix: `discokey:`.
    case disco

    /// The hex prefix `tailcfg` writes for this role's public key.
    ///
    /// Source: `types/key/node.go` (`nodePublicHexPrefix`), `machine.go`
    /// (`machinePublicHexPrefix`), `disco.go` (`discoPublicHexPrefix`).
    public var publicTextPrefix: String {
        switch self {
        case .machine: return "mkey:"
        case .node: return "nodekey:"
        case .disco: return "discokey:"
        }
    }

    /// The hex prefix Go writes for a private key of this role.
    ///
    /// All three roles use `privkey:` (`types/key/machine.go`,
    /// `types/key/node.go`). This engine only ever uses the value to *reject*
    /// private text that arrives where a public key is expected.
    public var privateTextPrefix: String { "privkey:" }

    /// The two-letter binary prefix Go uses in `MarshalBinary`
    /// (`np` for node keys, `mp` for machine keys, `dp` for disco keys).
    ///
    /// Only used to keep our own storage of public keys self-describing.
    public var binaryPrefix: String {
        switch self {
        case .machine: return "mp"
        case .node: return "np"
        case .disco: return "dp"
        }
    }
}

/// Errors from key parsing, generation or derivation.
public enum TailscaleKeyError: Error, Equatable, Sendable {

    /// The key material was not the expected number of bytes.
    ///
    /// - Parameters:
    ///   - expected: The required size in bytes.
    ///   - actual: The size that was supplied.
    case invalidKeySize(expected: Int, actual: Int)

    /// A textual key did not carry the prefix its role requires.
    ///
    /// - Parameter prefix: The prefix that was expected.
    case missingPrefix(String)

    /// A textual key carried the `privkey:` prefix where a public key was
    /// expected. Parsing is refused so that a private key can never be logged
    /// or sent by accident.
    case privateKeyWherePublicKeyExpected

    /// A textual key contained characters that are not hexadecimal digits, or
    /// had the wrong length.
    case malformedHex

    /// The platform has no X25519 implementation.
    ///
    /// - Parameter reason: A human readable explanation.
    case unsupportedPlatform(String)

    /// A public key could not be derived from the private key material.
    case keyDerivationFailed
}

// MARK: - Public keys

/// A 32 byte Tailscale *public* key with the role it belongs to.
///
/// Public keys are safe to log, and ``description`` is the prefixed hex form
/// that the control protocol uses.
public struct TailscalePublicKey: Hashable, Sendable, CustomStringConvertible, Codable {

    /// The key size every Tailscale key shares, in bytes.
    public static let size = 32

    /// Which key this is.
    public let role: TailscaleKeyRole

    /// The 32 raw bytes.
    public let rawValue: Data

    // MARK: Creation

    /// Wraps key material that is already known to be valid.
    ///
    /// - Parameters:
    ///   - role: Which key this is.
    ///   - rawValue: Exactly 32 bytes.
    /// - Returns: `nil` when the input is not 32 bytes.
    public init?(role: TailscaleKeyRole, rawValue: Data) {
        guard rawValue.count == TailscalePublicKey.size else { return nil }
        self.role = role
        self.rawValue = rawValue
    }

    /// Parses a public key from the text forms `tailcfg` and its tools produce.
    ///
    /// Both `<prefix><hex>` (what the control protocol sends) and bare hex are
    /// accepted, case insensitively. A `privkey:` string is rejected rather
    /// than silently reinterpreted, because that is how a private key would
    /// otherwise end up in a log.
    ///
    /// - Parameters:
    ///   - role: Which key this is.
    ///   - text: The textual key.
    /// - Returns: `nil` when the text is not a valid key of that role.
    public init?(role: TailscaleKeyRole, text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix(TailscaleKeyRole.machine.privateTextPrefix) {
            return nil
        }
        let hex: String
        if let colon = trimmed.firstIndex(of: ":") {
            let prefix = String(trimmed[trimmed.startIndex ... colon])
            guard prefix == role.publicTextPrefix else { return nil }
            hex = String(trimmed[trimmed.index(after: colon)...])
        } else {
            hex = trimmed
        }
        guard let bytes = TailscalePublicKey.hexToBytes(hex), bytes.count == TailscalePublicKey.size else {
            return nil
        }
        self.role = role
        self.rawValue = Data(bytes)
    }

    // MARK: Textual form

    /// The prefixed hex form the control protocol uses, for example
    /// `nodekey:1c2d…`.
    public var text: String {
        role.publicTextPrefix + bareHex
    }

    /// The 64 character lowercase hex form, with no prefix.
    ///
    /// This is *not* what `tailcfg` puts on the wire; it is convenient for
    /// storage keys, log lines and comparisons.
    public var bareHex: String {
        TailscalePublicKey.bytesToHex([UInt8](rawValue))
    }

    /// The prefixed hex form, so that logging a public key produces the same
    /// string the control server would.
    public var description: String { text }

    /// Whether every byte is zero, which is how `tailcfg` spells "unset" for
    /// the fields that have no `omitempty` tag (for example
    /// `RegisterRequest.OldNodeKey`).
    public var isZero: Bool {
        rawValue.allSatisfy { $0 == 0 }
    }

    // MARK: Conversion

    /// The same bytes as a WireGuard key, for node keys.
    ///
    /// The node key *is* the WireGuard key in Tailscale: `wgengine` feeds
    /// `NodePrivate` straight to the WireGuard device, and peers install the
    /// public half in `AllowedIPs`.
    public var wireGuardKey: WireGuardKey? {
        WireGuardKey(rawValue: rawValue)
    }

    // MARK: Codable

    /// Decodes the prefixed hex form, falling back to bare hex.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when the text is not a key of this role.
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let text = try container.decode(String.self)

        // `role` is a stored property, so it cannot be read before `self` is
        // initialised — but it does not have to be guessed either: the wire text
        // carries a role prefix (`mkey:`, `nodekey:`, `discokey:`). Derive the role
        // from that, and only fall back to the node key for bare hex, which is the
        // form Apple's own tools use when they omit it.
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let inferred = TailscaleKeyRole.allCases.first {
            trimmed.hasPrefix($0.publicTextPrefix)
        } ?? .node

        guard let parsed = TailscalePublicKey(role: inferred, text: trimmed) else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "\"\(text)\" is not a 32 byte public key")
        }
        self = parsed
    }

    /// Encodes the prefixed hex form.
    ///
    /// - Parameter encoder: The encoder to write to.
    /// - Throws: A coding error when the key is malformed.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(text)
    }

    // MARK: Hex helpers

    /// Decodes hex digits, accepting either case.
    ///
    /// - Parameter text: An even number of hex digits.
    /// - Returns: The bytes, or `nil` when the text is not hex.
    static func hexToBytes(_ text: String) -> [UInt8]? {
        guard text.count % 2 == 0, !text.isEmpty else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(text.count / 2)
        var index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            guard let byte = UInt8(text[index ..< next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        return bytes
    }

    /// Encodes bytes as lowercase hex, matching Go's `hex.EncodeToString`.
    ///
    /// - Parameter bytes: The bytes to encode.
    /// - Returns: Two hex digits per byte.
    static func bytesToHex(_ bytes: [UInt8]) -> String {
        var out = ""
        out.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            out.append(Character(UnicodeScalar(TailscalePublicKey.hexDigits[Int(byte >> 4)])))
            out.append(Character(UnicodeScalar(TailscalePublicKey.hexDigits[Int(byte & 0x0F)])))
        }
        return out
    }

    /// The lowercase hex alphabet.
    private static let hexDigits: [UInt8] = Array("0123456789abcdef".utf8)
}

// MARK: - Private keys

/// A 32 byte Tailscale *private* key with the role it belongs to.
///
/// The type is deliberately awkward to print: ``description`` and
/// ``debugDescription`` redact the material, and the type is not `Codable`, so
/// there is no way to hand a private key to a `JSONEncoder` and no way to write
/// one to a file by accident. Persistence goes through ``TailscaleStateStore``,
/// which puts private keys in a ``Keychain`` and nothing else.
public struct TailscalePrivateKey: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {

    /// The key size every Tailscale key shares, in bytes.
    public static let size = 32

    /// Which key this is.
    public let role: TailscaleKeyRole

    /// The 32 raw bytes.
    ///
    /// This is the only way to get the material out. Never log it, never write
    /// it to a file, and never put it in a URL.
    public let rawValue: Data

    // MARK: Creation

    /// Wraps key material that is already known to be valid.
    ///
    /// - Parameters:
    ///   - role: Which key this is.
    ///   - rawValue: Exactly 32 bytes.
    /// - Returns: `nil` when the input is not 32 bytes.
    public init?(role: TailscaleKeyRole, rawValue: Data) {
        guard rawValue.count == TailscalePrivateKey.size else { return nil }
        self.role = role
        self.rawValue = rawValue
    }

    /// Generates a new private key of a role.
    ///
    /// All three of Tailscale's keys are clamped Curve25519 scalars
    /// (`types/key/machine.go` `NewMachine`, `node.go` `NewNode`,
    /// `disco.go` `NewDisco` all call `clamp25519Private`), and
    /// ``X25519/generatePrivateKey()`` produces exactly that shape.
    ///
    /// - Parameter role: Which key to generate.
    /// - Throws: ``TailscaleKeyError/unsupportedPlatform(_:)`` when the
    ///   platform has no X25519 implementation.
    /// - Returns: A fresh private key.
    public static func generate(role: TailscaleKeyRole) throws -> TailscalePrivateKey {
        guard X25519.isAvailable else {
            throw TailscaleKeyError.unsupportedPlatform("X25519 requires CryptoKit")
        }
        let bytes = X25519.generatePrivateKey()
        guard let key = TailscalePrivateKey(role: role, rawValue: Data(bytes)) else {
            throw TailscaleKeyError.invalidKeySize(expected: TailscalePrivateKey.size, actual: bytes.count)
        }
        return key
    }

    /// Parses a private key from Go's `privkey:<hex>` form.
    ///
    /// Only used to read back what ``TailscaleStateStore`` put in the keychain,
    /// which is the one place a private key is allowed to exist as text. The
    /// prefixed form is required, so that a public key cannot be read back as a
    /// private one by mistake.
    ///
    /// - Parameters:
    ///   - role: Which key this is.
    ///   - text: The textual key, `privkey:<hex>`.
    /// - Returns: `nil` when the text is not a private key of that role.
    public init?(role: TailscaleKeyRole, text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix(role.privateTextPrefix) else { return nil }
        let hex = String(trimmed.dropFirst(role.privateTextPrefix.count))
        guard let bytes = TailscalePublicKey.hexToBytes(hex),
              bytes.count == TailscalePrivateKey.size else { return nil }
        self.role = role
        self.rawValue = Data(bytes)
    }

    // MARK: Derivation

    /// The matching public key.
    ///
    /// - Throws: ``TailscaleKeyError/keyDerivationFailed`` when the platform
    ///   refuses the scalar.
    /// - Returns: The 32 byte public key.
    public func publicKey() throws -> TailscalePublicKey {
        guard X25519.isAvailable else {
            throw TailscaleKeyError.unsupportedPlatform("X25519 requires CryptoKit")
        }
        let publicBytes: [UInt8]
        do {
            publicBytes = try X25519.publicKey(for: [UInt8](rawValue))
        } catch {
            throw TailscaleKeyError.keyDerivationFailed
        }
        guard let key = TailscalePublicKey(role: role, rawValue: Data(publicBytes)) else {
            throw TailscaleKeyError.invalidKeySize(expected: TailscalePublicKey.size, actual: publicBytes.count)
        }
        return key
    }

    /// The private key as a WireGuard key, which is how the node key is used.
    ///
    /// Note that ``WireGuardKey/description`` prints the base64 form, so do not
    /// log the result.
    public var wireGuardKey: WireGuardKey? {
        WireGuardKey(rawValue: rawValue)
    }

    // MARK: Textual form

    /// A redacted description.
    ///
    /// The key material never appears here. This is not a stylistic choice:
    /// a private key in a log is a private key that has leaked.
    public var description: String {
        "TailscalePrivateKey(\(role.rawValue), redacted)"
    }

    /// A redacted debug description.
    public var debugDescription: String { description }

    /// Go's `privkey:<hex>` form.
    ///
    /// Named `storageText` rather than `description` so that reaching for it is
    /// always a deliberate act.
    var storageText: String {
        role.privateTextPrefix + TailscalePublicKey.bytesToHex([UInt8](rawValue))
    }
}

// MARK: - Key pairs

/// A private key together with the public key derived from it.
public struct TailscaleKeyPair: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {

    /// Which key this pair is.
    public var role: TailscaleKeyRole { privateKey.role }

    /// The private half.
    public let privateKey: TailscalePrivateKey

    /// The public half, which is what goes in a `tailcfg` message.
    public let publicKey: TailscalePublicKey

    /// Generates a fresh pair.
    ///
    /// - Parameter role: Which key to generate.
    /// - Throws: ``TailscaleKeyError`` when the platform cannot derive the
    ///   public key.
    /// - Returns: A new key pair.
    public static func generate(role: TailscaleKeyRole) throws -> TailscaleKeyPair {
        try TailscaleKeyPair(privateKey: TailscalePrivateKey.generate(role: role))
    }

    /// Builds the pair for an existing private key.
    ///
    /// - Parameter privateKey: The private key.
    /// - Throws: ``TailscaleKeyError`` when the public key cannot be derived.
    public init(privateKey: TailscalePrivateKey) throws {
        self.privateKey = privateKey
        self.publicKey = try privateKey.publicKey()
    }

    /// A description that names the key but not its material.
    public var description: String {
        "TailscaleKeyPair(\(role.rawValue), public: \(publicKey.text), private: redacted)"
    }

    /// A debug description that names the key but not its material.
    public var debugDescription: String { description }
}

/// The three keys a node owns.
///
/// Not `Codable`: persisting this through a generic encoder would put private
/// keys in whatever file the caller chose. Use ``TailscaleStateStore``, which
/// knows which half belongs in a keychain.
public struct TailscaleKeys: Sendable, Equatable {

    /// The device key (`key.MachinePrivate`), which survives node-key rotation.
    public var machine: TailscaleKeyPair

    /// The node key (`key.NodePrivate`), which is the WireGuard static key.
    public var node: TailscaleKeyPair

    /// The disco key (`key.DiscoPrivate`), for endpoint discovery.
    public var disco: TailscaleKeyPair

    /// Creates a key set from three existing pairs.
    ///
    /// - Parameters:
    ///   - machine: The device key.
    ///   - node: The node key.
    ///   - disco: The disco key.
    public init(machine: TailscaleKeyPair, node: TailscaleKeyPair, disco: TailscaleKeyPair) {
        self.machine = machine
        self.node = node
        self.disco = disco
    }

    /// Generates a complete set of keys for a fresh install.
    ///
    /// - Throws: ``TailscaleKeyError`` when the platform cannot derive public
    ///   keys.
    /// - Returns: Three freshly generated key pairs.
    public static func generate() throws -> TailscaleKeys {
        TailscaleKeys(machine: try .generate(role: .machine),
                      node: try .generate(role: .node),
                      disco: try .generate(role: .disco))
    }

    /// Replaces the node key, keeping the machine and disco keys.
    ///
    /// This is what key expiry requires: the server remembers the machine, so
    /// the new node key is accepted as a rotation of the old one rather than as
    /// a brand new device.
    ///
    /// - Throws: ``TailscaleKeyError`` when the platform cannot derive public
    ///   keys.
    /// - Returns: A copy of the receiver with a fresh node key.
    public func rotatingNodeKey() throws -> TailscaleKeys {
        var copy = self
        copy.node = try .generate(role: .node)
        return copy
    }
}
