import Foundation

/// The `--key-direction` parameter of `--secret`, `--tls-auth` and `--tls-crypt`
/// (`normal` = 0, `inverse` = 1).
///
/// OpenVPN stores two independent 128-byte key blocks in one 256-byte static
/// key file. `normal` sends with block 0 and receives with block 1; `inverse`
/// swaps them. The conventional deployment is `key-direction 0` on the server
/// and `key-direction 1` on the client, so that the client's *outgoing* key
/// equals the server's *incoming* key.
public enum OVPNKeyDirection: Int, Sendable, Codable, CaseIterable {
    /// Send with key block 0, receive with key block 1.
    case normal = 0
    /// Send with key block 1, receive with key block 0.
    case inverse = 1
}

/// One 128-byte half of an OpenVPN static key file.
///
/// `struct key` in OpenVPN is two 64-byte fields laid out back to back:
///
/// ```
/// offset 0  .. 63   cipher key (only the first `key_length` bytes are used)
/// offset 64 .. 127  HMAC key   (only the first `digest_length` bytes are used)
/// ```
///
/// AEAD ciphers do not use the HMAC key for a MAC; they reuse its *first*
/// `iv_length - 4` bytes as the implicit part of the packet nonce (see
/// `implicitIV`). That is a documented OpenVPN quirk, not an accident.
public struct OVPNKeyBlock: Sendable, Equatable {
    /// The 128 raw bytes (`keys[0]` or `keys[1]` of the key file).
    public let raw: Data

    /// Create a key block from exactly 128 bytes.
    public init(raw: Data) throws {
        guard raw.count == 128 else {
            throw OVPNError.invalidStaticKey("key block must be 128 bytes, got \(raw.count)")
        }
        self.raw = raw
    }

    /// The 64-byte cipher key field.
    public var cipherKey: Data { raw.prefix(64) }

    /// The 64-byte HMAC key field.
    public var hmacKey: Data { raw.suffix(64) }

    /// The cipher key truncated to the length the negotiated cipher needs
    /// (32 bytes for AES-256, 16 for AES-128, ...).
    public func cipherKey(length: Int) throws -> Data {
        guard length > 0, length <= 64 else {
            throw OVPNError.invalidStaticKey("cipher key length \(length) out of range")
        }
        return raw.prefix(length)
    }

    /// The HMAC key truncated to the digest size, which is what OpenVPN does
    /// (`key_type.hmac_length = md_kt_size(digest)`).
    public func hmacKey(digestLength: Int) throws -> Data {
        guard digestLength > 0, digestLength <= 64 else {
            throw OVPNError.invalidStaticKey("hmac key length \(digestLength) out of range")
        }
        return raw.suffix(64).prefix(digestLength)
    }

    /// The implicit IV used by AEAD ciphers, in OpenVPN's legacy (non-epoch)
    /// data format: `iv_length - 4` bytes taken from the *start of the HMAC
    /// key field*, placed at offset 4 of the 16-byte implicit IV buffer.
    ///
    /// `key_ctx_update_implicit_iv()` in `src/openvpn/crypto.c` documents this.
    public func implicitIV(ivLength: Int) -> Data {
        var iv = Data(repeating: 0, count: max(ivLength, 0))
        let implicitLength = max(ivLength - 4, 0)
        guard implicitLength > 0 else { return iv }
        let source = raw.suffix(64).prefix(implicitLength)
        for (index, byte) in source.enumerated() {
            iv[iv.startIndex + 4 + index] = byte
        }
        return iv
    }
}

/// The 256 bytes of an OpenVPN static key file (`.key`, `ta.key`, `static.key`).
///
/// The file is the serialisation of
///
/// ```c
/// struct key2 { int n; struct key keys[2]; };
/// ```
///
/// i.e. two 128-byte key blocks back to back, written as 16 lines of 32 hex
/// characters inside a `-----BEGIN OpenVPN Static key V1-----` envelope.
///
/// Block 0 is the bidirectional material (`--secret`, `--tls-auth`,
/// `--tls-crypt` use it for both directions) and is also the client's outgoing
/// block under `key-direction 0`; block 1 is the client's incoming block.
public struct OVPNStaticKey: Sendable, Equatable {
    /// Required size of the decoded key material.
    public static let byteCount = 256

    /// PEM-like begin marker used by `--genkey`.
    public static let beginMarker = "-----BEGIN OpenVPN Static key V1-----"
    /// PEM-like end marker used by `--genkey`.
    public static let endMarker = "-----END OpenVPN Static key V1-----"

    /// The full 256 decoded bytes.
    public let raw: Data

    /// Wrap exactly 256 bytes of key material.
    public init(raw: Data) throws {
        guard raw.count == Self.byteCount else {
            throw OVPNError.invalidStaticKey("expected \(Self.byteCount) bytes, got \(raw.count)")
        }
        self.raw = raw
    }

    /// `keys[0].cipher` — bytes 0..<64. Used with `--secret`/`--tls-crypt` in
    /// bidirectional mode.
    public var cipherKey: Data { raw.prefix(64) }

    /// `keys[0].hmac` — bytes 64..<128. Used with `--tls-auth`.
    public var hmacKey: Data { raw.suffix(192).prefix(64) }

    /// `keys[0]` — bytes 0..<128. The block a client sends with under
    /// `key-direction 0`, and the block its peer receives with.
    public var clientSendKey: Data { raw.prefix(128) }

    /// `keys[1]` — bytes 128..<256. The block a server sends with under
    /// `key-direction 0`.
    public var serverSendKey: Data { raw.suffix(128) }

    /// `keys[1]` — the block a client receives with under `key-direction 0`.
    /// Identical to `serverSendKey`, spelled for the receiving side.
    public var clientRecvKey: Data { serverSendKey }

    /// `keys[0]` — the block a server receives with under `key-direction 0`.
    /// Identical to `clientSendKey`, spelled for the receiving side.
    public var serverRecvKey: Data { clientSendKey }

    /// The key block to *encrypt* with for a direction.
    /// `nil` direction means bidirectional, which always uses block 0.
    public func sendKey(direction: OVPNKeyDirection?) -> OVPNKeyBlock {
        block(for: direction, sending: true)
    }

    /// The key block to *decrypt* with for a direction.
    public func recvKey(direction: OVPNKeyDirection?) -> OVPNKeyBlock {
        block(for: direction, sending: false)
    }

    private func block(for direction: OVPNKeyDirection?, sending: Bool) -> OVPNKeyBlock {
        let index: Int
        switch direction {
        case .none: index = 0
        case .normal: index = sending ? 0 : 1
        case .inverse: index = sending ? 1 : 0
        }
        // Both halves are always 128 bytes, so this cannot fail.
        return (try? OVPNKeyBlock(raw: index == 0 ? raw.prefix(128) : raw.suffix(128)))
            ?? OVPNKeyBlock(unchecked: raw.prefix(128))
    }

    /// Parse an `OpenVPN Static key V1` block.
    ///
    /// Accepts the canonical 16 lines of 32 hex characters, ignores the
    /// envelope, blank lines and `#` comments, and returns `nil` for anything
    /// that does not decode to exactly 256 bytes.
    public static func parse(_ text: String) -> OVPNStaticKey? {
        var hex = String()
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty { continue }
            if line.hasPrefix("-----") { continue }
            if line.hasPrefix("#") || line.hasPrefix(";") { continue }
            for scalar in line.unicodeScalars {
                guard CharacterSet.alphanumerics.contains(scalar) else { continue }
                hex.unicodeScalars.append(scalar)
            }
        }
        guard hex.count == byteCount * 2, let raw = OVPNWire.decodeHex(hex) else { return nil }
        return try? OVPNStaticKey(raw: raw)
    }

    /// Generate fresh random key material (the equivalent of
    /// `openvpn --genkey secret out.key`).
    public static func generate() -> OVPNStaticKey {
        var bytes = OVPNWire.randomBytes(byteCount)
        while bytes.count < byteCount {
            bytes.append(contentsOf: OVPNWire.randomBytes(byteCount - bytes.count))
        }
        return OVPNStaticKey(uncheckedRaw: bytes)
    }

    /// The canonical textual form (16 lines of 32 hex characters).
    public var pemRepresentation: String {
        var out = Self.beginMarker + "\n"
        let hex = OVPNWire.encodeHex(raw)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 32, limitedBy: hex.endIndex) ?? hex.endIndex
            out += String(hex[index..<next]) + "\n"
            index = next
        }
        out += Self.endMarker + "\n"
        return out
    }
}

/// A static key file plus its optional `--key-direction`.
///
/// Used for `--secret` (static key mode) and for the control-channel
/// authentication keys of `--tls-auth` / `--tls-crypt`.
public struct OVPNStaticKeyFile: Sendable, Equatable {
    /// `--key-direction 0`, `1`, or `nil` for bidirectional (no direction).
    public var direction: Int?

    /// The 256 bytes of key material.
    public var key: OVPNStaticKey

    /// Create a key file value.
    public init(direction: Int? = nil, key: OVPNStaticKey) {
        self.direction = direction
        self.key = key
    }

    /// The direction as a typed value (`nil` for bidirectional).
    public var keyDirection: OVPNKeyDirection? {
        guard let direction else { return nil }
        if direction & 1 == 0 { return .normal }
        return .inverse
    }

    /// The key block to encrypt with.
    public var sendKeyBlock: OVPNKeyBlock { key.sendKey(direction: keyDirection) }

    /// The key block to decrypt with.
    public var recvKeyBlock: OVPNKeyBlock { key.recvKey(direction: keyDirection) }
}

/// A `-----BEGIN OpenVPN tls-crypt-v2 client key-----` file.
///
/// The base64 payload is `wrapped_client_key || key`, where `key` is a single
/// 128-byte key block (`struct key`: 64-byte cipher field + 64-byte HMAC
/// field) and `wrapped_client_key` is the blob the client must echo to the
/// server in the `P_CONTROL_HARD_RESET_CLIENT_V3` / `P_CONTROL_WKC_V1`
/// packets. The client uses `key` for the tls-crypt wrapping of its own
/// control channel, exactly like `--tls-crypt`.
public struct OVPNTlsCryptV2ClientKey: Sendable, Equatable {
    /// Begin marker of the client key file.
    public static let beginMarker = "-----BEGIN OpenVPN tls-crypt-v2 client key-----"
    /// End marker of the client key file.
    public static let endMarker = "-----END OpenVPN tls-crypt-v2 client key-----"

    /// The decoded file contents (`wrappedClientKey || key`).
    public let raw: Data

    /// Wrapped client key, to be appended to `P_CONTROL_HARD_RESET_CLIENT_V3`
    /// and `P_CONTROL_WKC_V1` packets.
    public let wrappedClientKey: Data

    /// The 128-byte tls-crypt key the client uses for its control channel.
    public let key: OVPNKeyBlock

    /// Split a decoded client-key blob.
    public init(raw: Data) throws {
        guard raw.count > 128 else {
            throw OVPNError.invalidStaticKey("tls-crypt-v2 client key blob too short (\(raw.count) bytes)")
        }
        self.raw = raw
        self.wrappedClientKey = raw.prefix(raw.count - 128)
        self.key = OVPNKeyBlock(unchecked: raw.suffix(128))
    }

    /// Parse the PEM-like client key file.
    public static func parse(_ text: String) -> OVPNTlsCryptV2ClientKey? {
        var base64 = String()
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty || line.hasPrefix("-----") { continue }
            base64 += line
        }
        guard let raw = Data(base64Encoded: base64) else { return nil }
        return try? OVPNTlsCryptV2ClientKey(raw: raw)
    }

    /// Encode back to the PEM-like form.
    public var pemRepresentation: String {
        let body = raw.base64EncodedString()
        var lines: [String] = []
        var index = body.startIndex
        while index < body.endIndex {
            let next = body.index(index, offsetBy: 64, limitedBy: body.endIndex) ?? body.endIndex
            lines.append(String(body[index..<next]))
            index = next
        }
        return ([Self.beginMarker] + lines + [Self.endMarker]).joined(separator: "\n") + "\n"
    }
}

extension OVPNKeyBlock {
    /// Internal bypass used where the length was already validated by a caller
    /// (static-key splitting, tls-crypt-v2 parsing).
    init(unchecked raw: Data) {
        self.raw = raw
    }
}

extension OVPNStaticKey {
    /// Internal bypass used where the length was already validated.
    init(uncheckedRaw raw: Data) {
        self.raw = raw
    }
}
