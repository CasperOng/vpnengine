import CryptoKit
import Foundation
#if canImport(CommonCrypto)
import CommonCrypto
#endif

/// The digests OpenVPN can use for its packet HMACs.
///
/// `--auth` selects this for the data channel; `--tls-auth` selects it for the
/// control channel (OpenVPN 2.6 defaults to SHA-256 there, older releases used
/// SHA-1, which is why ``OVPNControlCrypto`` lets the caller pick).
public enum OVPNHMACAlgorithm: Sendable, Equatable, CaseIterable {
    /// SHA-1 (20-byte MAC) — legacy default of OpenVPN <= 2.5.
    case sha1
    /// SHA-256 (32-byte MAC) — default of OpenVPN 2.6.
    case sha256
    /// SHA-512 (64-byte MAC).
    case sha512

    /// Length of the MAC this digest produces.
    public var macLength: Int {
        switch self {
        case .sha1: return 20
        case .sha256: return 32
        case .sha512: return 64
        }
    }

    /// Compute `HMAC(key, data)`.
    public func authenticate(key: Data, data: Data) -> Data {
        switch self {
        case .sha1:
            let mac = HMAC<Insecure.SHA1>.authenticationCode(for: data, using: SymmetricKey(data: key))
            return Data(mac)
        case .sha256:
            let mac = HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key))
            return Data(mac)
        case .sha512:
            let mac = HMAC<SHA512>.authenticationCode(for: data, using: SymmetricKey(data: key))
            return Data(mac)
        }
    }

    /// Constant-time verification of `HMAC(key, data) == tag`.
    public func verify(key: Data, data: Data, tag: Data) -> Bool {
        let expected = authenticate(key: key, data: data)
        return OVPNWire.constantTimeEquals(expected, tag)
    }

    /// The OpenVPN spelling (`SHA1`, `SHA256`, ...).
    public var openVPNName: String {
        switch self {
        case .sha1: return "SHA1"
        case .sha256: return "SHA256"
        case .sha512: return "SHA512"
        }
    }

    /// Parse an OpenVPN digest name. Returns `nil` for unknown names, and the
    /// caller decides whether that is fatal.
    public static func parse(_ name: String?) -> OVPNHMACAlgorithm? {
        guard let name else { return nil }
        switch name.uppercased().replacingOccurrences(of: "-", with: "") {
        case "SHA", "SHA1": return .sha1
        case "SHA256": return .sha256
        case "SHA512": return .sha512
        default: return nil
        }
    }
}

/// Subset of OpenVPN's cipher list that this engine implements.
///
/// The names are the OpenVPN spellings (`AES-256-GCM`, `AES-256-CBC`,
/// `CHACHA20-POLY1305`); OpenVPN 2.6 also accepts `AES-256-GCM` style names
/// with an explicit tag length such as `AES-256-GCM:16`, which is stripped.
public enum OVPNCipherSpec: Sendable, Equatable {
    /// AES in CBC mode with a separate HMAC (the classic format).
    case cbc(keyLength: Int, name: String)
    /// AES-GCM (AEAD, 16-byte tag).
    case gcm(keyLength: Int, name: String)
    /// ChaCha20-Poly1305 (AEAD, 16-byte tag).
    case chacha20Poly1305(name: String)

    /// Block size for CBC ciphers, `nil` for stream/AEAD ciphers.
    public var blockSize: Int? {
        if case .cbc = self { return 16 }
        return nil
    }

    /// Key length in bytes.
    public var keyLength: Int {
        switch self {
        case let .cbc(keyLength, _), let .gcm(keyLength, _): return keyLength
        case .chacha20Poly1305: return 32
        }
    }

    /// Nonce/IV length in bytes used by OpenVPN for this cipher.
    public var ivLength: Int {
        switch self {
        case .cbc: return 16
        // OpenVPN uses a 12-byte nonce for both AEAD ciphers: the 4-byte
        // packet id followed by the implicit IV.
        case .gcm, .chacha20Poly1305: return 12
        }
    }

    /// AEAD ciphers carry their own authentication tag.
    public var isAEAD: Bool {
        switch self {
        case .cbc: return false
        case .gcm, .chacha20Poly1305: return true
        }
    }

    /// Size of the authentication tag on the wire.
    public var tagLength: Int { isAEAD ? 16 : 0 }

    /// The OpenVPN name to echo in logs and `--data-ciphers` negotiation.
    public var name: String {
        switch self {
        case let .cbc(_, name), let .gcm(_, name), let .chacha20Poly1305(name): return name
        }
    }

    /// The `OVPNPacketCodec.Cipher` value for this spec.
    var codecCipher: OVPNPacketCodec.Cipher {
        switch self {
        case let .cbc(_, name): return .aesCBC(name: name)
        case let .gcm(_, name): return .aesGCM(name: name)
        case .chacha20Poly1305: return .chacha20Poly1305
        }
    }

    /// Parse an OpenVPN cipher name (case is not significant).
    public static func parse(_ name: String) -> OVPNCipherSpec? {
        var token = name.uppercased()
        // `AES-256-GCM:16` (tag length suffix) and `AES-256-CBC:32`.
        if let colon = token.firstIndex(of: ":") { token = String(token[token.startIndex..<colon]) }
        switch token {
        case "AES-128-CBC": return .cbc(keyLength: 16, name: token)
        case "AES-192-CBC": return .cbc(keyLength: 24, name: token)
        case "AES-256-CBC": return .cbc(keyLength: 32, name: token)
        case "AES-128-GCM": return .gcm(keyLength: 16, name: token)
        case "AES-192-GCM": return .gcm(keyLength: 24, name: token)
        case "AES-256-GCM": return .gcm(keyLength: 32, name: token)
        case "CHACHA20-POLY1305": return .chacha20Poly1305(name: token)
        default: return nil
        }
    }
}

/// AES primitives that `CryptoKit` does not expose (CBC and raw CTR), backed by
/// CommonCrypto.
///
/// The rest of the engine talks to these three functions only, so swapping in
/// another backend (OpenSSL for Linux, for example) means editing one file.
enum OVPNAES {

    /// One-shot AES-CBC. The caller is responsible for padding: `data` must be
    /// a whole number of 16-byte blocks.
    static func cbc(key: Data, iv: Data, data: Data, encrypt: Bool) throws -> Data {
        #if canImport(CommonCrypto)
        guard key.count == 16 || key.count == 24 || key.count == 32 else {
            throw OVPNError.unsupportedCipher("AES key length \(key.count)")
        }
        guard iv.count == 16 else {
            throw OVPNError.malformedPacket("AES-CBC IV must be 16 bytes, got \(iv.count)")
        }
        guard data.count % 16 == 0 else {
            throw OVPNError.malformedPacket("AES-CBC input must be block aligned, got \(data.count)")
        }
        guard !data.isEmpty else { return Data() }

        var out = Data(count: data.count + 16)
        var moved = 0
        // `out.count` must be read before the buffer is borrowed exclusively.
        let outputCapacity = out.count
        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                data.withUnsafeBytes { inputBytes in
                    out.withUnsafeMutableBytes { outputBytes in
                        CCCrypt(
                            CCOperation(encrypt ? kCCEncrypt : kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(ccNoPadding),
                            keyBytes.baseAddress, key.count,
                            ivBytes.baseAddress,
                            inputBytes.baseAddress, data.count,
                            outputBytes.baseAddress, outputCapacity,
                            &moved
                        )
                    }
                }
            }
        }
        guard status == kCCSuccess else {
            throw OVPNError.malformedPacket("AES-CBC operation failed (\(status))")
        }
        out.removeSubrange((out.startIndex + moved)..<out.endIndex)
        return out
        #else
        throw OVPNError.unsupportedFeature("AES-CBC requires CommonCrypto on this platform")
        #endif
    }

    /// AES in counter mode (big-endian counter, as OpenVPN's `AES-256-CTR`
    /// uses for tls-crypt). CTR is symmetric, so one function serves both
    /// directions.
    static func ctr(key: Data, iv: Data, data: Data) throws -> Data {
        #if canImport(CommonCrypto)
        guard key.count == 16 || key.count == 24 || key.count == 32 else {
            throw OVPNError.unsupportedCipher("AES key length \(key.count)")
        }
        guard iv.count == 16 else {
            throw OVPNError.malformedPacket("AES-CTR IV must be 16 bytes, got \(iv.count)")
        }
        guard !data.isEmpty else { return Data() }

        var cryptor: CCCryptorRef?
        let createStatus = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                CCCryptorCreateWithMode(
                    CCOperation(kCCEncrypt),
                    CCMode(kCCModeCTR),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding),
                    ivBytes.baseAddress,
                    keyBytes.baseAddress,
                    key.count,
                    nil, 0, 0,
                    CCModeOptions(kCCModeOptionCTR_BE),
                    &cryptor
                )
            }
        }
        guard createStatus == kCCSuccess, let cryptor else {
            throw OVPNError.unsupportedFeature("AES-CTR unavailable")
        }
        defer { CCCryptorRelease(cryptor) }

        var out = Data(count: data.count)
        var moved = 0
        let outputCapacity = out.count
        let status = data.withUnsafeBytes { inputBytes in
            out.withUnsafeMutableBytes { outputBytes in
                CCCryptorUpdate(cryptor, inputBytes.baseAddress, data.count, outputBytes.baseAddress, outputCapacity, &moved)
            }
        }
        guard status == kCCSuccess, moved == data.count else {
            throw OVPNError.decryptionFailed
        }
        return out
        #else
        throw OVPNError.unsupportedFeature("AES-CTR requires CommonCrypto on this platform")
        #endif
    }
}

/// PKCS#7 padding, as OpenVPN's CBC ciphers apply through OpenSSL's
/// `EVP_CIPHER` with padding enabled.
enum OVPNPadding {

    /// Append `1...blockSize` bytes so the result is a whole number of blocks.
    /// A full extra block is added when `data` is already aligned — that is
    /// what PKCS#7 requires and what OpenVPN puts on the wire.
    static func pkcs7Pad(_ data: Data, blockSize: Int) -> Data {
        let remainder = data.count % blockSize
        let padLength = blockSize - remainder
        var out = data
        out.append(contentsOf: repeatElement(UInt8(padLength), count: padLength))
        return out
    }

    /// Remove PKCS#7 padding, rejecting anything that is not valid padding.
    static func pkcs7Unpad(_ data: Data, blockSize: Int) throws -> Data {
        guard let last = data.last else {
            throw OVPNError.decryptionFailed
        }
        let padLength = Int(last)
        guard padLength >= 1, padLength <= blockSize, padLength <= data.count else {
            throw OVPNError.decryptionFailed
        }
        let suffix = data.suffix(padLength)
        guard suffix.allSatisfy({ $0 == last }) else {
            throw OVPNError.decryptionFailed
        }
        return data.dropLast(padLength)
    }

    /// Zero padding used for TAP mode, which must not grow the frame: the
    /// Ethernet header carries the real length.
    static func zeroPad(_ data: Data, blockSize: Int) -> Data {
        let remainder = data.count % blockSize
        guard remainder != 0 else { return data }
        var out = data
        out.append(contentsOf: repeatElement(0, count: blockSize - remainder))
        return out
    }
}
