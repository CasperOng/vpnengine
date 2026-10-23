//
//  ChaCha20Poly1305.swift
//  VPNEngine
//
//  AEAD_CHACHA20_POLY1305 (RFC 8439, section 2.8).
//
//  Two entry points live here:
//
//   * ``ChaCha20Poly1305`` - a self contained implementation used as the
//     reference for the test suite and as the fallback on platforms without
//     CryptoKit.
//   * ``ChaChaPolyAEAD`` - the construction the protocol code actually calls.
//     On Apple platforms it forwards to CryptoKit's `ChaChaPoly`; elsewhere it
//     falls back to the local implementation. Both are byte for byte identical,
//     which the test suite asserts.
//

import Foundation

#if canImport(CryptoKit)
import CryptoKit
#endif

/// AEAD_CHACHA20_POLY1305 built from the local ChaCha20 and Poly1305.
///
/// The construction is the IETF one: a 96 bit nonce, a Poly1305 one-time key
/// taken from keystream block 0, and message data encrypted with keystream
/// blocks starting at counter 1. This is exactly the AEAD WireGuard uses for
/// transport data messages and for the encrypted fields of handshake messages.
public enum ChaCha20Poly1305 {

    /// Tag length in bytes.
    public static let tagSize = 16

    /// Nonce length in bytes.
    public static let nonceSize = 12

    /// Length of the ChaCha20 block used as the Poly1305 key.
    private static let poly1305KeyLength = 32

    /// Encrypts and authenticates `plaintext`.
    ///
    /// - Parameters:
    ///   - key: 32 byte key.
    ///   - nonce: 12 byte nonce. Must never be reused with the same key.
    ///   - plaintext: The data to encrypt.
    ///   - authenticatedData: Additional data that is authenticated but not
    ///     encrypted. WireGuard passes the handshake hash here, or nothing at
    ///     all for transport data.
    /// - Returns: `plaintext.count + 16` bytes: ciphertext followed by the tag,
    ///   or `nil` if a size is wrong.
    public static func seal(key: [UInt8],
                            nonce: [UInt8],
                            plaintext: [UInt8],
                            authenticatedData: [UInt8]) -> [UInt8]? {
        guard key.count == ChaCha20.keySize else { return nil }
        guard nonce.count == ChaCha20.nonceSize else { return nil }
        guard let ciphertext = ChaCha20.xor(key: key, nonce: nonce, counter: 1, data: plaintext) else {
            return nil
        }
        guard let tag = authenticationTag(key: key,
                                          nonce: nonce,
                                          ciphertext: ciphertext,
                                          authenticatedData: authenticatedData) else {
            return nil
        }
        return ciphertext + tag
    }

    /// Verifies and decrypts a sealed box produced by ``seal(key:nonce:plaintext:authenticatedData:)``.
    ///
    /// - Parameters:
    ///   - key: 32 byte key.
    ///   - nonce: 12 byte nonce.
    ///   - ciphertext: Ciphertext followed by the 16 byte tag.
    ///   - authenticatedData: The same additional data passed to `seal`.
    /// - Returns: The plaintext, or `nil` if the tag does not verify or a size
    ///   is wrong.
    public static func open(key: [UInt8],
                            nonce: [UInt8],
                            ciphertext: [UInt8],
                            authenticatedData: [UInt8]) -> [UInt8]? {
        guard key.count == ChaCha20.keySize else { return nil }
        guard nonce.count == ChaCha20.nonceSize else { return nil }
        guard ciphertext.count >= tagSize else { return nil }

        let body = Array(ciphertext[0 ..< ciphertext.count - tagSize])
        let tag = Array(ciphertext[ciphertext.count - tagSize ..< ciphertext.count])
        guard let expected = authenticationTag(key: key,
                                              nonce: nonce,
                                              ciphertext: body,
                                              authenticatedData: authenticatedData) else {
            return nil
        }
        guard constantTimeEquals(expected, tag) else { return nil }
        return ChaCha20.xor(key: key, nonce: nonce, counter: 1, data: body)
    }

    // MARK: - Internals

    /// Derives the Poly1305 one-time key from keystream block 0.
    static func poly1305Key(key: [UInt8], nonce: [UInt8]) -> [UInt8]? {
        guard let block = ChaCha20.block(key: key, counter: 0, nonce: nonce) else { return nil }
        return Array(block.prefix(poly1305KeyLength))
    }

    /// Computes the tag over the RFC 8439 AEAD construction
    /// `aad || pad16(aad) || ct || pad16(ct) || len(aad) || len(ct)`.
    static func authenticationTag(key: [UInt8],
                                  nonce: [UInt8],
                                  ciphertext: [UInt8],
                                  authenticatedData: [UInt8]) -> [UInt8]? {
        guard let oneTimeKey = poly1305Key(key: key, nonce: nonce) else { return nil }

        var message: [UInt8] = []
        message.reserveCapacity(authenticatedData.count + ciphertext.count + 32)
        message.append(contentsOf: authenticatedData)
        message.append(contentsOf: [UInt8](repeating: 0, count: padding(for: authenticatedData.count)))
        message.append(contentsOf: ciphertext)
        message.append(contentsOf: [UInt8](repeating: 0, count: padding(for: ciphertext.count)))
        message.append(contentsOf: littleEndian64(UInt64(authenticatedData.count)))
        message.append(contentsOf: littleEndian64(UInt64(ciphertext.count)))

        return Poly1305.tag(key: oneTimeKey, message: message)
    }

    private static func padding(for length: Int) -> Int {
        (16 - (length % 16)) % 16
    }

    private static func littleEndian64(_ value: UInt64) -> [UInt8] {
        (0 ..< 8).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
    }
}

/// Compares two byte arrays without leaking their contents through timing.
///
/// - Parameters:
///   - lhs: First buffer.
///   - rhs: Second buffer.
/// - Returns: `true` when the buffers have equal contents. Buffers of
///   different lengths compare unequal, but the contents are still folded in so
///   that the running time does not depend on the first differing byte.
func constantTimeEquals(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
    var difference = UInt8(lhs.count == rhs.count ? 0 : 1)
    let count = Swift.min(lhs.count, rhs.count)
    for i in 0 ..< count {
        difference |= lhs[i] ^ rhs[i]
    }
    return difference == 0
}

/// The AEAD that the WireGuard protocol code calls.
///
/// On Apple platforms this forwards to CryptoKit's `ChaChaPoly`, which is the
/// hardware accelerated implementation. `CryptoKit` only exposes the IETF
/// 96 bit nonce variant, which is exactly what WireGuard needs for handshake
/// fields and transport data messages; the cookie reply uses the extended
/// nonce variant in ``XChaCha20Poly1305``.
public enum ChaChaPolyAEAD {

    /// Tag length in bytes.
    public static let tagSize = 16

    /// Nonce length in bytes.
    public static let nonceSize = 12

    /// Encrypts and authenticates `plaintext`.
    ///
    /// - Parameters:
    ///   - key: 32 byte key.
    ///   - nonce: 12 byte nonce.
    ///   - plaintext: The data to encrypt.
    ///   - authenticatedData: Authenticated but unencrypted data.
    /// - Throws: ``VPNCryptoError`` for bad sizes, or a CryptoKit error.
    /// - Returns: Ciphertext followed by the 16 byte tag.
    public static func seal(key: [UInt8],
                            nonce: [UInt8],
                            plaintext: [UInt8],
                            authenticatedData: [UInt8]) throws -> [UInt8] {
        guard key.count == ChaCha20.keySize else {
            throw VPNCryptoError.invalidKeySize(expected: ChaCha20.keySize, actual: key.count)
        }
        guard nonce.count == nonceSize else {
            throw VPNCryptoError.invalidNonceSize(expected: nonceSize, actual: nonce.count)
        }

        #if canImport(CryptoKit)
        let symmetricKey = SymmetricKey(data: Data(key))
        let cryptoKitNonce = try ChaChaPoly.Nonce(data: Data(nonce))
        let box = try ChaChaPoly.seal(Data(plaintext),
                                      using: symmetricKey,
                                      nonce: cryptoKitNonce,
                                      authenticating: Data(authenticatedData))
        return [UInt8](box.ciphertext) + [UInt8](box.tag)
        #else
        guard let sealed = ChaCha20Poly1305.seal(key: key,
                                                 nonce: nonce,
                                                 plaintext: plaintext,
                                                 authenticatedData: authenticatedData) else {
            throw VPNCryptoError.authenticationFailure
        }
        return sealed
        #endif
    }

    /// Verifies and decrypts a sealed box.
    ///
    /// - Parameters:
    ///   - key: 32 byte key.
    ///   - nonce: 12 byte nonce.
    ///   - ciphertext: Ciphertext followed by the 16 byte tag.
    ///   - authenticatedData: Authenticated but unencrypted data.
    /// - Throws: ``VPNCryptoError/authenticationFailure`` when the tag does not
    ///   verify; callers must treat that as "drop the packet silently".
    /// - Returns: The plaintext.
    public static func open(key: [UInt8],
                            nonce: [UInt8],
                            ciphertext: [UInt8],
                            authenticatedData: [UInt8]) throws -> [UInt8] {
        guard key.count == ChaCha20.keySize else {
            throw VPNCryptoError.invalidKeySize(expected: ChaCha20.keySize, actual: key.count)
        }
        guard nonce.count == nonceSize else {
            throw VPNCryptoError.invalidNonceSize(expected: nonceSize, actual: nonce.count)
        }
        guard ciphertext.count >= tagSize else {
            throw VPNCryptoError.authenticationFailure
        }

        #if canImport(CryptoKit)
        let body = Data(ciphertext[0 ..< ciphertext.count - tagSize])
        let tag = Data(ciphertext[ciphertext.count - tagSize ..< ciphertext.count])
        let box = try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: Data(nonce)),
                                           ciphertext: body,
                                           tag: tag)
        do {
            let plaintext = try ChaChaPoly.open(box,
                                                using: SymmetricKey(data: Data(key)),
                                                authenticating: Data(authenticatedData))
            return [UInt8](plaintext)
        } catch {
            throw VPNCryptoError.authenticationFailure
        }
        #else
        guard let plaintext = ChaCha20Poly1305.open(key: key,
                                                    nonce: nonce,
                                                    ciphertext: ciphertext,
                                                    authenticatedData: authenticatedData) else {
            throw VPNCryptoError.authenticationFailure
        }
        return plaintext
        #endif
    }
}
