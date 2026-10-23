//
//  XChaCha20Poly1305.swift
//  VPNEngine
//
//  XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03, section 2.4).
//
//  WireGuard uses this construction for exactly one thing: the cookie reply
//  message (whitepaper, section 5.4.7). The 192 bit nonce is used as
//  `HChaCha20(key, nonce[0..16])` for the subkey and then the remaining eight
//  nonce bytes are prefixed with four zero bytes to form the 96 bit nonce of
//  the underlying ChaCha20-Poly1305 AEAD.
//

import Foundation

/// XChaCha20-Poly1305, the extended nonce AEAD used for WireGuard's cookie reply.
public enum XChaCha20Poly1305 {

    /// Nonce length in bytes.
    public static let nonceSize = 24

    /// Tag length in bytes.
    public static let tagSize = 16

    /// Derives the 12 byte IETF nonce used by the inner ChaCha20-Poly1305 call.
    ///
    /// - Parameter nonce24: The 24 byte extended nonce.
    /// - Returns: `00000000 || nonce24[16..24]`, or `nil` if the size is wrong.
    static func derivedNonce(_ nonce24: Data) -> Data? {
        guard nonce24.count == nonceSize else { return nil }
        var nonce = Data(repeating: 0, count: 4)
        nonce.append(nonce24.suffix(8))
        return nonce
    }

    /// Derives the subkey for the inner ChaCha20-Poly1305 call.
    ///
    /// - Parameters:
    ///   - key: 32 byte key.
    ///   - nonce24: The 24 byte extended nonce.
    /// - Returns: The 32 byte subkey, or `nil` if a size is wrong.
    static func subkey(key: Data, nonce24: Data) -> [UInt8]? {
        guard nonce24.count == nonceSize else { return nil }
        return HChaCha20.subkey(key: [UInt8](key), nonce: [UInt8](nonce24.prefix(16)))
    }

    /// Encrypts and authenticates `plaintext`.
    ///
    /// - Parameters:
    ///   - key: 32 byte key, normally `HASH("cookie--" || responder public key)`.
    ///   - nonce24: 24 byte extended nonce. For WireGuard's cookie reply this is
    ///     a random value chosen by the responder.
    ///   - plaintext: The data to encrypt; the 16 byte cookie for WireGuard.
    ///   - authenticatedData: Authenticated but unencrypted data. WireGuard
    ///     passes the `mac1` value of the message that triggered the cookie
    ///     reply, which binds the reply to that message.
    /// - Throws: ``VPNCryptoError`` if a size is wrong or the AEAD fails.
    /// - Returns: Ciphertext followed by the 16 byte tag.
    public static func seal(key: Data,
                            nonce24: Data,
                            plaintext: Data,
                            authenticatedData: Data) throws -> Data {
        guard key.count == ChaCha20.keySize else {
            throw VPNCryptoError.invalidKeySize(expected: ChaCha20.keySize, actual: key.count)
        }
        guard nonce24.count == nonceSize else {
            throw VPNCryptoError.invalidNonceSize(expected: nonceSize, actual: nonce24.count)
        }
        guard let derivedKey = subkey(key: key, nonce24: nonce24),
              let derivedNonce = derivedNonce(nonce24) else {
            throw VPNCryptoError.invalidNonceSize(expected: nonceSize, actual: nonce24.count)
        }
        let sealed = try ChaChaPolyAEAD.seal(key: derivedKey,
                                             nonce: [UInt8](derivedNonce),
                                             plaintext: [UInt8](plaintext),
                                             authenticatedData: [UInt8](authenticatedData))
        return Data(sealed)
    }

    /// Verifies and decrypts a sealed box produced by ``seal(key:nonce24:plaintext:authenticatedData:)``.
    ///
    /// - Parameters:
    ///   - key: 32 byte key.
    ///   - nonce24: 24 byte extended nonce.
    ///   - ciphertext: Ciphertext followed by the 16 byte tag.
    ///   - authenticatedData: The same additional data passed to `seal`.
    /// - Throws: ``VPNCryptoError/authenticationFailure`` when the tag does not
    ///   verify; callers must treat that as "drop the message silently".
    /// - Returns: The plaintext.
    public static func open(key: Data,
                            nonce24: Data,
                            ciphertext: Data,
                            authenticatedData: Data) throws -> Data {
        guard key.count == ChaCha20.keySize else {
            throw VPNCryptoError.invalidKeySize(expected: ChaCha20.keySize, actual: key.count)
        }
        guard nonce24.count == nonceSize else {
            throw VPNCryptoError.invalidNonceSize(expected: nonceSize, actual: nonce24.count)
        }
        guard let derivedKey = subkey(key: key, nonce24: nonce24),
              let derivedNonce = derivedNonce(nonce24) else {
            throw VPNCryptoError.invalidNonceSize(expected: nonceSize, actual: nonce24.count)
        }
        let plaintext = try ChaChaPolyAEAD.open(key: derivedKey,
                                               nonce: [UInt8](derivedNonce),
                                               ciphertext: [UInt8](ciphertext),
                                               authenticatedData: [UInt8](authenticatedData))
        return Data(plaintext)
    }
}
