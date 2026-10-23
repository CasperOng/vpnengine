//
//  X25519.swift
//  VPNEngine
//
//  X25519 Diffie-Hellman (RFC 7748), the only asymmetric primitive in the
//  WireGuard handshake.
//
//  This wrapper exists so that exactly one file in the package touches
//  CryptoKit's key agreement API, and so that the RFC 7748 test vectors can be
//  driven through the same code path the handshake uses.
//

import Foundation

#if canImport(CryptoKit)
import CryptoKit
#endif

/// X25519 key agreement (RFC 7748).
public enum X25519 {

    /// Key size in bytes, for both private scalars and public u-coordinates.
    public static let keySize = 32

    /// Whether the platform has an X25519 implementation available.
    public static var isAvailable: Bool {
        #if canImport(CryptoKit)
        return true
        #else
        return false
        #endif
    }

    /// Generates a new clamped private scalar.
    ///
    /// WireGuard private keys are random 32 byte strings with the standard
    /// X25519 clamping bits applied, which is what this returns.
    ///
    /// - Returns: 32 bytes of private scalar.
    public static func generatePrivateKey() -> [UInt8] {
        #if canImport(CryptoKit)
        var bytes = [UInt8](Curve25519.KeyAgreement.PrivateKey().rawRepresentation)
        return clamp(bytes)
        #else
        var bytes = [UInt8](repeating: 0, count: keySize)
        var generator = SystemRandomNumberGenerator()
        for i in 0 ..< keySize {
            bytes[i] = UInt8.random(in: .min ... .max, using: &generator)
        }
        return clamp(bytes)
        #endif
    }

    /// Applies the X25519 clamping bits (RFC 7748, section 5): clear the low
    /// three bits of the first byte so the scalar is a multiple of the
    /// cofactor, and force the second-highest bit of the last byte.
    ///
    /// WireGuard's own key generator (`wg genkey`) stores clamped keys, so
    /// this makes generated keys byte-for-byte the shape WireGuard produces.
    /// Clamping is also applied internally by the scalar multiplication, so it
    /// does not change any derived public key.
    ///
    /// - Parameter privateKey: 32 bytes of private scalar.
    /// - Returns: The same scalar with the clamping bits applied.
    static func clamp(_ privateKey: [UInt8]) -> [UInt8] {
        guard privateKey.count == keySize else { return privateKey }
        var bytes = privateKey
        bytes[0] &= 248
        bytes[31] = (bytes[31] & 127) | 64
        return bytes
    }

    /// Derives the public u-coordinate for a private scalar.
    ///
    /// - Parameter privateKey: 32 byte private scalar. Clamping is applied by
    ///   the implementation, so an unclamped RFC 7748 test scalar produces the
    ///   RFC's expected output.
    /// - Throws: ``VPNCryptoError/invalidKeySize(expected:actual:)`` if the
    ///   scalar is not 32 bytes, or a platform error.
    /// - Returns: 32 bytes of public key.
    public static func publicKey(for privateKey: [UInt8]) throws -> [UInt8] {
        #if canImport(CryptoKit)
        guard privateKey.count == keySize else {
            throw VPNCryptoError.invalidKeySize(expected: keySize, actual: privateKey.count)
        }
        let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(privateKey))
        return [UInt8](key.publicKey.rawRepresentation)
        #else
        throw VPNCryptoError.unsupportedPlatform("X25519 requires CryptoKit")
        #endif
    }

    /// Performs the X25519 Diffie-Hellman function.
    ///
    /// - Parameters:
    ///   - privateKey: 32 byte private scalar, either side's.
    ///   - publicKey: 32 byte public u-coordinate, the other side's.
    /// - Throws: ``VPNCryptoError`` for wrong key sizes or a public key of
    ///   small order (which would make the shared secret all zeros and must
    ///   never be used as key material).
    /// - Returns: The 32 byte shared secret.
    public static func sharedSecret(privateKey: [UInt8], publicKey: [UInt8]) throws -> [UInt8] {
        #if canImport(CryptoKit)
        guard privateKey.count == keySize else {
            throw VPNCryptoError.invalidKeySize(expected: keySize, actual: privateKey.count)
        }
        guard publicKey.count == keySize else {
            throw VPNCryptoError.invalidKeySize(expected: keySize, actual: publicKey.count)
        }

        let privateScalar = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(privateKey))
        let publicPoint: Curve25519.KeyAgreement.PublicKey
        do {
            publicPoint = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(publicKey))
        } catch {
            throw VPNCryptoError.invalidPublicKey
        }

        let secret: SharedSecret
        do {
            secret = try privateScalar.sharedSecretFromKeyAgreement(with: publicPoint)
        } catch {
            // CryptoKit rejects some small order points outright; others
            // produce an all-zero output.
            throw VPNCryptoError.invalidPublicKey
        }
        let bytes = [UInt8](secret.withUnsafeBytes { Data($0) })
        // RFC 7748 section 6.1 and the WireGuard reference implementation both
        // insist on this check: an all-zero output means the peer sent a point
        // of small order, and that value must never become key material.
        if bytes.allSatisfy({ $0 == 0 }) {
            throw VPNCryptoError.invalidPublicKey
        }
        return bytes
        #else
        throw VPNCryptoError.unsupportedPlatform("X25519 requires CryptoKit")
        #endif
    }
}
