//
//  WireGuardKDF.swift
//  VPNEngine
//
//  The WireGuard key derivation function (whitepaper, section 2.3):
//
//      Hmac(key, input)    := Hmac-Blake2s(key, input, 32)
//      Kdf_n(key, input):  Sets tau_0 := Hmac(key, input),
//                                tau_1 := Hmac(tau_0, 0x1),
//                                tau_i := Hmac(tau_0, tau_(i-1) || i)
//                                and returns the n-tuple (tau_1, ..., tau_n).
//
//  Two details are easy to get wrong and both are load bearing for
//  interoperability:
//
//   1. `Hmac` here is the *ordinary* HMAC construction of RFC 2104 with
//      BLAKE2s-256 as the hash function and a 64 byte block size. It is not
//      BLAKE2s in keyed mode, and it is not "keyed BLAKE2s twice".
//   2. KDF1 is a two stage HMAC: the first HMAC produces the pseudo random
//      key, the second HMACs the counter byte 0x1 with that key.
//
//  The test suite pins both against the vectors published with the reference
//  implementation, so any change here is caught immediately.
//

import Foundation

/// The HKDF style key derivation function used throughout the WireGuard handshake.
public enum WireGuardKDF {

    /// The hash function's block size, which is what HMAC pads its key to.
    static let hmacBlockSize = 64

    /// HMAC-BLAKE2s (RFC 2104 with BLAKE2s-256 as the hash function).
    ///
    /// - Parameters:
    ///   - key: The HMAC key. Keys longer than 64 bytes are hashed first, as
    ///     RFC 2104 requires. HMAC keys here are always 32 byte chaining keys.
    ///   - input: The message to authenticate.
    /// - Returns: 32 bytes of MAC.
    static func hmac(key: [UInt8], input: [UInt8]) -> [UInt8] {
        var paddedKey = key.count > hmacBlockSize ? Blake2s.hash(key) : key
        if paddedKey.count < hmacBlockSize {
            paddedKey.append(contentsOf: [UInt8](repeating: 0, count: hmacBlockSize - paddedKey.count))
        }

        var innerPad = [UInt8](repeating: 0x36, count: hmacBlockSize)
        var outerPad = [UInt8](repeating: 0x5C, count: hmacBlockSize)
        for i in 0 ..< hmacBlockSize {
            innerPad[i] ^= paddedKey[i]
            outerPad[i] ^= paddedKey[i]
        }

        let inner = Blake2s.hash(innerPad + input)
        return Blake2s.hash(outerPad + inner)
    }

    /// `Kdf1(key, input)`: a single 32 byte output.
    ///
    /// - Parameters:
    ///   - key: The chaining key.
    ///   - input: The input key material, typically a DH result.
    /// - Returns: 32 bytes.
    public static func kdf1(key: [UInt8], input: [UInt8]) -> [UInt8] {
        let pseudoRandomKey = hmac(key: key, input: input)
        return hmac(key: pseudoRandomKey, input: [0x01])
    }

    /// `Kdf2(key, input)`: two 32 byte outputs.
    ///
    /// - Parameters:
    ///   - key: The chaining key.
    ///   - input: The input key material, typically a DH result.
    /// - Returns: The two 32 byte outputs `(tau_1, tau_2)`.
    public static func kdf2(key: [UInt8], input: [UInt8]) -> ([UInt8], [UInt8]) {
        let pseudoRandomKey = hmac(key: key, input: input)
        let first = hmac(key: pseudoRandomKey, input: [0x01])
        let second = hmac(key: pseudoRandomKey, input: first + [0x02])
        return (first, second)
    }

    /// `Kdf3(key, input)`: three 32 byte outputs.
    ///
    /// The third output is the AEAD key used for the handshake response's
    /// `empty` field when the input is the preshared key (the `MixKeyAndHash`
    /// step of the Noise `IKpsk2` pattern); the second output is mixed into the
    /// handshake hash.
    ///
    /// - Parameters:
    ///   - key: The chaining key.
    ///   - input: The input key material. WireGuard always passes the
    ///     preshared key, using 32 zero bytes when none is configured.
    /// - Returns: The three 32 byte outputs `(tau_1, tau_2, tau_3)`.
    public static func kdf3(key: [UInt8], input: [UInt8]) -> ([UInt8], [UInt8], [UInt8]) {
        let pseudoRandomKey = hmac(key: key, input: input)
        let first = hmac(key: pseudoRandomKey, input: [0x01])
        let second = hmac(key: pseudoRandomKey, input: first + [0x02])
        let third = hmac(key: pseudoRandomKey, input: second + [0x03])
        return (first, second, third)
    }
}
