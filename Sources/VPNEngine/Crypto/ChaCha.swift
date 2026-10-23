//
//  ChaCha.swift
//  VPNEngine
//
//  ChaCha20 and HChaCha20.
//
//  WireGuard (whitepaper, section 2.3) uses ChaCha20-Poly1305 as the AEAD for
//  every encrypted field, with the IETF 96 bit nonce for transport data and
//  handshake fields and the extended 192 bit nonce (XChaCha20-Poly1305) for the
//  cookie reply message. HChaCha20 is only needed to build the latter.
//
//  References:
//   * RFC 8439, section 2.3 (ChaCha20 block function)
//   * draft-irtf-cfrg-xchacha-03, section 2.2 (HChaCha20)
//

import Foundation

/// The ChaCha20 stream cipher (RFC 8439).
public enum ChaCha20 {

    /// Required key size in bytes.
    public static let keySize = 32

    /// Required nonce size in bytes (the IETF variant).
    public static let nonceSize = 12

    /// Number of keystream bytes produced per block.
    public static let blockSize = 64

    /// The "expand 32-byte k" constants, serialised little endian.
    private static let constants: [UInt32] = [0x6170_7865, 0x3320_646E, 0x7962_2D32, 0x6B20_6574]

    /// Produces one 64 byte keystream block (RFC 8439, section 2.3.2).
    ///
    /// - Parameters:
    ///   - key: 32 byte key.
    ///   - counter: Block counter, encoded into word 12.
    ///   - nonce: 12 byte nonce, encoded into words 13...15.
    /// - Returns: 64 bytes of keystream, or `nil` if a size is wrong.
    public static func block(key: [UInt8], counter: UInt32, nonce: [UInt8]) -> [UInt8]? {
        guard key.count == keySize, nonce.count == nonceSize else { return nil }

        var state = [UInt32](repeating: 0, count: 16)
        state[0] = constants[0]
        state[1] = constants[1]
        state[2] = constants[2]
        state[3] = constants[3]
        for i in 0 ..< 8 {
            state[4 + i] = load32(key, i * 4)
        }
        state[12] = counter
        for i in 0 ..< 3 {
            state[13 + i] = load32(nonce, i * 4)
        }

        var working = state

        // Twenty rounds: ten column rounds interleaved with ten diagonal rounds.
        for _ in 0 ..< 10 {
            quarterRound(&working, 0, 4, 8, 12)
            quarterRound(&working, 1, 5, 9, 13)
            quarterRound(&working, 2, 6, 10, 14)
            quarterRound(&working, 3, 7, 11, 15)
            quarterRound(&working, 0, 5, 10, 15)
            quarterRound(&working, 1, 6, 11, 12)
            quarterRound(&working, 2, 7, 8, 13)
            quarterRound(&working, 3, 4, 9, 14)
        }

        var out = [UInt8](repeating: 0, count: blockSize)
        for i in 0 ..< 16 {
            store32(working[i] &+ state[i], into: &out, at: i * 4)
        }
        return out
    }

    /// XORs `data` with the ChaCha20 keystream (RFC 8439, section 2.4).
    ///
    /// Encryption and decryption are the same operation.
    ///
    /// - Parameters:
    ///   - key: 32 byte key.
    ///   - nonce: 12 byte nonce.
    ///   - counter: Initial block counter; RFC 8439 uses 1 for message data so
    ///     that block 0 can supply the Poly1305 one-time key.
    ///   - data: The plaintext or ciphertext.
    /// - Returns: The transformed bytes, or `nil` if a key/nonce size is wrong.
    public static func xor(key: [UInt8],
                           nonce: [UInt8],
                           counter: UInt32 = 0,
                           data: [UInt8]) -> [UInt8]? {
        guard key.count == keySize, nonce.count == nonceSize else { return nil }

        var out = data
        var blockCounter = counter
        var offset = 0
        while offset < data.count {
            guard let keystream = block(key: key, counter: blockCounter, nonce: nonce) else { return nil }
            let count = Swift.min(blockSize, data.count - offset)
            for i in 0 ..< count {
                out[offset + i] = data[offset + i] ^ keystream[i]
            }
            offset += count
            blockCounter = blockCounter &+ 1
        }
        return out
    }

    // MARK: - Helpers

    /// One ChaCha quarter round (RFC 8439, section 2.1).
    private static func quarterRound(_ state: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        state[a] = state[a] &+ state[b]
        state[d] = rotateLeft(state[d] ^ state[a], by: 16)
        state[c] = state[c] &+ state[d]
        state[b] = rotateLeft(state[b] ^ state[c], by: 12)
        state[a] = state[a] &+ state[b]
        state[d] = rotateLeft(state[d] ^ state[a], by: 8)
        state[c] = state[c] &+ state[d]
        state[b] = rotateLeft(state[b] ^ state[c], by: 7)
    }

    private static func rotateLeft(_ value: UInt32, by amount: UInt32) -> UInt32 {
        (value << amount) | (value >> (32 - amount))
    }

    private static func load32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | UInt32(bytes[offset + 1]) << 8
            | UInt32(bytes[offset + 2]) << 16
            | UInt32(bytes[offset + 3]) << 24
    }

    private static func store32(_ value: UInt32, into bytes: inout [UInt8], at offset: Int) {
        bytes[offset] = UInt8(truncatingIfNeeded: value)
        bytes[offset + 1] = UInt8(truncatingIfNeeded: value >> 8)
        bytes[offset + 2] = UInt8(truncatingIfNeeded: value >> 16)
        bytes[offset + 3] = UInt8(truncatingIfNeeded: value >> 24)
    }
}

/// HChaCha20 (draft-irtf-cfrg-xchacha-03, section 2.2).
///
/// HChaCha20 is the ChaCha20 block function with one notable difference: the
/// feed-forward addition of the input state is omitted and the output is made
/// from the first and last rows only, yielding a 256 bit subkey from a 256 bit
/// key and a 128 bit nonce. Its only use here is deriving the subkey for
/// XChaCha20-Poly1305.
public enum HChaCha20 {

    /// Required nonce size in bytes.
    public static let nonceSize = 16

    /// Derives the 32 byte HChaCha20 subkey.
    ///
    /// - Parameters:
    ///   - key: 32 byte key.
    ///   - nonce: 16 byte nonce.
    /// - Returns: 32 bytes of subkey, or `nil` if a size is wrong.
    public static func subkey(key: [UInt8], nonce: [UInt8]) -> [UInt8]? {
        guard key.count == ChaCha20.keySize, nonce.count == nonceSize else { return nil }

        var state = [UInt32](repeating: 0, count: 16)
        state[0] = 0x6170_7865
        state[1] = 0x3320_646E
        state[2] = 0x7962_2D32
        state[3] = 0x6B20_6574
        for i in 0 ..< 8 {
            state[4 + i] = load32(key, i * 4)
        }
        for i in 0 ..< 4 {
            state[12 + i] = load32(nonce, i * 4)
        }

        // Twenty rounds, no feed-forward addition.
        for _ in 0 ..< 10 {
            quarterRound(&state, 0, 4, 8, 12)
            quarterRound(&state, 1, 5, 9, 13)
            quarterRound(&state, 2, 6, 10, 14)
            quarterRound(&state, 3, 7, 11, 15)
            quarterRound(&state, 0, 5, 10, 15)
            quarterRound(&state, 1, 6, 11, 12)
            quarterRound(&state, 2, 7, 8, 13)
            quarterRound(&state, 3, 4, 9, 14)
        }

        // Only words 0...3 and 12...15 are serialised, little endian.
        var out = [UInt8](repeating: 0, count: 32)
        for i in 0 ..< 4 {
            store32(state[i], into: &out, at: i * 4)
            store32(state[12 + i], into: &out, at: 16 + i * 4)
        }
        return out
    }

    // MARK: - Helpers

    private static func quarterRound(_ state: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        state[a] = state[a] &+ state[b]
        state[d] = rotateLeft(state[d] ^ state[a], by: 16)
        state[c] = state[c] &+ state[d]
        state[b] = rotateLeft(state[b] ^ state[c], by: 12)
        state[a] = state[a] &+ state[b]
        state[d] = rotateLeft(state[d] ^ state[a], by: 8)
        state[c] = state[c] &+ state[d]
        state[b] = rotateLeft(state[b] ^ state[c], by: 7)
    }

    private static func rotateLeft(_ value: UInt32, by amount: UInt32) -> UInt32 {
        (value << amount) | (value >> (32 - amount))
    }

    private static func load32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | UInt32(bytes[offset + 1]) << 8
            | UInt32(bytes[offset + 2]) << 16
            | UInt32(bytes[offset + 3]) << 24
    }

    private static func store32(_ value: UInt32, into bytes: inout [UInt8], at offset: Int) {
        bytes[offset] = UInt8(truncatingIfNeeded: value)
        bytes[offset + 1] = UInt8(truncatingIfNeeded: value >> 8)
        bytes[offset + 2] = UInt8(truncatingIfNeeded: value >> 16)
        bytes[offset + 3] = UInt8(truncatingIfNeeded: value >> 24)
    }
}
