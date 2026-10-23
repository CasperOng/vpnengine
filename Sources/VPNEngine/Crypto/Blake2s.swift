//
//  Blake2s.swift
//  VPNEngine
//
//  BLAKE2s as specified by RFC 7693.
//
//  WireGuard uses BLAKE2s throughout ("Hash" and "Mac" in the whitepaper,
//  section 2.3). Two things about the primitive matter for interoperability:
//
//   1. The digest length is part of the parameter block, so BLAKE2s-128 is
//      *not* BLAKE2s-256 truncated to 16 bytes: it is a different function
//      with a different initialisation vector. WireGuard's `mac1`/`mac2`
//      fields and the cookie are keyed BLAKE2s with a 16 byte digest and a
//      32 byte key.
//   2. When the function is keyed, the key is zero padded to a *full* 64 byte
//      block and that block is compressed first, exactly like a message
//      block, with the byte counter starting at 64.
//

import Foundation

/// BLAKE2s (RFC 7693), the hash function used by the WireGuard protocol.
///
/// The implementation is deliberately straightforward: no SIMD, no unrolling
/// beyond the ten rounds of the compression function. It is fast enough for
/// the handshake rate WireGuard allows (one handshake per peer every few
/// seconds at most) and for the 148 byte handshake messages.
public enum Blake2s {

    /// BLAKE2s processes data in 64 byte blocks.
    public static let blockSize = 64

    /// Largest digest BLAKE2s can produce.
    public static let maxDigestLength = 32

    /// Largest key BLAKE2s accepts.
    public static let maxKeyLength = 32

    // MARK: - One-shot API

    /// Computes an unkeyed BLAKE2s digest.
    ///
    /// - Parameters:
    ///   - data: The message to hash.
    ///   - digestLength: Digest size in bytes, 1...32. Defaults to 32.
    /// - Returns: `digestLength` bytes of digest.
    public static func hash(_ data: [UInt8], digestLength: Int = 32) -> [UInt8] {
        var core = Core(digestLength: digestLength, key: [])
        core.update(data)
        return core.finalize()
    }

    /// Computes an unkeyed BLAKE2s digest of `data`.
    ///
    /// - Parameters:
    ///   - data: The message to hash.
    ///   - digestLength: Digest size in bytes, 1...32. Defaults to 32.
    /// - Returns: `digestLength` bytes of digest.
    public static func hash(_ data: Data, digestLength: Int = 32) -> [UInt8] {
        hash([UInt8](data), digestLength: digestLength)
    }

    /// Computes a keyed BLAKE2s digest.
    ///
    /// This is what the WireGuard whitepaper calls `Mac(key, input)`. Note that
    /// a keyed call is not merely "a hash with a key": the key is padded to a
    /// full 64 byte block and compressed first, which is why
    /// `mac(key: [], data)` differs from `hash(data)`.
    ///
    /// - Parameters:
    ///   - key: Key, 0...32 bytes. Longer keys are truncated to 32 bytes.
    ///   - data: The message to authenticate.
    ///   - digestLength: Digest size in bytes, 1...32. Defaults to 32;
    ///     WireGuard passes 16 for `mac1`, `mac2` and the cookie.
    /// - Returns: `digestLength` bytes of keyed digest.
    public static func mac(key: [UInt8], _ data: [UInt8], digestLength: Int = 32) -> [UInt8] {
        var core = Core(digestLength: digestLength, key: key)
        core.update(data)
        return core.finalize()
    }

    /// Computes a keyed BLAKE2s digest of `data`.
    ///
    /// - Parameters:
    ///   - key: Key, 0...32 bytes. Longer keys are truncated to 32 bytes.
    ///   - data: The message to authenticate.
    ///   - digestLength: Digest size in bytes, 1...32. Defaults to 32.
    /// - Returns: `digestLength` bytes of keyed digest.
    public static func mac(key: [UInt8], _ data: Data, digestLength: Int = 32) -> [UInt8] {
        mac(key: key, [UInt8](data), digestLength: digestLength)
    }

    // MARK: - Constants

    /// The BLAKE2s initialisation vector (RFC 7693, section 2.6): the first
    /// thirty-two bits of the fractional parts of the square roots of the
    /// first eight primes, identical to the SHA-256 IV.
    static let iv: [UInt32] = [
        0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
        0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19,
    ]

    /// Message word permutation schedule (RFC 7693, section 2.7). BLAKE2s
    /// runs ten rounds and therefore uses the first ten rows.
    static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ]

    /// Incremental BLAKE2s state (the `hashlib`-style interface).
    ///
    /// The final block of a BLAKE2s message is compressed with a different
    /// flag to every other block, so the state always holds back at least one
    /// byte (up to a whole block) until ``finalize()`` is called.
    struct Core {

        private var h: [UInt32]

        /// Bytes that have been fed in but not yet compressed.
        private var buffer: [UInt8] = []

        /// Number of bytes covered by blocks that have already been compressed.
        private var compressedBytes: UInt64 = 0

        private let digestLength: Int

        /// Creates a hasher.
        ///
        /// - Parameters:
        ///   - digestLength: Requested digest size, clamped to 1...32.
        ///   - key: Optional key, clamped to the first 32 bytes.
        init(digestLength: Int, key: [UInt8]) {
            let length = Swift.min(Swift.max(digestLength, 1), Blake2s.maxDigestLength)
            let validatedKey = Array(key.prefix(Blake2s.maxKeyLength))
            self.digestLength = length

            // Parameter block, byte 0 packed as: digest length | key length |
            // fanout = 1 | depth = 1 (RFC 7693, section 2.5).
            var parameter = Blake2s.iv
            parameter[0] ^= 0x0101_0000
                ^ (UInt32(validatedKey.count) << 8)
                ^ UInt32(length)
            self.h = parameter

            if !validatedKey.isEmpty {
                // The key is zero padded to a whole 64 byte block and becomes
                // the first *data* block: the reference implementation writes
                // it through the ordinary update path, which means that for an
                // empty message the key block is the final block and carries
                // the finalisation flag. Buffering it here reproduces that
                // exactly.
                var keyBlock = validatedKey
                keyBlock.append(contentsOf: [UInt8](repeating: 0, count: Blake2s.blockSize - validatedKey.count))
                buffer = keyBlock
            }
        }

        /// Absorbs more message bytes.
        ///
        /// - Parameter bytes: The next chunk of the message.
        mutating func update(_ bytes: [UInt8]) {
            guard !bytes.isEmpty else { return }

            var chunk = buffer
            chunk.append(contentsOf: bytes)

            var offset = 0
            // Keep the last (up to) 64 bytes buffered: they may be the final
            // block and therefore need the finalisation flag.
            while chunk.count - offset > Blake2s.blockSize {
                compressedBytes += UInt64(Blake2s.blockSize)
                compress(Array(chunk[offset ..< offset + Blake2s.blockSize]),
                         total: compressedBytes,
                         lastBlock: false)
                offset += Blake2s.blockSize
            }
            buffer = Array(chunk[offset...])
        }

        /// Finishes the digest. The state must not be used afterwards.
        ///
        /// - Returns: The digest truncated to the requested length.
        mutating func finalize() -> [UInt8] {
            var block = buffer
            block.append(contentsOf: [UInt8](repeating: 0, count: Blake2s.blockSize - block.count))
            compressedBytes += UInt64(buffer.count)
            compress(block, total: compressedBytes, lastBlock: true)

            var out: [UInt8] = []
            out.reserveCapacity(32)
            for word in h {
                out.append(UInt8(truncatingIfNeeded: word))
                out.append(UInt8(truncatingIfNeeded: word >> 8))
                out.append(UInt8(truncatingIfNeeded: word >> 16))
                out.append(UInt8(truncatingIfNeeded: word >> 24))
            }
            buffer.removeAll(keepingCapacity: false)
            return Array(out.prefix(digestLength))
        }

        // MARK: Compression function

        /// The BLAKE2s compression function `F` (RFC 7693, section 3.2).
        ///
        /// - Parameters:
        ///   - block: Exactly 64 bytes of message.
        ///   - total: Total number of input bytes including this block; split
        ///     into the two 32 bit halves of the counter `t`.
        ///   - lastBlock: Whether this is the final block (`f0` in the spec).
        private mutating func compress(_ block: [UInt8], total: UInt64, lastBlock: Bool) {
            var v = [UInt32](repeating: 0, count: 16)
            for i in 0 ..< 8 { v[i] = h[i] }
            for i in 0 ..< 8 { v[8 + i] = Blake2s.iv[i] }

            var m = [UInt32](repeating: 0, count: 16)
            for i in 0 ..< 16 {
                let j = i * 4
                m[i] = UInt32(block[j])
                    | UInt32(block[j + 1]) << 8
                    | UInt32(block[j + 2]) << 16
                    | UInt32(block[j + 3]) << 24
            }

            v[12] ^= UInt32(truncatingIfNeeded: total)
            v[13] ^= UInt32(truncatingIfNeeded: total >> 32)
            if lastBlock { v[14] = ~v[14] }

            for round in 0 ..< 10 {
                let s = Blake2s.sigma[round]
                g(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
                g(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
                g(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
                g(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
                g(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
                g(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
                g(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
                g(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
            }

            for i in 0 ..< 8 { h[i] ^= v[i] ^ v[i + 8] }
        }

        /// The BLAKE2s mixing function `G` (RFC 7693, section 3.1).
        ///
        /// - Parameters:
        ///   - v: The 16 word working vector, modified in place.
        ///   - a: Index of the first word.
        ///   - b: Index of the second word.
        ///   - c: Index of the third word.
        ///   - d: Index of the fourth word.
        ///   - x: First message word to mix in.
        ///   - y: Second message word to mix in.
        private func g(_ v: inout [UInt32],
                       _ a: Int, _ b: Int, _ c: Int, _ d: Int,
                       _ x: UInt32, _ y: UInt32) {
            v[a] = v[a] &+ v[b] &+ x
            v[d] = rotateRight(v[d] ^ v[a], by: 16)
            v[c] = v[c] &+ v[d]
            v[b] = rotateRight(v[b] ^ v[c], by: 12)
            v[a] = v[a] &+ v[b] &+ y
            v[d] = rotateRight(v[d] ^ v[a], by: 8)
            v[c] = v[c] &+ v[d]
            v[b] = rotateRight(v[b] ^ v[c], by: 7)
        }

        /// Rotates a 32 bit word right (RFC 7693 uses right rotations of 16,
        /// 12, 8 and 7 bits in `G`).
        private func rotateRight(_ value: UInt32, by amount: UInt32) -> UInt32 {
            (value >> amount) | (value << (32 - amount))
        }
    }
}
