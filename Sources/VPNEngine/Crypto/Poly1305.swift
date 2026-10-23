//
//  Poly1305.swift
//  VPNEngine
//
//  Poly1305 one-time authenticator (RFC 8439, section 2.5).
//
//  The AEAD used by WireGuard is ChaCha20-Poly1305; on Apple platforms the AEAD
//  is supplied by CryptoKit (see ``ChaChaPolyAEAD``), but the raw authenticator
//  is implemented here so that the AEAD construction can be verified against the
//  published test vectors and so that the library keeps working on platforms
//  without CryptoKit. CryptoKit does not expose bare Poly1305.
//
//  The arithmetic is the classic "donna" 5 x 26 bit limb representation: the
//  accumulator h and the clamped key r are held as five 26 bit limbs, products
//  are accumulated in 64 bit words, and carries are folded back into the limbs
//  after every block. r is clamped to 2^124 - 1 style values by the
//  specification, so no limb is ever more than 26 + a few bits wide.
//

import Foundation

/// Poly1305 (RFC 8439, section 2.5).
public struct Poly1305 {

    /// Size of a Poly1305 key in bytes.
    public static let keySize = 32

    /// Size of the authentication tag in bytes.
    public static let tagSize = 16

    /// Block size in bytes.
    public static let blockSize = 16

    /// Five 26 bit limbs of the accumulator.
    private var h: [UInt64] = [0, 0, 0, 0, 0]

    /// Five 26 bit limbs of the clamped key `r`.
    private let r: [UInt64]

    /// The 128 bit `s` half of the key, as one 32 bit word per limb.
    private let pad: [UInt32]

    /// Bytes buffered until a full block is available.
    private var buffer: [UInt8] = []

    /// Creates an authenticator from a one-time key.
    ///
    /// - Parameter key: 32 byte one-time key: the first 16 bytes are `r`
    ///   (clamped as the specification requires), the last 16 bytes are `s`.
    /// - Returns: `nil` if the key is not exactly 32 bytes.
    public init?(key: [UInt8]) {
        guard key.count == Poly1305.keySize else { return nil }

        // r = little endian bytes 0..15, clamped so that it fits the
        // 2^130 - 5 arithmetic. The masks below are the standard decomposition
        // of `r &= 0x0ffffffc0ffffffc0ffffffc0fffffff` into five 26 bit limbs,
        // read as overlapping 32 bit little endian words exactly as the
        // reference implementation of Poly1305 does.
        let words = (0 ..< 5).map { index -> UInt64 in
            let base = index * 3
            return UInt64(key[base])
                | UInt64(key[base + 1]) << 8
                | UInt64(key[base + 2]) << 16
                | UInt64(key[base + 3]) << 24
        }

        self.r = [
            words[0] & 0x3FF_FFFF,
            (words[1] >> 2) & 0x3FF_FF03,
            (words[2] >> 4) & 0x3FF_C0FF,
            (words[3] >> 6) & 0x3F0_3FFF,
            (words[4] >> 8) & 0x00F_FFFF,
        ]

        self.pad = [
            UInt32(key[16]) | UInt32(key[17]) << 8 | UInt32(key[18]) << 16 | UInt32(key[19]) << 24,
            UInt32(key[20]) | UInt32(key[21]) << 8 | UInt32(key[22]) << 16 | UInt32(key[23]) << 24,
            UInt32(key[24]) | UInt32(key[25]) << 8 | UInt32(key[26]) << 16 | UInt32(key[27]) << 24,
            UInt32(key[28]) | UInt32(key[29]) << 8 | UInt32(key[30]) << 16 | UInt32(key[31]) << 24,
        ]
    }

    /// Absorbs more message bytes.
    ///
    /// - Parameter bytes: The next chunk of the message.
    public mutating func update(_ bytes: [UInt8]) {
        guard !bytes.isEmpty else { return }

        var chunk = buffer
        chunk.append(contentsOf: bytes)

        var offset = 0
        while chunk.count - offset >= Poly1305.blockSize {
            absorb(Array(chunk[offset ..< offset + Poly1305.blockSize]), addHighBit: true)
            offset += Poly1305.blockSize
        }
        buffer = Array(chunk[offset...])
    }

    /// Finishes the tag. The state must not be used afterwards.
    ///
    /// - Returns: The 16 byte Poly1305 tag.
    public mutating func finalize() -> [UInt8] {
        if !buffer.isEmpty {
            var finalBlock = buffer
            // The final (partial) block is padded with a single 1 byte and then
            // zero bytes. This supplies the 2^(8 * length) bit; the 2^128 bit
            // is *not* added for this block (RFC 8439, section 2.5.1).
            finalBlock.append(1)
            finalBlock.append(contentsOf: [UInt8](repeating: 0, count: Poly1305.blockSize - finalBlock.count))
            absorb(finalBlock, addHighBit: false)
            buffer = []
        }

        // Fully carry h.
        var carry = h[1] >> 26; h[1] &= 0x3FF_FFFF; h[2] &+= carry
        carry = h[2] >> 26; h[2] &= 0x3FF_FFFF; h[3] &+= carry
        carry = h[3] >> 26; h[3] &= 0x3FF_FFFF; h[4] &+= carry
        carry = h[4] >> 26; h[4] &= 0x3FF_FFFF; h[0] &+= carry * 5
        carry = h[0] >> 26; h[0] &= 0x3FF_FFFF; h[1] &+= carry

        // Compute h + -p (i.e. h + 5 - 2^130) and select it if h >= p.
        var g = [UInt64](repeating: 0, count: 5)
        var c = h[0] + 5
        g[0] = c & 0x3FF_FFFF; c >>= 26
        c &+= h[1]; g[1] = c & 0x3FF_FFFF; c >>= 26
        c &+= h[2]; g[2] = c & 0x3FF_FFFF; c >>= 26
        c &+= h[3]; g[3] = c & 0x3FF_FFFF; c >>= 26
        c &+= h[4]
        g[4] = c &- (1 << 26)

        // If the subtraction borrowed, bit 63 is set and `mask` becomes zero.
        let mask = (g[4] >> 63) &- 1
        let inverted = ~mask
        for i in 0 ..< 5 {
            h[i] = (h[i] & inverted) | (g[i] & mask)
        }

        // h = (h + s) mod 2^128, serialised little endian.
        var words = [UInt32](repeating: 0, count: 4)
        words[0] = UInt32(truncatingIfNeeded: h[0] | (h[1] << 26))
        words[1] = UInt32(truncatingIfNeeded: (h[1] >> 6) | (h[2] << 20))
        words[2] = UInt32(truncatingIfNeeded: (h[2] >> 12) | (h[3] << 14))
        words[3] = UInt32(truncatingIfNeeded: (h[3] >> 18) | (h[4] << 8))

        var carry64: UInt64 = 0
        var tag = [UInt8](repeating: 0, count: Poly1305.tagSize)
        for i in 0 ..< 4 {
            let sum = UInt64(words[i]) &+ UInt64(pad[i]) &+ carry64
            let word = UInt32(truncatingIfNeeded: sum)
            carry64 = sum >> 32
            tag[i * 4] = UInt8(truncatingIfNeeded: word)
            tag[i * 4 + 1] = UInt8(truncatingIfNeeded: word >> 8)
            tag[i * 4 + 2] = UInt8(truncatingIfNeeded: word >> 16)
            tag[i * 4 + 3] = UInt8(truncatingIfNeeded: word >> 24)
        }
        return tag
    }

    /// One-shot convenience wrapper.
    ///
    /// - Parameters:
    ///   - key: 32 byte one-time key.
    ///   - message: The message to authenticate.
    /// - Returns: The 16 byte tag, or `nil` if the key size is wrong.
    public static func tag(key: [UInt8], message: [UInt8]) -> [UInt8]? {
        guard var state = Poly1305(key: key) else { return nil }
        state.update(message)
        return state.finalize()
    }

    // MARK: - Internals

    /// Absorbs exactly one block.
    ///
    /// - Parameters:
    ///   - block: Exactly 16 bytes; the caller has already applied the padding
    ///     rule for a final partial block.
    ///   - addHighBit: Whether to add the 2^128 bit. This is the case for every
    ///     full block of the message, and never for a padded final block.
    private mutating func absorb(_ block: [UInt8], addHighBit: Bool) {
        let t0 = UInt64(block[0]) | UInt64(block[1]) << 8 | UInt64(block[2]) << 16 | UInt64(block[3]) << 24
        let t1 = UInt64(block[4]) | UInt64(block[5]) << 8 | UInt64(block[6]) << 16 | UInt64(block[7]) << 24
        let t2 = UInt64(block[8]) | UInt64(block[9]) << 8 | UInt64(block[10]) << 16 | UInt64(block[11]) << 24
        let t3 = UInt64(block[12]) | UInt64(block[13]) << 8 | UInt64(block[14]) << 16 | UInt64(block[15]) << 24

        var m = [UInt64](repeating: 0, count: 5)
        m[0] = t0 & 0x3FF_FFFF
        m[1] = ((t0 >> 26) | (t1 << 6)) & 0x3FF_FFFF
        m[2] = ((t1 >> 20) | (t2 << 12)) & 0x3FF_FFFF
        m[3] = ((t2 >> 14) | (t3 << 18)) & 0x3FF_FFFF
        m[4] = addHighBit ? (t3 >> 8) | (1 << 24) : (t3 >> 8)

        h[0] &+= m[0]
        h[1] &+= m[1]
        h[2] &+= m[2]
        h[3] &+= m[3]
        h[4] &+= m[4]

        // h *= r  (mod 2^130 - 5), using r5..r1 * 5 for the wrapped terms.
        let s1 = r[1] * 5
        let s2 = r[2] * 5
        let s3 = r[3] * 5
        let s4 = r[4] * 5

        let d0 = h[0] * r[0] &+ h[1] * s4 &+ h[2] * s3 &+ h[3] * s2 &+ h[4] * s1
        var d1 = h[0] * r[1] &+ h[1] * r[0] &+ h[2] * s4 &+ h[3] * s3 &+ h[4] * s2
        var d2 = h[0] * r[2] &+ h[1] * r[1] &+ h[2] * r[0] &+ h[3] * s4 &+ h[4] * s3
        var d3 = h[0] * r[3] &+ h[1] * r[2] &+ h[2] * r[1] &+ h[3] * r[0] &+ h[4] * s4
        var d4 = h[0] * r[4] &+ h[1] * r[3] &+ h[2] * r[2] &+ h[3] * r[1] &+ h[4] * r[0]

        var carry = d0 >> 26; h[0] = d0 & 0x3FF_FFFF
        d1 &+= carry; carry = d1 >> 26; h[1] = d1 & 0x3FF_FFFF
        d2 &+= carry; carry = d2 >> 26; h[2] = d2 & 0x3FF_FFFF
        d3 &+= carry; carry = d3 >> 26; h[3] = d3 & 0x3FF_FFFF
        d4 &+= carry; carry = d4 >> 26; h[4] = d4 & 0x3FF_FFFF
        h[0] &+= carry * 5; carry = h[0] >> 26; h[0] &= 0x3FF_FFFF
        h[1] &+= carry
    }
}
