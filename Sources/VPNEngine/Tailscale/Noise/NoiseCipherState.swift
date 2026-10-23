//
//  NoiseCipherState.swift
//  VPNEngine
//
//  The Noise `CipherState` object (Noise Protocol Framework, revision 34,
//  section 5.1) instantiated for the `ChaChaPoly` cipher functions.
//
//  This is the object a completed Noise handshake hands out: ``split()`` on
//  ``NoiseIKHandshake`` produces two of them, one per direction, and every
//  record after the handshake is sealed with one and opened with the other.
//
//  Two details in here are load bearing for interoperability and are the
//  classic place an implementation goes wrong:
//
//   1. **The nonce.** Noise encodes the 64 bit counter into the AEAD nonce as
//      *four zero bytes followed by the little endian counter*:
//
//          ENCRYPT(k, n, ad, plaintext): "AEAD_CHACHA20_POLY1305 from [RFC
//          7539]. The 96-bit nonce is formed by encoding 32 bits of zeros
//          followed by little-endian encoding of n."
//              - Noise spec, section 12.3
//
//      This is easy to get backwards, because RFC 8439's own worked examples
//      split a 96 bit nonce into a 32 bit block counter and a 64 bit nonce
//      inside the ChaCha state. Noise does not do that: the whole 64 bit value
//      is the counter, it occupies the *last* eight bytes of the nonce, and it
//      starts at zero rather than one, because Noise performs one AEAD
//      operation per nonce instead of a stream with a block counter of its
//      own.
//
//   2. **The reserved nonce.** The value 2^64 - 1 is reserved for `REKEY`
//      (Noise spec, section 4.2), so a `CipherState` must refuse to encrypt or
//      decrypt once `n` reaches it rather than wrapping around and reusing a
//      nonce with a key.
//
//  References:
//   * Noise Protocol Framework, revision 34: https://noiseprotocol.org/noise.html
//   * RFC 8439 (ChaCha20-Poly1305)
//

import Foundation

/// One direction of a Noise `CipherState`: a 32 byte key, a 64 bit nonce
/// counter, and the two operations that use them.
///
/// A `CipherState` is *not* thread safe; the transport that owns it serialises
/// access. It is marked `@unchecked Sendable` so it can be stored in a
/// `Sendable` transport that does that serialisation itself.
public final class NoiseCipherState: @unchecked Sendable {

    // MARK: - Constants

    /// Key size in bytes, fixed by `ChaChaPoly`.
    public static let keySize = 32

    /// Authentication tag size in bytes.
    public static let tagSize = ChaCha20Poly1305.tagSize

    /// AEAD nonce size in bytes.
    public static let nonceSize = ChaCha20Poly1305.nonceSize

    /// The nonce reserved for ``rekey()``: 2^64 - 1 (Noise spec, section 4.2).
    public static let reservedNonce: UInt64 = .max

    /// The largest number of ciphertext bytes one `encryptWithAd` call can
    /// produce, given that ``reservedNonce`` is never usable.
    public static let maxMessages: UInt64 = .max

    // MARK: - State

    /// The key, or `nil` for a `CipherState` with no key.
    ///
    /// Noise allows a keyless `CipherState` whose `EncryptWithAd` and
    /// `DecryptWithAd` are the identity function. No handshake this package
    /// implements ever leaves one keyless, but the object models it so the
    /// behaviour is specified rather than undefined.
    private var key: [UInt8]?

    /// The nonce counter, `n` in the spec.
    public private(set) var nonceCounter: UInt64 = 0

    // MARK: - Creation

    /// Creates a keyless `CipherState`.
    ///
    /// `encryptWithAd` returns its input unchanged and `decryptWithAd` does
    /// likewise, per Noise spec section 5.1 ("If `k` is non-empty returns
    /// `ENCRYPT(k, n++, ad, plaintext)`. Otherwise returns `plaintext`").
    public init() {
        self.key = nil
    }

    /// Creates a `CipherState` with a key.
    ///
    /// - Parameter key: Exactly 32 bytes.
    /// - Throws: ``VPNCryptoError/invalidKeySize(expected:actual:)`` when the
    ///   key is not 32 bytes.
    public init(key: Data) throws {
        guard key.count == NoiseCipherState.keySize else {
            throw VPNCryptoError.invalidKeySize(expected: NoiseCipherState.keySize,
                                                actual: key.count)
        }
        self.key = [UInt8](key)
    }

    /// Creates a `CipherState` from a key that is already the right size.
    ///
    /// - Parameter key: Exactly 32 bytes; the caller has checked.
    init(checkedKey key: [UInt8]) {
        self.key = key
    }

    // MARK: - Queries

    /// Whether this state has a key. A keyless state passes data through.
    public var hasKey: Bool { key != nil }

    /// The key, for tests and for ``rekey()``. Never log this value.
    var keyBytes: [UInt8] { key ?? [] }

    /// The twelve byte AEAD nonce that encodes a Noise counter.
    ///
    /// - Parameter counter: The 64 bit Noise nonce.
    /// - Returns: `00 00 00 00 || little endian counter` (Noise spec,
    ///   section 12.3).
    public static func nonceBytes(for counter: UInt64) -> [UInt8] {
        var nonce = [UInt8](repeating: 0, count: nonceSize)
        for index in 0 ..< 8 {
            nonce[4 + index] = UInt8(truncatingIfNeeded: counter >> (8 * index))
        }
        return nonce
    }

    // MARK: - Encryption

    /// Noise's `EncryptWithAd(ad, plaintext)`.
    ///
    /// - Parameters:
    ///   - plaintext: The data to seal.
    ///   - authenticatedData: Additional data that is authenticated but not
    ///     encrypted. The control protocol passes an empty value.
    /// - Throws: ``VPNCryptoError`` when the nonce is exhausted or the AEAD
    ///   fails.
    /// - Returns: Ciphertext followed by the 16 byte tag, or `plaintext` when
    ///   this state has no key.
    public func encryptWithAd(_ plaintext: Data, ad authenticatedData: Data = Data()) throws -> Data {
        guard let key else { return plaintext }
        guard nonceCounter != NoiseCipherState.reservedNonce else {
            throw VPNCryptoError.invalidState("the Noise nonce is exhausted; the key must be rekeyed")
        }
        let sealed = try ChaChaPolyAEAD.seal(key: key,
                                             nonce: NoiseCipherState.nonceBytes(for: nonceCounter),
                                             plaintext: [UInt8](plaintext),
                                             authenticatedData: [UInt8](authenticatedData))
        nonceCounter += 1
        return Data(sealed)
    }

    /// Noise's `DecryptWithAd(ad, ciphertext)`.
    ///
    /// - Parameters:
    ///   - ciphertext: Ciphertext followed by the 16 byte tag.
    ///   - authenticatedData: The same additional data passed to
    ///     ``encryptWithAd(_:ad:)``.
    /// - Throws: ``VPNCryptoError/authenticationFailure`` when the tag does not
    ///   verify, or ``VPNCryptoError`` when the nonce is exhausted. The nonce
    ///   is not incremented on failure, as the spec requires.
    /// - Returns: The plaintext, or `ciphertext` when this state has no key.
    public func decryptWithAd(_ ciphertext: Data, ad authenticatedData: Data = Data()) throws -> Data {
        guard let key else { return ciphertext }
        guard nonceCounter != NoiseCipherState.reservedNonce else {
            throw VPNCryptoError.invalidState("the Noise nonce is exhausted; the key must be rekeyed")
        }
        let plaintext = try ChaChaPolyAEAD.open(key: key,
                                                nonce: NoiseCipherState.nonceBytes(for: nonceCounter),
                                                ciphertext: [UInt8](ciphertext),
                                                authenticatedData: [UInt8](authenticatedData))
        nonceCounter += 1
        return Data(plaintext)
    }

    // MARK: - Rekey

    /// Noise's `Rekey()`: `k = REKEY(k)`.
    ///
    /// The counter is deliberately *not* reset: the spec defines `Rekey()` as
    /// "Sets `k = REKEY(k)`" and nothing more (Noise spec, section 5.1).
    ///
    /// - Throws: ``VPNCryptoError`` when this state has no key.
    public func rekey() throws {
        guard let key else {
            throw VPNCryptoError.invalidState("a keyless CipherState cannot be rekeyed")
        }
        self.key = [UInt8](try NoiseCipherState.rekeyedKey(Data(key)))
    }

    /// Noise's `REKEY(k)`.
    ///
    /// > Returns a new 32-byte cipher key as a pseudorandom function of `k`.
    /// > If this function is not specifically defined for some set of cipher
    /// > functions, then it defaults to returning the first 32 bytes from
    /// > `ENCRYPT(k, maxnonce, zerolen, zeros)`, where `maxnonce` equals
    /// > 2^64-1, `zerolen` is a zero-length byte sequence, and `zeros` is a
    /// > sequence of 32 bytes filled with zeros.
    /// >
    /// > - Noise spec, section 4.2
    ///
    /// - Parameter key: The current key, 32 bytes.
    /// - Throws: ``VPNCryptoError`` for a bad key size or a failed seal.
    /// - Returns: The next key, 32 bytes.
    public static func rekeyedKey(_ key: Data) throws -> Data {
        let sealed = try ChaChaPolyAEAD.seal(key: [UInt8](key),
                                             nonce: nonceBytes(for: reservedNonce),
                                             plaintext: [UInt8](repeating: 0, count: keySize),
                                             authenticatedData: [])
        return Data(sealed.prefix(keySize))
    }
}
