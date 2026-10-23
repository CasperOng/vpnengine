//
//  Blake2sAndKdfTests.swift
//  VPNEngineTests
//
//  BLAKE2s, the WireGuard KDF and TAI64N timestamps, against the published
//  vectors in ``TestVectors``.
//

import XCTest
@testable import VPNEngine

final class Blake2sTests: XCTestCase {

    func testUnkeyedVectors() {
        XCTAssertHexEqual(Blake2s.hash([]), TestVectors.blake2s256Empty, "BLAKE2s-256 of the empty message")
        XCTAssertHexEqual(Blake2s.hash(Array("abc".utf8)), TestVectors.blake2s256Abc, "BLAKE2s-256 of 'abc'")
    }

    /// A message that is exactly one block long must still be compressed as the
    /// final block, and a longer message must compress all but its last block
    /// without the finalisation flag.
    func testBlockBoundaries() {
        XCTAssertHexEqual(Blake2s.hash(hexBytes(TestVectors.blake2sKeyedInput64Input)),
                          TestVectors.blake2s256Input64,
                          "BLAKE2s-256 of 64 bytes")
        XCTAssertHexEqual(Blake2s.hash(hexBytes(TestVectors.blake2sKeyedInput128Input)),
                          TestVectors.blake2s256Input128,
                          "BLAKE2s-256 of 128 bytes")
    }

    /// The digest length is part of the parameter block, so a 16 byte digest is
    /// a different function, not a prefix of the 32 byte one. WireGuard relies
    /// on this for `mac1`, `mac2` and the cookie.
    func testDigestLengthIsNotTruncation() {
        XCTAssertHexEqual(Blake2s.hash([], digestLength: 16),
                          TestVectors.blake2s128Empty,
                          "BLAKE2s-128 of the empty message")
        XCTAssertHexEqual(Blake2s.hash(Array("abc".utf8), digestLength: 16),
                          TestVectors.blake2s128Abc,
                          "BLAKE2s-128 of 'abc'")

        let truncated = Array(Blake2s.hash(Array("abc".utf8)).prefix(16))
        XCTAssertNotEqual(hexString(truncated),
                          TestVectors.blake2s128Abc,
                          "BLAKE2s-128 must not equal a truncated BLAKE2s-256")
    }

    /// The official BLAKE2 known answer tests, whose key is a full 32 bytes.
    func testKeyedVectors() {
        let key = hexBytes(TestVectors.blake2sKatKey)
        let cases: [(input: String, expected: String)] = [
            (TestVectors.blake2sKeyedEmptyInput, TestVectors.blake2sKeyedEmptyHash),
            (TestVectors.blake2sKeyedInput3Input, TestVectors.blake2sKeyedInput3Hash),
            (TestVectors.blake2sKeyedInput64Input, TestVectors.blake2sKeyedInput64Hash),
            (TestVectors.blake2sKeyedInput128Input, TestVectors.blake2sKeyedInput128Hash),
            (TestVectors.blake2sKeyedInput255Input, TestVectors.blake2sKeyedInput255Hash),
        ]
        for testCase in cases {
            let message = hexBytes(testCase.input)
            XCTAssertHexEqual(Blake2s.mac(key: key, message),
                              testCase.expected,
                              "keyed BLAKE2s-256 of \(message.count) bytes")
        }
    }

    /// Keyed BLAKE2s-128 with a 32 byte key: the exact shape of WireGuard's MAC.
    func testKeyedDigestLength16() {
        let key = hexBytes(TestVectors.blake2sKatKey)
        XCTAssertHexEqual(Blake2s.mac(key: key, Array("abc".utf8), digestLength: 16),
                          TestVectors.blake2sKeyed128AbcHash,
                          "keyed BLAKE2s-128 of 'abc'")
        XCTAssertHexEqual(Blake2s.mac(key: key, [], digestLength: 16),
                          TestVectors.blake2sKeyed128EmptyHash,
                          "keyed BLAKE2s-128 of the empty message")
    }

    /// This is the detail the specification calls out: when the function is
    /// keyed, the key is padded to a whole 64 byte block which is compressed
    /// before the message. Keyed BLAKE2s is therefore not "prefix the message
    /// with the key".
    func testKeyPaddingIsAFullBlock() {
        let key = hexBytes(TestVectors.blake2sKatKey)
        let message = Array("abc".utf8)

        let keyed = Blake2s.mac(key: key, message)
        let concatenated = Blake2s.hash(key + message)
        XCTAssertNotEqual(hexString(keyed),
                          hexString(concatenated),
                          "keyed BLAKE2s must compress the padded key as its own block")

        // A key whose length is exactly the block size is *not* hashed first;
        // only the length matters for the parameter block.
        var shortKey = Array(key.prefix(4))
        shortKey.append(contentsOf: [UInt8](repeating: 0, count: 60))
        XCTAssertNotEqual(hexString(Blake2s.mac(key: Array(key.prefix(4)), message)),
                          hexString(Blake2s.mac(key: shortKey, message)),
                          "the parameter block records the key length, so padding the "
                          + "key by hand changes the result")
    }

    /// BLAKE2s with an empty key is the unkeyed function: the parameter block's
    /// key length is zero and no key block is compressed.
    func testEmptyKeyMatchesUnkeyed() {
        let message = Array("the quick brown fox".utf8)
        XCTAssertHexEqual(Blake2s.mac(key: [], message),
                          hexString(Blake2s.hash(message)),
                          "an empty key must behave like the unkeyed function")
    }

    func testOverlongKeyIsTruncated() {
        let key = hexBytes(TestVectors.blake2sKatKey)
        var overlong = key
        overlong.append(contentsOf: [UInt8](repeating: 0xAB, count: 8))
        XCTAssertHexEqual(Blake2s.mac(key: overlong, Array("abc".utf8)),
                          hexString(Blake2s.mac(key: key, Array("abc".utf8))),
                          "keys longer than 32 bytes are truncated")
    }

    func testDataOverloadsMatchByteArrayOverloads() {
        let key = hexBytes(TestVectors.blake2sKatKey)
        let message = Array("abc".utf8)
        XCTAssertHexEqual(Blake2s.hash(Data(message)), hexString(Blake2s.hash(message)))
        XCTAssertHexEqual(Blake2s.mac(key: key, Data(message)), hexString(Blake2s.mac(key: key, message)))
    }
}

final class WireGuardKDFTests: XCTestCase {

    /// The three vectors published with the reference implementation.
    func testKdfVectors() {
        for (index, vector) in TestVectors.kdfVectors.enumerated() {
            let key = hexBytes(vector.key)
            let input = hexBytes(vector.input)

            XCTAssertHexEqual(WireGuardKDF.kdf1(key: key, input: input),
                              vector.t0,
                              "kdf1 vector \(index)")

            let (first, second) = WireGuardKDF.kdf2(key: key, input: input)
            XCTAssertHexEqual(first, vector.t0, "kdf2 vector \(index) tau1")
            XCTAssertHexEqual(second, vector.t1, "kdf2 vector \(index) tau2")

            let (tau1, tau2, tau3) = WireGuardKDF.kdf3(key: key, input: input)
            XCTAssertHexEqual(tau1, vector.t0, "kdf3 vector \(index) tau1")
            XCTAssertHexEqual(tau2, vector.t1, "kdf3 vector \(index) tau2")
            XCTAssertHexEqual(tau3, vector.t2, "kdf3 vector \(index) tau3")
        }
    }

    /// The KDF prefix relationship the protocol relies on: `kdf2` and `kdf3`
    /// must agree on their shared prefixes so that callers may look at only the
    /// outputs they need.
    func testKdfFamiliesAgreeOnPrefixes() {
        let key = hexBytes(TestVectors.blake2sKatKey)
        let input = hexBytes(TestVectors.blake2sKeyedInput64Input)

        let (first2, second2) = WireGuardKDF.kdf2(key: key, input: input)
        let (first3, second3, third3) = WireGuardKDF.kdf3(key: key, input: input)
        XCTAssertHexEqual(first3, hexString(first2), "tau1")
        XCTAssertHexEqual(second3, hexString(second2), "tau2")
        XCTAssertNotEqual(hexString(third3), hexString(second2), "tau3 is its own value")
    }

    /// Guards the single most dangerous interoperability detail in the
    /// handshake: WireGuard's `Hmac` is the ordinary RFC 2104 HMAC over
    /// BLAKE2s-256, not nested keyed BLAKE2s. The published vectors above
    /// already prove this, and this test states the difference explicitly so a
    /// future "simplification" of `hmac` fails loudly rather than silently
    /// breaking interoperability with real WireGuard peers.
    func testHmacIsStandardHmacNotNestedKeyedBlake2s() {
        let key = hexBytes(TestVectors.kdfVectors[0].key)
        let input = hexBytes(TestVectors.kdfVectors[0].input)
        let expected = TestVectors.kdfVectors[0].t0

        let nested = Blake2s.mac(key: key, Blake2s.mac(key: key, input))
        XCTAssertNotEqual(hexString(nested), expected,
                          "nested keyed BLAKE2s is not WireGuard's HMAC")

        XCTAssertHexEqual(WireGuardKDF.kdf1(key: key, input: input), expected, "kdf1")

        // The intermediate value inside kdf1 is the HMAC of the vector's key
        // and input, computed with the BLAKE2 toolkit's HMAC implementation.
        // Checking it separates "the HMAC construction is right" from "the KDF
        // composition is right".
        XCTAssertHexEqual(WireGuardKDF.hmac(key: key, input: input),
                          "ed378e02e152b574e0d9e01fb029a7066c3cc687917c28bf9dfe5b042769fa46",
                          "the intermediate pseudo random key")
    }

    /// RFC 2104 hashes keys longer than the block size before use.
    func testHmacHandlesKeysLongerThanABlock() {
        let key = [UInt8](repeating: 0x5A, count: 100)
        let hashedKey = Blake2s.hash(key)
        XCTAssertHexEqual(WireGuardKDF.hmac(key: key, input: []),
                          hexString(WireGuardKDF.hmac(key: hashedKey, input: [])),
                          "a key longer than 64 bytes is hashed first")
    }
}

final class Tai64nTests: XCTestCase {

    func testKnownTimestamps() {
        XCTAssertHexEqual(Tai64n.timestamp(seconds: 0, nanoseconds: 0),
                          TestVectors.tai64nUnixEpoch,
                          "the Unix epoch")
        XCTAssertHexEqual(Tai64n.timestamp(seconds: 1_672_531_200, nanoseconds: 0),
                          TestVectors.tai64nExample,
                          "2023-01-01T00:00:00Z")
        XCTAssertHexEqual(Tai64n.timestamp(seconds: 1_700_000_000, nanoseconds: 500_000_000),
                          TestVectors.tai64nExampleNanos,
                          "a timestamp with nanoseconds")
        XCTAssertHexEqual(Tai64n.timestamp(seconds: 0, nanoseconds: 999_999_999),
                          TestVectors.tai64nMaxNanos,
                          "the largest nanosecond field")
    }

    func testTimestampForDate() {
        let date = Date(timeIntervalSince1970: 1_672_531_200)
        XCTAssertHexEqual(Tai64n.timestamp(for: date),
                          TestVectors.tai64nExample,
                          "a Date at a whole second")
    }

    func testTimestampSize() {
        XCTAssertEqual(Tai64n.now().count, Tai64n.timestampSize)
        XCTAssertEqual(Tai64n.timestampSize, 12)
    }

    /// The timestamp the handshake generates must decode back to roughly now,
    /// otherwise the peer's replay protection would reject it.
    func testNowIsCurrent() {
        let before = Date()
        let decoded = Tai64n.decode(Tai64n.now())
        guard let decoded else {
            XCTFail("Tai64n.now() did not decode")
            return
        }
        let seconds = TimeInterval(decoded.seconds)
        XCTAssertLessThanOrEqual(seconds, before.timeIntervalSince1970 + 1)
        XCTAssertGreaterThan(seconds, before.timeIntervalSince1970 - 5)
        XCTAssertLessThan(decoded.nanoseconds, 1_000_000_000)
    }

    func testOrdering() {
        let earlier = Tai64n.timestamp(seconds: 100, nanoseconds: 999_999_999)
        let later = Tai64n.timestamp(seconds: 101, nanoseconds: 0)
        XCTAssertTrue(Tai64n.isLater(later, than: earlier))
        XCTAssertFalse(Tai64n.isLater(earlier, than: later))
        XCTAssertFalse(Tai64n.isLater(earlier, than: earlier))

        // A sub-second difference must still order correctly, which is what the
        // nanosecond field is for: the handshake rejects a timestamp that is
        // not strictly later than the last one it accepted.
        let subSecond = Tai64n.timestamp(seconds: 100, nanoseconds: 1_000)
        XCTAssertTrue(Tai64n.isLater(earlier, than: subSecond))
        XCTAssertTrue(Tai64n.isLater(subSecond, than: Tai64n.timestamp(seconds: 100, nanoseconds: 999)))
    }

    func testDecodeRejectsWrongLength() {
        XCTAssertNil(Tai64n.decode([]))
        XCTAssertNil(Tai64n.decode([UInt8](repeating: 0, count: 11)))
        XCTAssertNil(Tai64n.decode([UInt8](repeating: 0, count: 13)))

        // Comparisons between buffers that are not twelve bytes long are
        // refused rather than guessed at.
        XCTAssertFalse(Tai64n.isLater([0, 1], than: tai64nSafeStub))
        XCTAssertFalse(Tai64n.isLater(tai64nSafeStub, than: [0, 1]))
    }
}

/// A twelve byte constant used only to prove that comparisons of the wrong
/// length are refused.
private let tai64nSafeStub: [UInt8] = [UInt8](repeating: 0, count: 12)
