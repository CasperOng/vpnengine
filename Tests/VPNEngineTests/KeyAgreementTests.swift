//
//  KeyAgreementTests.swift
//  VPNEngineTests
//
//  X25519 against the RFC 7748 vectors, driven through the same wrapper the
//  WireGuard handshake uses.
//

import XCTest
@testable import VPNEngine

final class X25519Tests: XCTestCase {

    func testPublicKeyDerivationVector() throws {
        XCTAssertHexEqual(try X25519.publicKey(for: hexBytes(TestVectors.x25519AlicePrivate)),
                          TestVectors.x25519AlicePublic,
                          "Alice's public key")
        XCTAssertHexEqual(try X25519.publicKey(for: hexBytes(TestVectors.x25519BobPrivate)),
                          TestVectors.x25519BobPublic,
                          "Bob's public key")
    }

    func testSharedSecretVector() throws {
        let fromAlice = try X25519.sharedSecret(privateKey: hexBytes(TestVectors.x25519AlicePrivate),
                                               publicKey: hexBytes(TestVectors.x25519BobPublic))
        let fromBob = try X25519.sharedSecret(privateKey: hexBytes(TestVectors.x25519BobPrivate),
                                             publicKey: hexBytes(TestVectors.x25519AlicePublic))
        XCTAssertHexEqual(fromAlice, TestVectors.x25519SharedSecret, "Alice's view of the shared secret")
        XCTAssertHexEqual(fromBob, TestVectors.x25519SharedSecret, "Bob's view of the shared secret")
    }

    /// RFC 7748 section 5.2's first block: a scalar with a u-coordinate that is
    /// not the base point.
    func testFunctionVectorsWithNonBasePointInputs() throws {
        XCTAssertHexEqual(try X25519.sharedSecret(
            privateKey: hexBytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            publicKey: hexBytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
            "RFC 7748 section 5.2 first vector")

        XCTAssertHexEqual(try X25519.sharedSecret(
            privateKey: hexBytes("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
            publicKey: hexBytes("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")),
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
            "RFC 7748 section 5.2 second vector")
    }

    /// RFC 7748 section 5.2's iterated test: `k` becomes `X25519(k, u)` and `u`
    /// becomes the previous `k`.
    func testIteratedVector() throws {
        var k = hexBytes(TestVectors.x25519IteratedScalar)
        var u = k

        for iteration in 1 ... 1000 {
            let previousK = k
            k = try X25519.sharedSecret(privateKey: k, publicKey: u)
            u = previousK
            if iteration == 1 {
                XCTAssertHexEqual(k, TestVectors.x25519Iterated1, "after one iteration")
            }
        }
        XCTAssertHexEqual(k, TestVectors.x25519Iterated1000, "after 1,000 iterations")
    }

    /// A public key of small order yields an all-zero shared secret, which must
    /// never be used as key material.
    ///
    /// The four encodings below are the small-order points that stay small
    /// order after the RFC's rule that the most significant bit of the
    /// u-coordinate is ignored: `0`, `1`, and the two order-8 points. The other
    /// published small-order encodings all have the high bit set, so masking
    /// turns them into ordinary points of large order and returning a secret
    /// for them is correct behaviour rather than a bug.
    func testSmallOrderPublicKeysAreRejected() {
        let privateKey = hexBytes(TestVectors.x25519AlicePrivate)
        let smallOrderPoints = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        ]
        for point in smallOrderPoints {
            XCTAssertThrowsError(try X25519.sharedSecret(privateKey: privateKey, publicKey: hexBytes(point)),
                                 "small order point \(point) must be refused")
        }
    }

    func testKeySizeValidation() {
        XCTAssertThrowsError(try X25519.publicKey(for: [UInt8](repeating: 0, count: 31)))
        XCTAssertThrowsError(try X25519.sharedSecret(privateKey: [UInt8](repeating: 0, count: 31),
                                                     publicKey: [UInt8](repeating: 0, count: 32)))
        XCTAssertThrowsError(try X25519.sharedSecret(privateKey: [UInt8](repeating: 0, count: 32),
                                                     publicKey: [UInt8](repeating: 0, count: 33)))
    }

    /// Generated keys must carry the standard clamping bits, like `wg genkey`.
    func testGeneratedKeysAreClampedAndUsable() throws {
        for _ in 0 ..< 32 {
            let key = X25519.generatePrivateKey()
            XCTAssertEqual(key.count, X25519.keySize)
            XCTAssertEqual(key[0] & 0b0000_0111, 0, "low three bits clear")
            XCTAssertEqual(key[31] & 0b1000_0000, 0, "top bit clear")
            XCTAssertEqual(key[31] & 0b0100_0000, 0b0100_0000, "second highest bit set")

            let publicKey = try X25519.publicKey(for: key)
            XCTAssertEqual(publicKey.count, X25519.keySize)
            XCTAssertFalse(publicKey.allSatisfy { $0 == 0 })
        }
    }

    /// Two freshly generated keys must agree on a shared secret in both
    /// directions, which is the property the handshake depends on.
    func testGeneratedKeysAgree() throws {
        let alicePrivate = X25519.generatePrivateKey()
        let bobPrivate = X25519.generatePrivateKey()
        let alicePublic = try X25519.publicKey(for: alicePrivate)
        let bobPublic = try X25519.publicKey(for: bobPrivate)

        let fromAlice = try X25519.sharedSecret(privateKey: alicePrivate, publicKey: bobPublic)
        let fromBob = try X25519.sharedSecret(privateKey: bobPrivate, publicKey: alicePublic)
        XCTAssertHexEqual(fromAlice, hexString(fromBob), "shared secrets must match")
    }

    /// Clamping does not change the derived public key, only the stored form of
    /// the scalar, which is why unclamped RFC 7748 scalars still work.
    func testClampingDoesNotChangeThePublicKey() throws {
        let unclamped = hexBytes(TestVectors.x25519AlicePrivate)
        let clamped = X25519.clamp(unclamped)
        XCTAssertNotEqual(hexString(unclamped), hexString(clamped))
        XCTAssertHexEqual(try X25519.publicKey(for: clamped), TestVectors.x25519AlicePublic)
    }
}
