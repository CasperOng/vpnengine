//
//  ChaChaAndAeadTests.swift
//  VPNEngineTests
//
//  ChaCha20, HChaCha20, Poly1305 and the two AEAD constructions, against the
//  RFC 8439 and draft-irtf-cfrg-xchacha-03 vectors.
//

import XCTest
@testable import VPNEngine

final class ChaCha20Tests: XCTestCase {

    func testBlockFunctionVector() {
        let output = ChaCha20.block(key: hexBytes(TestVectors.chacha20BlockKey),
                                    counter: TestVectors.chacha20BlockCounter,
                                    nonce: hexBytes(TestVectors.chacha20BlockNonce))
        XCTAssertHexEqual(output ?? [], TestVectors.chacha20BlockOutput, "RFC 8439 section 2.3.2")
    }

    func testEncryptionVector() {
        let ciphertext = ChaCha20.xor(key: hexBytes(TestVectors.chacha20Key),
                                     nonce: hexBytes(TestVectors.chacha20Nonce),
                                     counter: TestVectors.chacha20Counter,
                                     data: Array(TestVectors.sunscreenPlaintext.utf8))
        XCTAssertHexEqual(ciphertext ?? [], TestVectors.chacha20Ciphertext, "RFC 8439 section 2.4.2")
    }

    func testDecryptionVector() {
        let plaintext = ChaCha20.xor(key: hexBytes(TestVectors.chacha20Key),
                                     nonce: hexBytes(TestVectors.chacha20Nonce),
                                     counter: TestVectors.chacha20Counter,
                                     data: hexBytes(TestVectors.chacha20Ciphertext))
        XCTAssertEqual(String(decoding: plaintext ?? [], as: UTF8.self),
                       TestVectors.sunscreenPlaintext,
                       "decryption is the same operation")
    }

    /// Block zero of the ChaCha20 keystream is the Poly1305 one-time key, which
    /// is why message data starts at counter 1.
    func testBlockZeroSuppliesTheOneTimeKey() {
        let block = ChaCha20.block(key: hexBytes(TestVectors.aeadKey),
                                   counter: 0,
                                   nonce: hexBytes(TestVectors.aeadNonce))
        XCTAssertHexEqual(Array((block ?? []).prefix(32)),
                          TestVectors.chacha20OneTimeKey,
                          "RFC 8439 section 2.6.2")
    }

    func testKeystreamVector() {
        let keystream = ChaCha20.xor(key: hexBytes(TestVectors.aeadKey),
                                     nonce: hexBytes(TestVectors.aeadNonce),
                                     counter: 1,
                                     data: [UInt8](repeating: 0, count: 114))
        XCTAssertHexEqual(keystream ?? [], TestVectors.aeadKeystream, "RFC 8439 section 2.8.2 keystream")
    }

    /// The counter must carry across block boundaries and the final partial
    /// block must be truncated, not padded.
    func testPartialBlocksAndCounterRollover() {
        let key = hexBytes(TestVectors.chacha20Key)
        let nonce = hexBytes(TestVectors.chacha20Nonce)

        let full = ChaCha20.xor(key: key, nonce: nonce, counter: 0, data: [UInt8](repeating: 0, count: 192)) ?? []
        XCTAssertEqual(full.count, 192)
        for length in [1, 63, 64, 65, 127, 128, 129] {
            let short = ChaCha20.xor(key: key, nonce: nonce, counter: 0, data: [UInt8](repeating: 0, count: length)) ?? []
            XCTAssertEqual(short, Array(full.prefix(length)), "keystream must be a prefix at length \(length)")
        }
    }

    func testRejectsWrongSizes() {
        XCTAssertNil(ChaCha20.block(key: [UInt8](repeating: 0, count: 16), counter: 0, nonce: [UInt8](repeating: 0, count: 12)))
        XCTAssertNil(ChaCha20.block(key: [UInt8](repeating: 0, count: 32), counter: 0, nonce: [UInt8](repeating: 0, count: 8)))
        XCTAssertNil(ChaCha20.xor(key: [], nonce: [UInt8](repeating: 0, count: 12), data: [1, 2, 3]))
        XCTAssertNil(ChaCha20.xor(key: [UInt8](repeating: 0, count: 32), nonce: [], data: [1, 2, 3]))
    }
}

final class HChaCha20Tests: XCTestCase {

    func testSubkeyVector() {
        let subkey = HChaCha20.subkey(key: hexBytes(TestVectors.chacha20BlockKey),
                                      nonce: hexBytes(TestVectors.hchachaNonce))
        XCTAssertHexEqual(subkey ?? [], TestVectors.hchachaSubkey, "draft-irtf-cfrg-xchacha-03 section 2.2.1")
    }

    func testRejectsWrongSizes() {
        XCTAssertNil(HChaCha20.subkey(key: [UInt8](repeating: 0, count: 31), nonce: [UInt8](repeating: 0, count: 16)))
        XCTAssertNil(HChaCha20.subkey(key: [UInt8](repeating: 0, count: 32), nonce: [UInt8](repeating: 0, count: 15)))
    }
}

final class Poly1305Tests: XCTestCase {

    func testTagVector() {
        let tag = Poly1305.tag(key: hexBytes(TestVectors.poly1305Key),
                               message: Array(TestVectors.poly1305Message.utf8))
        XCTAssertHexEqual(tag ?? [], TestVectors.poly1305Tag, "RFC 8439 section 2.5.2")
    }

    /// For an empty message the accumulator stays zero, so the tag is just the
    /// `s` half of the key.
    func testEmptyMessageReturnsTheSecondHalfOfTheKey() {
        let key = hexBytes(TestVectors.poly1305Key)
        let tag = Poly1305.tag(key: key, message: [])
        XCTAssertHexEqual(tag ?? [], hexString(Array(key.suffix(16))), "Poly1305 of the empty message")
    }

    /// Streaming in arbitrary chunks must produce the same tag as one call,
    /// which is what exercises the "hold back the partial block" logic.
    func testStreamingMatchesOneShot() {
        let key = hexBytes(TestVectors.poly1305Key)
        let message = Array(TestVectors.sunscreenPlaintext.utf8)
        let expected = Poly1305.tag(key: key, message: message) ?? []
        XCTAssertFalse(expected.isEmpty)

        for chunkSize in [1, 3, 15, 16, 17, 31, 32, 33, 64, 100, 113, 114, 115] {
            guard var state = Poly1305(key: key) else {
                XCTFail("could not create Poly1305 state")
                return
            }
            var offset = 0
            while offset < message.count {
                let count = Swift.min(chunkSize, message.count - offset)
                state.update(Array(message[offset ..< offset + count]))
                offset += count
            }
            XCTAssertHexEqual(state.finalize(), hexString(expected), "chunk size \(chunkSize)")
        }
    }

    /// A message that is an exact multiple of the block size gets the 2^128 bit
    /// on every block and no padding byte, unlike a message one byte shorter.
    func testExactBlockMultiple() {
        let key = hexBytes(TestVectors.poly1305Key)
        for length in [0, 1, 15, 16, 17, 31, 32, 33, 48] {
            let message = [UInt8](repeating: 0x41, count: length)
            guard var state = Poly1305(key: key) else {
                XCTFail("could not create Poly1305 state")
                return
            }
            state.update(message)
            XCTAssertHexEqual(state.finalize(),
                              hexString(Poly1305.tag(key: key, message: message) ?? []),
                              "one-shot agreement at length \(length)")
        }

        // The 16 byte message is a whole block, so its tag must differ from the
        // 15 byte message's: the padding rule differs.
        let tag15 = Poly1305.tag(key: key, message: [UInt8](repeating: 0x41, count: 15)) ?? []
        let tag16 = Poly1305.tag(key: key, message: [UInt8](repeating: 0x41, count: 16)) ?? []
        XCTAssertNotEqual(hexString(tag15), hexString(tag16))
    }

    func testRejectsWrongKeySize() {
        XCTAssertNil(Poly1305(key: [UInt8](repeating: 0, count: 31)))
        XCTAssertNil(Poly1305.tag(key: [], message: [1, 2, 3]))
    }

    func testConstantTimeComparison() {
        XCTAssertTrue(constantTimeEquals([1, 2, 3], [1, 2, 3]))
        XCTAssertFalse(constantTimeEquals([1, 2, 3], [1, 2, 4]))
        XCTAssertFalse(constantTimeEquals([1, 2, 3], [1, 2]))
        XCTAssertFalse(constantTimeEquals([], [0]))
        XCTAssertTrue(constantTimeEquals([], []))
    }
}

final class ChaCha20Poly1305Tests: XCTestCase {

    func testSealVector() {
        let sealed = ChaCha20Poly1305.seal(key: hexBytes(TestVectors.aeadKey),
                                           nonce: hexBytes(TestVectors.aeadNonce),
                                           plaintext: Array(TestVectors.sunscreenPlaintext.utf8),
                                           authenticatedData: hexBytes(TestVectors.aeadAAD))
        XCTAssertHexEqual(sealed ?? [],
                          TestVectors.aeadCiphertext + TestVectors.aeadTag,
                          "RFC 8439 section 2.8.2")
    }

    func testOpenVector() {
        let plaintext = ChaCha20Poly1305.open(key: hexBytes(TestVectors.aeadKey),
                                              nonce: hexBytes(TestVectors.aeadNonce),
                                              ciphertext: hexBytes(TestVectors.aeadCiphertext + TestVectors.aeadTag),
                                              authenticatedData: hexBytes(TestVectors.aeadAAD))
        XCTAssertEqual(String(decoding: plaintext ?? [], as: UTF8.self), TestVectors.sunscreenPlaintext)
    }

    func testTamperedCiphertextIsRejected() {
        var sealed = hexBytes(TestVectors.aeadCiphertext + TestVectors.aeadTag)
        sealed[0] ^= 0x01
        XCTAssertNil(ChaCha20Poly1305.open(key: hexBytes(TestVectors.aeadKey),
                                           nonce: hexBytes(TestVectors.aeadNonce),
                                           ciphertext: sealed,
                                           authenticatedData: hexBytes(TestVectors.aeadAAD)))
    }

    func testTamperedTagIsRejected() {
        var sealed = hexBytes(TestVectors.aeadCiphertext + TestVectors.aeadTag)
        sealed[sealed.count - 1] ^= 0x80
        XCTAssertNil(ChaCha20Poly1305.open(key: hexBytes(TestVectors.aeadKey),
                                           nonce: hexBytes(TestVectors.aeadNonce),
                                           ciphertext: sealed,
                                           authenticatedData: hexBytes(TestVectors.aeadAAD)))
    }

    func testWrongAssociatedDataIsRejected() {
        XCTAssertNil(ChaCha20Poly1305.open(key: hexBytes(TestVectors.aeadKey),
                                           nonce: hexBytes(TestVectors.aeadNonce),
                                           ciphertext: hexBytes(TestVectors.aeadCiphertext + TestVectors.aeadTag),
                                           authenticatedData: hexBytes("50515253c0c1c2c3c4c5c6c8")))
    }

    func testEmptyPlaintextAndAssociatedData() {
        let key = hexBytes(TestVectors.aeadKey)
        let nonce = hexBytes(TestVectors.aeadNonce)
        let sealed = ChaCha20Poly1305.seal(key: key,
                                           nonce: nonce,
                                           plaintext: [],
                                           authenticatedData: []) ?? []
        XCTAssertEqual(sealed.count, ChaCha20Poly1305.tagSize, "an empty message seals to just a tag")
        XCTAssertEqual(ChaCha20Poly1305.open(key: key,
                                            nonce: nonce,
                                            ciphertext: sealed,
                                            authenticatedData: []),
                       [])
    }

    func testRejectsShortCiphertext() {
        XCTAssertNil(ChaCha20Poly1305.open(key: hexBytes(TestVectors.aeadKey),
                                           nonce: hexBytes(TestVectors.aeadNonce),
                                           ciphertext: [UInt8](repeating: 0, count: 15),
                                           authenticatedData: []))
    }

    /// CryptoKit's `ChaChaPoly` (used by the protocol code on Apple platforms)
    /// and the local implementation must be interchangeable: WireGuard peers
    /// cannot tell which one encrypted a message.
    func testCryptoKitAndLocalImplementationsAgree() throws {
        var generator = SystemRandomNumberGenerator()
        let lengths = [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 114, 115, 200, 1000]
        let aadLengths = [0, 1, 16, 32]

        for plaintextLength in lengths {
            for aadLength in aadLengths {
                let key = (0 ..< 32).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
                let nonce = (0 ..< 12).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
                let plaintext = (0 ..< plaintextLength).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
                let aad = (0 ..< aadLength).map { _ in UInt8.random(in: .min ... .max, using: &generator) }

                let local = ChaCha20Poly1305.seal(key: key,
                                                  nonce: nonce,
                                                  plaintext: plaintext,
                                                  authenticatedData: aad) ?? []
                let cryptoKit = try ChaChaPolyAEAD.seal(key: key,
                                                        nonce: nonce,
                                                        plaintext: plaintext,
                                                        authenticatedData: aad)
                XCTAssertHexEqual(cryptoKit, hexString(local),
                                  "seal mismatch, plaintext \(plaintextLength), aad \(aadLength)")

                let opened = try ChaChaPolyAEAD.open(key: key,
                                                     nonce: nonce,
                                                     ciphertext: local,
                                                     authenticatedData: aad)
                XCTAssertEqual(opened, plaintext)

                let openedLocally = ChaCha20Poly1305.open(key: key,
                                                         nonce: nonce,
                                                         ciphertext: cryptoKit,
                                                         authenticatedData: aad)
                XCTAssertEqual(openedLocally, plaintext)
            }
        }
    }

    func testCryptoKitPathsRejectTampering() {
        let sealed = hexBytes(TestVectors.aeadCiphertext + TestVectors.aeadTag)
        var tampered = sealed
        tampered[tampered.count - 1] ^= 0x01

        XCTAssertThrowsError(try ChaChaPolyAEAD.open(key: hexBytes(TestVectors.aeadKey),
                                                     nonce: hexBytes(TestVectors.aeadNonce),
                                                     ciphertext: tampered,
                                                     authenticatedData: hexBytes(TestVectors.aeadAAD))) { error in
            XCTAssertEqual(error as? VPNCryptoError, .authenticationFailure)
        }
    }

    func testCryptoKitPathValidatesSizes() {
        XCTAssertThrowsError(try ChaChaPolyAEAD.seal(key: [UInt8](repeating: 0, count: 31),
                                                     nonce: [UInt8](repeating: 0, count: 12),
                                                     plaintext: [],
                                                     authenticatedData: []))
        XCTAssertThrowsError(try ChaChaPolyAEAD.seal(key: [UInt8](repeating: 0, count: 32),
                                                     nonce: [UInt8](repeating: 0, count: 11),
                                                     plaintext: [],
                                                     authenticatedData: []))
        XCTAssertThrowsError(try ChaChaPolyAEAD.open(key: [UInt8](repeating: 0, count: 32),
                                                     nonce: [UInt8](repeating: 0, count: 12),
                                                     ciphertext: [UInt8](repeating: 0, count: 4),
                                                     authenticatedData: []))
    }
}

final class XChaCha20Poly1305Tests: XCTestCase {

    func testSealVector() throws {
        let sealed = try XChaCha20Poly1305.seal(key: hexData(TestVectors.xchachaKey),
                                               nonce24: hexData(TestVectors.xchachaNonce),
                                               plaintext: Data(TestVectors.sunscreenPlaintext.utf8),
                                               authenticatedData: hexData(TestVectors.aeadAAD))
        XCTAssertHexEqual([UInt8](sealed),
                          TestVectors.xchachaCiphertext + TestVectors.xchachaTag,
                          "draft-irtf-cfrg-xchacha-03 appendix A.3.1")
    }

    func testOpenVector() throws {
        let plaintext = try XChaCha20Poly1305.open(key: hexData(TestVectors.xchachaKey),
                                                   nonce24: hexData(TestVectors.xchachaNonce),
                                                   ciphertext: hexData(TestVectors.xchachaCiphertext + TestVectors.xchachaTag),
                                                   authenticatedData: hexData(TestVectors.aeadAAD))
        XCTAssertEqual(String(decoding: plaintext, as: UTF8.self), TestVectors.sunscreenPlaintext)
    }

    /// XChaCha20-Poly1305 is defined as HChaCha20 for the subkey plus the
    /// ordinary IETF construction with a zero-prefixed 96 bit nonce, so
    /// composing the two primitives by hand must reproduce it exactly.
    func testMatchesHandComposedConstruction() throws {
        let key = hexData(TestVectors.xchachaKey)
        let nonce = hexData(TestVectors.xchachaNonce)
        let aad = hexData(TestVectors.aeadAAD)
        let plaintext = Data(TestVectors.sunscreenPlaintext.utf8)

        let subkey = HChaCha20.subkey(key: [UInt8](key), nonce: [UInt8](nonce.prefix(16))) ?? []
        var derivedNonce = Data(repeating: 0, count: 4)
        derivedNonce.append(nonce.suffix(8))
        let composed = ChaCha20Poly1305.seal(key: subkey,
                                            nonce: [UInt8](derivedNonce),
                                            plaintext: [UInt8](plaintext),
                                            authenticatedData: [UInt8](aad)) ?? []

        let published = try XChaCha20Poly1305.seal(key: key, nonce24: nonce, plaintext: plaintext, authenticatedData: aad)
        XCTAssertHexEqual([UInt8](published), hexString(composed), "composition")
    }

    func testRoundTripAndTamper() throws {
        let key = Data(X25519.generatePrivateKey())
        let nonce = Data((0 ..< 24).map { UInt8($0) })
        for length in [0, 1, 16, 32, 100] {
            let plaintext = Data((0 ..< length).map { UInt8($0 % 251) })
            let sealed = try XChaCha20Poly1305.seal(key: key,
                                                   nonce24: nonce,
                                                   plaintext: plaintext,
                                                   authenticatedData: Data("aad".utf8))
            let opened = try XChaCha20Poly1305.open(key: key,
                                                   nonce24: nonce,
                                                   ciphertext: sealed,
                                                   authenticatedData: Data("aad".utf8))
            XCTAssertEqual(opened, plaintext)

            var tampered = sealed
            tampered[tampered.count - 1] ^= 0x01
            XCTAssertThrowsError(try XChaCha20Poly1305.open(key: key,
                                                           nonce24: nonce,
                                                           ciphertext: tampered,
                                                           authenticatedData: Data("aad".utf8)))
        }
    }

    func testRejectsWrongSizes() {
        XCTAssertThrowsError(try XChaCha20Poly1305.seal(key: Data(repeating: 0, count: 24),
                                                        nonce24: Data(repeating: 0, count: 24),
                                                        plaintext: Data(),
                                                        authenticatedData: Data()))
        XCTAssertThrowsError(try XChaCha20Poly1305.seal(key: Data(repeating: 0, count: 32),
                                                        nonce24: Data(repeating: 0, count: 23),
                                                        plaintext: Data(),
                                                        authenticatedData: Data()))
        XCTAssertThrowsError(try XChaCha20Poly1305.open(key: Data(repeating: 0, count: 32),
                                                        nonce24: Data(repeating: 0, count: 25),
                                                        ciphertext: Data(),
                                                        authenticatedData: Data()))
    }
}
