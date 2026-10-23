//
//  HandshakeTests.swift
//  VPNEngineTests
//
//  The Noise IK handshake, the message formats and the transport data framing.
//
//  The centrepiece is `testKnownAnswerHandshake`, which drives the engine with
//  fixed keys, ephemerals, indices and timestamp and compares every byte
//  against an independent implementation of the whitepaper (see
//  `regenerate-handshake-vectors.py`).
//

import XCTest
@testable import VPNEngine

final class WireGuardMessageTests: XCTestCase {

    func testInitiationRoundTrip() throws {
        let initiation = WireGuardInitiation(senderIndex: 0x1122_3344,
                                            ephemeral: Data(repeating: 0xAA, count: 32),
                                            encryptedStatic: Data(repeating: 0xBB, count: 48),
                                            encryptedTimestamp: Data(repeating: 0xCC, count: 28),
                                            mac1: Data(repeating: 0xDD, count: 16),
                                            mac2: Data(repeating: 0xEE, count: 16))
        let serialized = initiation.serialized()
        XCTAssertEqual(serialized.count, 148)
        XCTAssertEqual(WireGuardWireFormat.initiationSize, 148)
        XCTAssertEqual(try XCTUnwrap(WireGuardInitiation.parse(serialized)), initiation)

        // The type field is a little endian 32 bit value with three reserved
        // zero bytes after the type itself.
        let bytes = [UInt8](serialized)
        XCTAssertEqual(Array(bytes[0 ..< 4]), [1, 0, 0, 0])
        XCTAssertEqual(Array(bytes[4 ..< 8]), [0x44, 0x33, 0x22, 0x11])
        XCTAssertEqual(WireGuardInitiation.mac1CoveredRange, 0 ..< 116)
        XCTAssertEqual(WireGuardInitiation.mac2CoveredRange, 0 ..< 132)
    }

    func testResponseRoundTrip() throws {
        let response = WireGuardResponse(senderIndex: 1,
                                        receiverIndex: 2,
                                        ephemeral: Data(repeating: 0x01, count: 32),
                                        encryptedEmpty: Data(repeating: 0x02, count: 16),
                                        mac1: Data(repeating: 0x03, count: 16),
                                        mac2: Data(repeating: 0x04, count: 16))
        let serialized = response.serialized()
        XCTAssertEqual(serialized.count, 92)
        XCTAssertEqual(WireGuardWireFormat.responseSize, 92)
        XCTAssertEqual(try XCTUnwrap(WireGuardResponse.parse(serialized)), response)
        XCTAssertEqual(WireGuardResponse.mac1CoveredRange, 0 ..< 60)
        XCTAssertEqual(WireGuardResponse.mac2CoveredRange, 0 ..< 76)
    }

    func testCookieReplyRoundTrip() throws {
        let reply = WireGuardCookieReply(receiverIndex: 7,
                                        nonce: Data(repeating: 0x05, count: 24),
                                        encryptedCookie: Data(repeating: 0x06, count: 32))
        let serialized = reply.serialized()
        XCTAssertEqual(serialized.count, 64)
        XCTAssertEqual(WireGuardWireFormat.cookieReplySize, 64)
        XCTAssertEqual(try XCTUnwrap(WireGuardCookieReply.parse(serialized)), reply)
    }

    func testTransportDataRoundTrip() throws {
        let message = WireGuardTransportData(receiverIndex: 0xDEAD_BEEF,
                                            counter: 0x0102_0304_0506_0708,
                                            encryptedPacket: Data(repeating: 0x07, count: 48))
        let serialized = message.serialized()
        XCTAssertEqual(serialized.count, 16 + 48)
        XCTAssertEqual(try XCTUnwrap(WireGuardTransportData.parse(serialized)), message)
        XCTAssertFalse(message.isKeepalive)
        XCTAssertEqual(WireGuardWireFormat.keepaliveSize, 32)

        let keepalive = WireGuardTransportData(receiverIndex: 1,
                                              counter: 0,
                                              encryptedPacket: Data(repeating: 0, count: 16))
        XCTAssertTrue(keepalive.isKeepalive)
    }

    func testParsersRejectWrongSizesAndTypes() {
        XCTAssertNil(WireGuardInitiation.parse(Data(repeating: 0, count: 147)))
        XCTAssertNil(WireGuardInitiation.parse(Data(repeating: 0, count: 149)))
        XCTAssertNil(WireGuardResponse.parse(Data(repeating: 0, count: 91)))
        XCTAssertNil(WireGuardCookieReply.parse(Data(repeating: 0, count: 63)))
        XCTAssertNil(WireGuardTransportData.parse(Data(repeating: 0, count: 31)))

        // A response whose type field says "initiation" must not parse as a
        // response.
        var response = WireGuardResponse(senderIndex: 1, receiverIndex: 2,
                                        ephemeral: Data(repeating: 0, count: 32),
                                        encryptedEmpty: Data(repeating: 0, count: 16),
                                        mac1: Data(repeating: 0, count: 16),
                                        mac2: Data(repeating: 0, count: 16)).serialized()
        response[0] = 1
        XCTAssertNil(WireGuardResponse.parse(response))
    }

    func testMessageTypeDetection() {
        XCTAssertEqual(wireGuardMessageType(of: Data([1, 0, 0, 0])), .handshakeInitiation)
        XCTAssertEqual(wireGuardMessageType(of: Data([2, 0, 0, 0])), .handshakeResponse)
        XCTAssertEqual(wireGuardMessageType(of: Data([3, 0, 0, 0])), .cookieReply)
        XCTAssertEqual(wireGuardMessageType(of: Data([4, 0, 0, 0])), .transportData)

        XCTAssertNil(wireGuardMessageType(of: Data([5, 0, 0, 0])))
        XCTAssertNil(wireGuardMessageType(of: Data([1, 1, 0, 0])), "reserved bytes must be zero")
        XCTAssertNil(wireGuardMessageType(of: Data([1, 0, 0])), "too short")
        XCTAssertNil(wireGuardMessageType(of: Data()))
    }

    func testTransportNonceLayout() {
        XCTAssertEqual(LittleEndian.transportNonce(counter: 0),
                       [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        XCTAssertEqual(LittleEndian.transportNonce(counter: 1),
                       [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0])
        XCTAssertEqual(LittleEndian.transportNonce(counter: 0x0102_0304_0506_0708),
                       [0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1])
    }

    func testLittleEndianHelpers() {
        let bytes: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        XCTAssertEqual(LittleEndian.readUInt32(bytes, at: 0), 0x0403_0201)
        XCTAssertEqual(LittleEndian.readUInt64(bytes, at: 0), 0x0807_0605_0403_0201)
        XCTAssertNil(LittleEndian.readUInt32(bytes, at: 5))
        XCTAssertNil(LittleEndian.readUInt64(bytes, at: 1))

        var out: [UInt8] = []
        LittleEndian.append(UInt32(0x0403_0201), to: &out)
        LittleEndian.append(UInt64(0x0807_0605_0403_0201), to: &out)
        XCTAssertEqual(out, [0x01, 0x02, 0x03, 0x04] + bytes)
    }
}

final class HandshakeTests: XCTestCase {

    /// Every byte of the handshake, checked against an independent
    /// implementation.
    func testKnownAnswerHandshake() throws {
        let presharedKey = hexData(HandshakeVectors.presharedKey)
        let timestamp = hexBytes(HandshakeVectors.timestamp)

        // 1. The initiator builds the initiation.
        let initiator = WireGuardHandshake(localStatic: hexData(HandshakeVectors.initiatorStaticPrivate),
                                          remotePublic: hexData(HandshakeVectors.responderStaticPublic),
                                          presharedKey: presharedKey,
                                          isInitiator: true)
        initiator.ephemeralKeyGenerator = { hexBytes(HandshakeVectors.initiatorEphemeral) }
        initiator.indexGenerator = { 0x1122_3344 }
        initiator.timestampProvider = { timestamp }

        let initiation = try initiator.createInitiation()
        XCTAssertEqual(initiation.count, 148)
        XCTAssertHexEqual([UInt8](initiation), HandshakeVectors.initiation, "handshake initiation")

        // 2. The responder consumes it and builds the response.
        let responder = WireGuardHandshake(localStatic: hexData(HandshakeVectors.responderStaticPrivate),
                                          remotePublic: hexData(HandshakeVectors.initiatorStaticPublic),
                                          presharedKey: presharedKey,
                                          isInitiator: false)
        responder.ephemeralKeyGenerator = { hexBytes(HandshakeVectors.responderEphemeral) }
        responder.indexGenerator = { 0x5566_7788 }

        let response = try responder.consumeInitiation(initiation)
        XCTAssertEqual(response.count, 92)
        XCTAssertHexEqual([UInt8](response), HandshakeVectors.response, "handshake response")

        // 3. The initiator consumes the response.
        let initiatorKeys = try initiator.consumeResponse(response)
        XCTAssertHexEqual(initiatorKeys.sendKey, HandshakeVectors.initiatorSendKey, "initiator send key")
        XCTAssertHexEqual(initiatorKeys.receiveKey, HandshakeVectors.initiatorReceiveKey, "initiator receive key")
        XCTAssertEqual(initiatorKeys.remoteIndex, 0x5566_7788)
        XCTAssertEqual(initiatorKeys.localIndex, 0x1122_3344)

        // 4. Both sides agree on the keys, mirrored.
        let responderKeys = try XCTUnwrap(responder.sessionKeys)
        XCTAssertHexEqual(responderKeys.sendKey, HandshakeVectors.responderSendKey, "responder send key")
        XCTAssertHexEqual(responderKeys.receiveKey, HandshakeVectors.responderReceiveKey, "responder receive key")
        XCTAssertEqual(responderKeys.remoteIndex, 0x1122_3344)
        XCTAssertEqual(responderKeys.localIndex, 0x5566_7788)

        XCTAssertHexEqual(initiatorKeys.sendKey, hexString(responderKeys.receiveKey), "mirrored send/receive")
        XCTAssertHexEqual(initiatorKeys.receiveKey, hexString(responderKeys.sendKey), "mirrored receive/send")
    }

    /// The transport data framing, including the zero padding to a sixteen byte
    /// multiple and the counter nonce, against the same oracle.
    func testKnownAnswerTransportMessage() throws {
        let message = try XCTUnwrap(WireGuardTransportData.parse(hexData(HandshakeVectors.transportMessage)))
        XCTAssertEqual(message.receiverIndex, 0x5566_7788)
        XCTAssertEqual(message.counter, 0)

        let plaintext = try ChaChaPolyAEAD.open(key: hexBytes(HandshakeVectors.initiatorSendKey),
                                                nonce: LittleEndian.transportNonce(counter: 0),
                                                ciphertext: [UInt8](message.encryptedPacket),
                                                authenticatedData: [])
        XCTAssertEqual(plaintext.count % 16, 0, "the plaintext is padded to a block boundary")
        XCTAssertGreaterThan(plaintext.count, hexBytes(HandshakeVectors.innerPacket).count)

        let declared = try XCTUnwrap(IPPacket.declaredLength(Data(plaintext)))
        XCTAssertEqual(declared, hexBytes(HandshakeVectors.innerPacket).count)
        XCTAssertHexEqual(Array(plaintext[0 ..< declared]), HandshakeVectors.innerPacket, "the inner packet")
        XCTAssertTrue(plaintext[declared...].allSatisfy { $0 == 0 }, "the padding is zeros")
    }

    /// A complete round trip with random keys, which is what a real tunnel does.
    func testRoundTripWithFreshKeys() throws {
        let initiatorPrivate = Data(X25519.generatePrivateKey())
        let responderPrivate = Data(X25519.generatePrivateKey())
        let initiatorPublic = try X25519.publicKey(for: [UInt8](initiatorPrivate))
        let responderPublic = try X25519.publicKey(for: [UInt8](responderPrivate))

        let initiator = WireGuardHandshake(localStatic: initiatorPrivate,
                                          remotePublic: Data(responderPublic),
                                          presharedKey: nil,
                                          isInitiator: true)
        let responder = WireGuardHandshake(localStatic: responderPrivate,
                                          remotePublic: Data(initiatorPublic),
                                          presharedKey: nil,
                                          isInitiator: false)

        let initiation = try initiator.createInitiation()
        XCTAssertEqual(initiation.count, 148)
        XCTAssertEqual(initiator.state, .initiationCreated)
        XCTAssertNil(initiator.sessionKeys)

        let response = try responder.consumeInitiation(initiation)
        XCTAssertEqual(response.count, 92)
        XCTAssertEqual(responder.state, .responseCreated)

        let initiatorKeys = try initiator.consumeResponse(response)
        let responderKeys = try XCTUnwrap(responder.sessionKeys)

        XCTAssertEqual(initiatorKeys.sendKey.count, 32)
        XCTAssertEqual(initiatorKeys.receiveKey.count, 32)
        XCTAssertHexEqual(initiatorKeys.sendKey, hexString(responderKeys.receiveKey), "initiator send")
        XCTAssertHexEqual(initiatorKeys.receiveKey, hexString(responderKeys.sendKey), "initiator receive")
        XCTAssertNotEqual(hexString(initiatorKeys.sendKey), hexString(initiatorKeys.receiveKey))
        XCTAssertEqual(initiatorKeys.remoteIndex, responderKeys.localIndex)
        XCTAssertEqual(responderKeys.remoteIndex, initiatorKeys.localIndex)
        XCTAssertEqual(initiator.state, .responseConsumed)
        XCTAssertEqual(responder.state, .responseCreated)
        XCTAssertNotNil(initiator.sessionKeys)
        XCTAssertNotNil(responder.sessionKeys)
    }

    func testInitiationCarriesAFreshTimestamp() throws {
        let initiatorPrivate = Data(X25519.generatePrivateKey())
        let responderPrivate = Data(X25519.generatePrivateKey())
        let responderPublic = try X25519.publicKey(for: [UInt8](responderPrivate))
        let initiatorPublic = try X25519.publicKey(for: [UInt8](initiatorPrivate))

        let initiator = WireGuardHandshake(localStatic: initiatorPrivate,
                                          remotePublic: Data(responderPublic),
                                          isInitiator: true)
        let initiation = try initiator.createInitiation()

        let responder = WireGuardHandshake(localStatic: responderPrivate,
                                          remotePublic: Data(initiatorPublic),
                                          isInitiator: false)
        // Consuming the initiation must succeed, which requires the timestamp to
        // be inside the AEAD and well formed.
        XCTAssertNoThrow(try responder.consumeInitiation(initiation))
    }

    // MARK: - MACs

    func testMAC1IsOverTheRightBytes() throws {
        let initiatorPrivate = Data(X25519.generatePrivateKey())
        let responderPrivate = Data(X25519.generatePrivateKey())
        let responderPublic = try X25519.publicKey(for: [UInt8](responderPrivate))

        let handshake = WireGuardHandshake(localStatic: initiatorPrivate,
                                          remotePublic: Data(responderPublic),
                                          isInitiator: true)
        let initiation = try handshake.createInitiation()
        let bytes = [UInt8](initiation)

        // HASH("mac1----" ‖ responder public key)
        let expectedKey = Blake2s.hash(Array("mac1----".utf8) + responderPublic)
        XCTAssertHexEqual(handshake.mac1Key, hexString(expectedKey), "the mac1 key")

        let expectedMAC = Blake2s.mac(key: expectedKey,
                                      Array(bytes[0 ..< 116]),
                                      digestLength: 16)
        XCTAssertHexEqual(Array(bytes[116 ..< 132]), hexString(expectedMAC), "mac1")

        // Without a cookie, mac2 is all zeros.
        XCTAssertTrue(bytes[132 ..< 148].allSatisfy { $0 == 0 }, "mac2 must be zero without a cookie")
    }

    func testFlippedByteBreaksMAC1() throws {
        let initiatorPrivate = Data(X25519.generatePrivateKey())
        let responderPrivate = Data(X25519.generatePrivateKey())
        let responderPublic = try X25519.publicKey(for: [UInt8](responderPrivate))
        let initiatorPublic = try X25519.publicKey(for: [UInt8](initiatorPrivate))

        let initiator = WireGuardHandshake(localStatic: initiatorPrivate,
                                          remotePublic: Data(responderPublic),
                                          isInitiator: true)
        let initiation = try initiator.createInitiation()
        let responder = WireGuardHandshake(localStatic: responderPrivate,
                                          remotePublic: Data(initiatorPublic),
                                          isInitiator: false)

        // Every byte up to the end of `mac1` is covered by it or by an AEAD tag,
        // so flipping any of them must be rejected. `mac2` is deliberately not
        // authenticated when no cookie is held.
        for index in [0, 4, 8, 39, 40, 87, 88, 115, 116, 120, 131] {
            var corrupted = [UInt8](initiation)
            corrupted[index] ^= 0x01
            XCTAssertThrowsError(try responder.consumeInitiation(Data(corrupted)),
                                 "a flipped byte at \(index) must be rejected")
        }

        // The untouched message still works.
        XCTAssertNoThrow(try responder.consumeInitiation(initiation))
    }

    func testFlippedByteBreaksResponseMAC1() throws {
        let initiatorPrivate = Data(X25519.generatePrivateKey())
        let responderPrivate = Data(X25519.generatePrivateKey())
        let responderPublic = try X25519.publicKey(for: [UInt8](responderPrivate))
        let initiatorPublic = try X25519.publicKey(for: [UInt8](initiatorPrivate))

        let initiator = WireGuardHandshake(localStatic: initiatorPrivate,
                                          remotePublic: Data(responderPublic),
                                          isInitiator: true)
        let initiation = try initiator.createInitiation()
        let responder = WireGuardHandshake(localStatic: responderPrivate,
                                          remotePublic: Data(initiatorPublic),
                                          isInitiator: false)
        let response = try responder.consumeInitiation(initiation)

        // Everything up to the end of `mac1` is covered by it, and the encrypted
        // empty field by its own tag.
        for index in [0, 4, 8, 11, 12, 43, 44, 59, 60, 75] {
            var corrupted = [UInt8](response)
            corrupted[index] ^= 0x80
            XCTAssertThrowsError(try initiator.consumeResponse(Data(corrupted)),
                                 "a flipped byte at \(index) must be rejected")
        }
        XCTAssertNoThrow(try initiator.consumeResponse(response))
    }

    /// A response for a different handshake must not be accepted, even when its
    /// MAC is valid.
    func testResponseForAnotherHandshakeIsRejected() throws {
        let initiatorPrivate = Data(X25519.generatePrivateKey())
        let responderPrivate = Data(X25519.generatePrivateKey())
        let responderPublic = try X25519.publicKey(for: [UInt8](responderPrivate))
        let initiatorPublic = try X25519.publicKey(for: [UInt8](initiatorPrivate))

        let first = WireGuardHandshake(localStatic: initiatorPrivate,
                                      remotePublic: Data(responderPublic),
                                      isInitiator: true)
        let firstInitiation = try first.createInitiation()

        let second = WireGuardHandshake(localStatic: initiatorPrivate,
                                       remotePublic: Data(responderPublic),
                                       isInitiator: true)
        _ = try second.createInitiation()

        let responder = WireGuardHandshake(localStatic: responderPrivate,
                                          remotePublic: Data(initiatorPublic),
                                          isInitiator: false)
        let response = try responder.consumeInitiation(firstInitiation)

        // `second` did not send the initiation this response answers.
        XCTAssertThrowsError(try second.consumeResponse(response)) { error in
            XCTAssertEqual(error as? VPNCryptoError,
                           .invalidState("the response is for a different handshake"))
        }
    }

    // MARK: - Roles and keys

    func testWrongPeerIsRejected() throws {
        let initiatorPrivate = Data(X25519.generatePrivateKey())
        let responderPrivate = Data(X25519.generatePrivateKey())
        let strangerPrivate = Data(X25519.generatePrivateKey())
        let responderPublic = try X25519.publicKey(for: [UInt8](responderPrivate))
        let strangerPublic = try X25519.publicKey(for: [UInt8](strangerPrivate))

        let initiator = WireGuardHandshake(localStatic: initiatorPrivate,
                                          remotePublic: Data(responderPublic),
                                          isInitiator: true)
        let initiation = try initiator.createInitiation()

        // A responder that expects a different peer must not accept it: the
        // decrypted static key is checked against the configured peer.
        let responder = WireGuardHandshake(localStatic: responderPrivate,
                                          remotePublic: Data(strangerPublic),
                                          isInitiator: false)
        XCTAssertThrowsError(try responder.consumeInitiation(initiation))
    }

    func testRoleMismatchIsRejected() throws {
        let initiatorPrivate = Data(X25519.generatePrivateKey())
        let responderPrivate = Data(X25519.generatePrivateKey())
        let responderPublic = try X25519.publicKey(for: [UInt8](responderPrivate))
        let initiatorPublic = try X25519.publicKey(for: [UInt8](initiatorPrivate))

        let initiator = WireGuardHandshake(localStatic: initiatorPrivate,
                                          remotePublic: Data(responderPublic),
                                          isInitiator: true)
        let responder = WireGuardHandshake(localStatic: responderPrivate,
                                          remotePublic: Data(initiatorPublic),
                                          isInitiator: false)

        let initiation = try initiator.createInitiation()
        XCTAssertThrowsError(try initiator.consumeInitiation(initiation), "an initiator cannot consume an initiation")
        XCTAssertThrowsError(try responder.createInitiation(), "a responder cannot create an initiation")
        XCTAssertThrowsError(try initiator.createInitiation(), "an initiation has already been created")
    }

    func testInvalidKeysAreRefused() throws {
        let good = Data(X25519.generatePrivateKey())
        let short = Data(repeating: 0x01, count: 31)

        let badLocal = WireGuardHandshake(localStatic: short, remotePublic: good, isInitiator: true)
        XCTAssertThrowsError(try badLocal.createInitiation()) { error in
            XCTAssertEqual(error as? VPNCryptoError, .invalidKeySize(expected: 32, actual: 31))
        }

        let badRemote = WireGuardHandshake(localStatic: good, remotePublic: short, isInitiator: true)
        XCTAssertThrowsError(try badRemote.createInitiation()) { error in
            XCTAssertEqual(error as? VPNCryptoError, .invalidKeySize(expected: 32, actual: 31))
        }

        let badPreshared = WireGuardHandshake(localStatic: good, remotePublic: good, presharedKey: short, isInitiator: true)
        XCTAssertThrowsError(try badPreshared.createInitiation()) { error in
            XCTAssertEqual(error as? VPNCryptoError, .invalidKeySize(expected: 32, actual: 31))
        }
    }

    // MARK: - Preshared keys

    func testPresharedKeyIsMixedEvenWhenAbsent() throws {
        let initiatorPrivate = Data(X25519.generatePrivateKey())
        let responderPrivate = Data(X25519.generatePrivateKey())
        let responderPublic = try X25519.publicKey(for: [UInt8](responderPrivate))
        let initiatorPublic = try X25519.publicKey(for: [UInt8](initiatorPrivate))

        // One side has no preshared key, the other has thirty-two zero bytes.
        // WireGuard mixes the psk unconditionally, so these must interoperate.
        let initiator = WireGuardHandshake(localStatic: initiatorPrivate,
                                          remotePublic: Data(responderPublic),
                                          presharedKey: nil,
                                          isInitiator: true)
        let responder = WireGuardHandshake(localStatic: responderPrivate,
                                          remotePublic: Data(initiatorPublic),
                                          presharedKey: Data(repeating: 0, count: 32),
                                          isInitiator: false)

        let initiation = try initiator.createInitiation()
        let response = try responder.consumeInitiation(initiation)
        let initiatorKeys = try initiator.consumeResponse(response)
        let responderKeys = try XCTUnwrap(responder.sessionKeys)
        XCTAssertHexEqual(initiatorKeys.sendKey, hexString(responderKeys.receiveKey), "zero psk equivalence")
    }

    func testMismatchedPresharedKeysFail() throws {
        let initiatorPrivate = Data(X25519.generatePrivateKey())
        let responderPrivate = Data(X25519.generatePrivateKey())
        let responderPublic = try X25519.publicKey(for: [UInt8](responderPrivate))
        let initiatorPublic = try X25519.publicKey(for: [UInt8](initiatorPrivate))

        let initiator = WireGuardHandshake(localStatic: initiatorPrivate,
                                          remotePublic: Data(responderPublic),
                                          presharedKey: Data(repeating: 0x11, count: 32),
                                          isInitiator: true)
        let responder = WireGuardHandshake(localStatic: responderPrivate,
                                          remotePublic: Data(initiatorPublic),
                                          presharedKey: Data(repeating: 0x22, count: 32),
                                          isInitiator: false)

        let initiation = try initiator.createInitiation()
        let response = try responder.consumeInitiation(initiation)
        // The response's empty field authenticates the psk, so the initiator
        // must reject it.
        XCTAssertThrowsError(try initiator.consumeResponse(response)) { error in
            XCTAssertEqual(error as? VPNCryptoError, .authenticationFailure)
        }
    }

    // MARK: - Replay and cookies

    func testReplayedInitiationIsRejected() throws {
        let initiatorPrivate = Data(X25519.generatePrivateKey())
        let responderPrivate = Data(X25519.generatePrivateKey())
        let responderPublic = try X25519.publicKey(for: [UInt8](responderPrivate))
        let initiatorPublic = try X25519.publicKey(for: [UInt8](initiatorPrivate))

        let initiator = WireGuardHandshake(localStatic: initiatorPrivate,
                                          remotePublic: Data(responderPublic),
                                          isInitiator: true)
        let initiation = try initiator.createInitiation()

        // The same responder object only accepts one initiation, and a second
        // responder with the same keys rejects the replay because the timestamp
        // is not newer.
        let responder = WireGuardHandshake(localStatic: responderPrivate,
                                          remotePublic: Data(initiatorPublic),
                                          isInitiator: false)
        _ = try responder.consumeInitiation(initiation)
        XCTAssertThrowsError(try responder.consumeInitiation(initiation))
    }

    func testCookieReplyIsStoredAndUsedForMAC2() throws {
        let initiatorPrivate = Data(X25519.generatePrivateKey())
        let responderPrivate = Data(X25519.generatePrivateKey())
        let responderPublic = try X25519.publicKey(for: [UInt8](responderPrivate))
        let initiatorPublic = try X25519.publicKey(for: [UInt8](initiatorPrivate))

        let initiator = WireGuardHandshake(localStatic: initiatorPrivate,
                                          remotePublic: Data(responderPublic),
                                          isInitiator: true)
        let initiation = try initiator.createInitiation()
        XCTAssertTrue([UInt8](initiation)[132 ..< 148].allSatisfy { $0 == 0 })

        // Build the cookie reply the way a responder under load would: the
        // cookie is encrypted with HASH("cookie--" ‖ responder public key) and
        // authenticated with the mac1 of the message being answered.
        let cookie = [UInt8](0 ..< 16).map { UInt8($0) }
        let nonce = Data((0 ..< 24).map { UInt8($0 &* 7) })
        let mac1 = Data([UInt8](initiation)[116 ..< 132])
        let cookieKey = Blake2s.hash(Array("cookie--".utf8) + responderPublic)
        let encryptedCookie = try XChaCha20Poly1305.seal(key: Data(cookieKey),
                                                        nonce24: nonce,
                                                        plaintext: Data(cookie),
                                                        authenticatedData: mac1)
        let reply = WireGuardCookieReply(receiverIndex: initiator.localIndex ?? 0,
                                        nonce: nonce,
                                        encryptedCookie: encryptedCookie).serialized()

        XCTAssertFalse(initiator.hasFreshCookie)
        XCTAssertHexEqual(try initiator.consumeCookieReply(reply), hexString(cookie), "the stored cookie")
        XCTAssertTrue(initiator.hasFreshCookie)

        // The retransmitted initiation must now carry a mac2.
        let resent = try XCTUnwrap(initiator.resendWithCookie())
        XCTAssertEqual(resent.count, 148)
        XCTAssertHexEqual(Array([UInt8](resent)[0 ..< 132]),
                          hexString(Array([UInt8](initiation)[0 ..< 132])),
                          "the message body must be unchanged by a retransmission")
        XCTAssertFalse(Array([UInt8](resent)[132 ..< 148]).allSatisfy { $0 == 0 },
                       "mac2 must no longer be zero")

        // The responder checks mac2 the same way.
        let expectedMAC2 = Blake2s.mac(key: cookie, Array([UInt8](resent)[0 ..< 132]), digestLength: 16)
        XCTAssertHexEqual(Array([UInt8](resent)[132 ..< 148]), hexString(expectedMAC2), "mac2")
    }

    func testForgedCookieReplyIsRejected() throws {
        let initiatorPrivate = Data(X25519.generatePrivateKey())
        let responderPrivate = Data(X25519.generatePrivateKey())
        let responderPublic = try X25519.publicKey(for: [UInt8](responderPrivate))

        let initiator = WireGuardHandshake(localStatic: initiatorPrivate,
                                          remotePublic: Data(responderPublic),
                                          isInitiator: true)
        let initiation = try initiator.createInitiation()

        // The same cookie reply but with the wrong associated data: an attacker
        // cannot make the initiator store a cookie for a message it did not
        // send.
        let cookieKey = Blake2s.hash(Array("cookie--".utf8) + responderPublic)
        let nonce = Data(repeating: 0x42, count: 24)
        let encrypted = try XChaCha20Poly1305.seal(key: Data(cookieKey),
                                                   nonce24: nonce,
                                                   plaintext: Data(repeating: 0xAB, count: 16),
                                                   authenticatedData: Data(repeating: 0x00, count: 16))
        let forged = WireGuardCookieReply(receiverIndex: initiator.localIndex ?? 0,
                                         nonce: nonce,
                                         encryptedCookie: encrypted).serialized()

        XCTAssertThrowsError(try initiator.consumeCookieReply(forged)) { error in
            XCTAssertEqual(error as? VPNCryptoError, .authenticationFailure)
        }
        XCTAssertFalse(initiator.hasFreshCookie)

        // A truncated reply is rejected too.
        XCTAssertThrowsError(try initiator.consumeCookieReply(Data([UInt8](initiation)[0 ..< 63])))
    }
}

final class ReplayWindowTests: XCTestCase {

    func testAcceptsInOrder() {
        var window = ReplayWindow(size: 64)
        for counter in UInt64(0) ..< 100 {
            XCTAssertTrue(window.accept(counter), "counter \(counter)")
        }
        XCTAssertEqual(window.highest, 99)
    }

    func testRejectsReplays() {
        var window = ReplayWindow(size: 64)
        XCTAssertTrue(window.accept(10))
        XCTAssertFalse(window.accept(10), "the same counter twice")
        XCTAssertTrue(window.accept(11))
        XCTAssertFalse(window.accept(11))
    }

    func testAcceptsReorderingInsideTheWindow() {
        var window = ReplayWindow(size: 64)
        for counter in UInt64(0) ..< 40 {
            XCTAssertTrue(window.accept(counter))
        }
        // Anything inside the window that has not been seen is still accepted.
        for counter in UInt64(0) ..< 40 {
            XCTAssertFalse(window.accept(counter), "counter \(counter) was already seen")
        }
        XCTAssertTrue(window.accept(64))
        XCTAssertTrue(window.accept(63))
        XCTAssertFalse(window.accept(0), "0 has fallen out of the window")
        XCTAssertFalse(window.accept(10), "10 has fallen out of the window")
    }

    func testLargeJumpResetsTheWindow() {
        var window = ReplayWindow(size: 64)
        XCTAssertTrue(window.accept(0))
        XCTAssertTrue(window.accept(1_000_000))
        XCTAssertEqual(window.highest, 1_000_000)
        XCTAssertFalse(window.accept(0), "the old counters are forgotten")
        XCTAssertTrue(window.accept(999_999))
    }

    func testWouldAcceptDoesNotRecord() {
        var window = ReplayWindow(size: 64)
        XCTAssertTrue(window.wouldAccept(5))
        XCTAssertTrue(window.wouldAccept(5), "checking must not record")
        XCTAssertTrue(window.accept(5))
        XCTAssertFalse(window.wouldAccept(5))
        XCTAssertFalse(window.accept(5))
    }

    func testCounterLimits() {
        var window = ReplayWindow(size: 64)
        XCTAssertTrue(window.accept(UInt64.max))
        XCTAssertFalse(window.accept(UInt64.max))
        XCTAssertTrue(window.accept(UInt64.max - 1))
        XCTAssertFalse(window.accept(UInt64.max - 100))

        XCTAssertTrue(window.hasAcceptedAnything)
        window.reset()
        XCTAssertFalse(window.hasAcceptedAnything)
        XCTAssertTrue(window.accept(0))
    }

    func testSmallWindowIsClamped() {
        var window = ReplayWindow(size: 0)
        XCTAssertEqual(window.size, 1)
        XCTAssertTrue(window.accept(7))
        XCTAssertFalse(window.accept(7))
    }
}
