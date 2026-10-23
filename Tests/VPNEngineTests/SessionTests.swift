//
//  SessionTests.swift
//  VPNEngineTests
//
//  Two sessions wired to each other through an in-memory transport: a complete
//  handshake, traffic in both directions, keepalives, rekeying and the failure
//  paths, all without a socket or root privileges.
//

import XCTest
@testable import VPNEngine

private extension WireGuardSessionState {

    /// Whether the session has usable keys.
    var isEstablished: Bool {
        if case .established = self { return true }
        return false
    }

    /// The failure reason, when there is one.
    var failureReason: String? {
        if case let .failed(reason) = self { return reason }
        return nil
    }
}

final class SessionTests: XCTestCase {

    // MARK: - Fixtures

    /// Two sessions that can reach each other: A has an endpoint for B, B has
    /// none, so A initiates and B responds.
    private struct Fixture {
        let sessionA: WireGuardSession
        let sessionB: WireGuardSession
        let transportA: InMemoryDatagramTransport
        let transportB: InMemoryDatagramTransport
        let configA: WireGuardConfiguration
        let configB: WireGuardConfiguration
    }

    private func makeFixture(timers: WireGuardSessionTimers = WireGuardSessionTimers(tickInterval: 0.02),
                            keepaliveA: UInt16? = nil,
                            keepaliveB: UInt16? = nil,
                            logA: @escaping @Sendable (String) -> Void = { _ in },
                            logB: @escaping @Sendable (String) -> Void = { _ in }) -> Fixture {
        let privateA = WireGuardKey.generatePrivateKey()
        let privateB = WireGuardKey.generatePrivateKey()
        let publicA = privateA.derivedPublicKey!
        let publicB = privateB.derivedPublicKey!

        let configA = WireGuardConfiguration(
            interface: WireGuardInterface(privateKey: privateA.rawValue,
                                          addresses: [CIDR(string: "10.7.0.2/24")!]),
            peers: [WireGuardPeer(publicKey: publicB.rawValue,
                                  endpoint: "192.0.2.1:51820",
                                  allowedIPs: [CIDR(string: "10.7.0.0/24")!, CIDR(string: "0.0.0.0/0")!],
                                  persistentKeepalive: keepaliveA)]
        )
        let configB = WireGuardConfiguration(
            interface: WireGuardInterface(privateKey: privateB.rawValue,
                                          addresses: [CIDR(string: "10.7.0.1/24")!]),
            peers: [WireGuardPeer(publicKey: publicA.rawValue,
                                  endpoint: nil,
                                  allowedIPs: [CIDR(string: "10.7.0.0/24")!],
                                  persistentKeepalive: keepaliveB)]
        )

        let (transportA, transportB) = InMemoryDatagramTransport.pair()
        return Fixture(sessionA: WireGuardSession(configuration: configA, transport: transportA, timers: timers, log: logA),
                       sessionB: WireGuardSession(configuration: configB, transport: transportB, timers: timers, log: logB),
                       transportA: transportA,
                       transportB: transportB,
                       configA: configA,
                       configB: configB)
    }

    /// An inner IPv4/UDP packet from A's address to B's address.
    private func outboundPacket() -> Data {
        var packet = hexData(PacketVectors.ipv4UDP)
        // Rewrite the source and destination to the tunnel addresses so that
        // cryptokey routing sends it to the peer.
        packet[12] = 10; packet[13] = 7; packet[14] = 0; packet[15] = 2
        packet[16] = 10; packet[17] = 7; packet[18] = 0; packet[19] = 1
        IPPacket.recomputeChecksums(&packet)
        return packet
    }

    // MARK: - Happy path

    func testHandshakeAndTrafficOverLoopback() async throws {
        let fixture = makeFixture()
        let receivedByB = Collector<[Data]>()
        let statesA = Collector<WireGuardSessionState>()
        let statesB = Collector<WireGuardSessionState>()
        fixture.sessionB.onInboundPackets = { packets in receivedByB.append(packets) }
        fixture.sessionA.onStateChange = { statesA.append($0) }
        fixture.sessionB.onStateChange = { statesB.append($0) }

        try await fixture.sessionA.start()
        try await fixture.sessionB.start()
        defer { Task { await fixture.sessionA.stop(); await fixture.sessionB.stop() } }

        // Both sides must reach an established session.
        let established = await waitUntil(timeout: 10) {
            fixture.sessionA.statistics.state.isEstablished
                && fixture.sessionB.statistics.state.isEstablished
        }
        XCTAssertTrue(established, "sessions did not establish: "
            + "\(fixture.sessionA.statistics.state) / \(fixture.sessionB.statistics.state)")
        XCTAssertTrue(statesA.values.contains { $0.isEstablished })
        XCTAssertTrue(statesB.values.contains { $0.isEstablished })

        // Send one packet from A to B.
        let packet = outboundPacket()
        fixture.sessionA.writeOutbound([packet])

        let delivered = await waitUntil { receivedByB.count >= 1 }
        XCTAssertTrue(delivered, "B never received the packet")
        XCTAssertBytesEqual(receivedByB.values[0][0], packet, "B must receive exactly what A sent")

        // The counters count encrypted transport data in both directions, so
        // after one packet plus the initiator's keepalive they must agree.
        let statisticsA = fixture.sessionA.statistics
        let statisticsB = fixture.sessionB.statistics
        XCTAssertEqual(statisticsA.bytesSent, statisticsB.bytesReceived,
                       "A's transmitted bytes must equal B's received bytes")
        XCTAssertGreaterThan(statisticsA.bytesSent, UInt64(packet.count))
        XCTAssertEqual(statisticsA.bytesReceived, 0)
        XCTAssertNotNil(statisticsA.lastHandshake)
        XCTAssertNotNil(statisticsB.lastHandshake)

        // Nothing was sent in the other direction yet.
        XCTAssertEqual(statisticsB.bytesSent, 0)
    }

    func testTrafficFlowsBothWays() async throws {
        let fixture = makeFixture()
        let receivedByA = Collector<[Data]>()
        let receivedByB = Collector<[Data]>()
        fixture.sessionA.onInboundPackets = { receivedByA.append($0) }
        fixture.sessionB.onInboundPackets = { receivedByB.append($0) }

        try await fixture.sessionA.start()
        try await fixture.sessionB.start()
        defer { Task { await fixture.sessionA.stop(); await fixture.sessionB.stop() } }

        let established = await waitUntil(timeout: 10) {
            fixture.sessionA.statistics.state.isEstablished
                && fixture.sessionB.statistics.state.isEstablished
        }
        XCTAssertTrue(established, "sessions did not establish")

        // A small packet towards A's address, which B's allowedIPs cover.
        var fromB = hexData(PacketVectors.ipv4UDP)
        fromB[12] = 10; fromB[13] = 7; fromB[14] = 0; fromB[15] = 1
        fromB[16] = 10; fromB[17] = 7; fromB[18] = 0; fromB[19] = 2
        IPPacket.recomputeChecksums(&fromB)

        fixture.sessionB.writeOutbound([fromB])
        let delivered = await waitUntil { receivedByA.count >= 1 }
        XCTAssertTrue(delivered, "A never received the packet")
        XCTAssertBytesEqual(receivedByA.values[0][0], fromB)

        // A can still send after B has spoken, with a second counter value.
        let packet = outboundPacket()
        fixture.sessionA.writeOutbound([packet])
        let deliveredAgain = await waitUntil { receivedByB.count >= 1 }
        XCTAssertTrue(deliveredAgain)
        XCTAssertBytesEqual(receivedByB.values[0][0], packet)

        XCTAssertGreaterThan(fixture.sessionA.statistics.bytesSent, 0)
        XCTAssertGreaterThan(fixture.sessionB.statistics.bytesSent, 0)
        XCTAssertGreaterThan(fixture.sessionA.statistics.bytesReceived, 0)
        XCTAssertGreaterThan(fixture.sessionB.statistics.bytesReceived, 0)
    }

    /// The initiator sends one empty packet as soon as the handshake completes,
    /// which the responder must decrypt without any inner packet appearing.
    func testKeepaliveAfterHandshake() async throws {
        let fixture = makeFixture()
        let receivedByB = Collector<[Data]>()
        fixture.sessionB.onInboundPackets = { receivedByB.append($0) }

        try await fixture.sessionA.start()
        try await fixture.sessionB.start()
        defer { Task { await fixture.sessionA.stop(); await fixture.sessionB.stop() } }

        let keepaliveArrived = await waitUntil(timeout: 10) {
            fixture.sessionB.statistics.bytesReceived >= UInt64(WireGuardWireFormat.keepaliveSize)
        }
        XCTAssertTrue(keepaliveArrived, "B did not receive the post-handshake keepalive")
        XCTAssertEqual(fixture.sessionB.statistics.bytesReceived,
                       UInt64(WireGuardWireFormat.keepaliveSize),
                       "a keepalive is exactly thirty-two bytes")
        XCTAssertEqual(receivedByB.count, 0, "a keepalive carries no inner packet")
    }

    /// A peer configured with `persistent-keepalive` must send empty packets
    /// when it has nothing else to say.
    func testPersistentKeepalive() async throws {
        let fixture = makeFixture(timers: WireGuardSessionTimers(tickInterval: 0.01),
                                 keepaliveA: 1)
        try await fixture.sessionA.start()
        try await fixture.sessionB.start()
        defer { Task { await fixture.sessionA.stop(); await fixture.sessionB.stop() } }

        let established = await waitUntil(timeout: 10) {
            fixture.sessionA.statistics.state.isEstablished
        }
        XCTAssertTrue(established)

        let firstCount = fixture.sessionA.statistics.bytesSent
        let secondKeepalive = await waitUntil(timeout: 6) {
            fixture.sessionA.statistics.bytesSent >= firstCount + UInt64(WireGuardWireFormat.keepaliveSize)
        }
        XCTAssertTrue(secondKeepalive, "no keepalive arrived within the interval")
        XCTAssertGreaterThan(fixture.sessionB.statistics.bytesReceived, firstCount - 1)
    }

    /// The initiator rekeys before its keys expire, without dropping the tunnel.
    func testRekeyAfterTime() async throws {
        let completions = Collector<String>()
        let timers = WireGuardSessionTimers(tickInterval: 0.01,
                                           rekeyAfterTime: 0.4,
                                           rejectAfterTime: 5,
                                           handshakeRetryInterval: 0.05,
                                           handshakeAttemptTimeout: 5,
                                           keepaliveTimeout: 5)
        let fixture = makeFixture(timers: timers, logA: { message in completions.append(message) })

        try await fixture.sessionA.start()
        try await fixture.sessionB.start()
        defer { Task { await fixture.sessionA.stop(); await fixture.sessionB.stop() } }

        let established = await waitUntil(timeout: 10) {
            fixture.sessionA.statistics.state.isEstablished
        }
        XCTAssertTrue(established)

        func completedHandshakes() -> Int {
            completions.values.filter { $0.contains("handshake with") }.count
        }

        let rekeyed = await waitUntil(timeout: 10) { completedHandshakes() >= 2 }
        XCTAssertTrue(rekeyed, "the session did not rekey, saw \(completedHandshakes()) handshakes")
        XCTAssertTrue(fixture.sessionA.statistics.state.isEstablished,
                      "a rekey must not take the session down")
        XCTAssertTrue(fixture.sessionB.statistics.state.isEstablished)
    }

    // MARK: - Failure paths

    /// With nobody answering, the timer must give up with a reason instead of
    /// retrying forever.
    func testHandshakeTimeoutFailsTheSession() async throws {
        let privateKey = WireGuardKey.generatePrivateKey()
        let peerKey = WireGuardKey.generatePrivateKey()
        let configuration = WireGuardConfiguration(
            interface: WireGuardInterface(privateKey: privateKey.rawValue, addresses: []),
            peers: [WireGuardPeer(publicKey: peerKey.rawValue,
                                  endpoint: "192.0.2.9:51820",
                                  allowedIPs: [CIDR(string: "0.0.0.0/0")!])]
        )
        // A lone transport: whatever is sent goes nowhere.
        let (transport, _) = InMemoryDatagramTransport.pair()
        let session = WireGuardSession(configuration: configuration,
                                      transport: transport,
                                      timers: WireGuardSessionTimers(tickInterval: 0.01,
                                                                     handshakeRetryInterval: 0.05,
                                                                     handshakeAttemptTimeout: 0.3))
        try await session.start()
        defer { Task { await session.stop() } }

        let failed = await waitUntil(timeout: 5) { session.statistics.state.failureReason != nil }
        XCTAssertTrue(failed, "the session never failed: \(session.statistics.state)")
        XCTAssertTrue(session.statistics.state.failureReason?.contains("handshake") ?? false,
                      "the reason should mention the handshake: \(String(describing: session.statistics.state.failureReason))")
        XCTAssertFalse(session.statistics.state.isEstablished)

        // Traffic offered afterwards must not crash anything.
        session.writeOutbound([outboundPacket()])
        XCTAssertEqual(session.statistics.bytesSent, 0)
    }

    /// Anything that is not a well-formed WireGuard message is dropped without
    /// disturbing an established session.
    func testMalformedDatagramsAreDroppedSilently() async throws {
        let fixture = makeFixture()
        let receivedByB = Collector<[Data]>()
        fixture.sessionB.onInboundPackets = { receivedByB.append($0) }

        try await fixture.sessionA.start()
        try await fixture.sessionB.start()
        defer { Task { await fixture.sessionA.stop(); await fixture.sessionB.stop() } }

        let established = await waitUntil(timeout: 10) {
            fixture.sessionA.statistics.state.isEstablished
                && fixture.sessionB.statistics.state.isEstablished
        }
        XCTAssertTrue(established)
        let sentBefore = fixture.sessionA.statistics.bytesSent
        let stateBefore = fixture.sessionB.statistics.state

        // Junk addressed at B, sent straight down A's transport.
        let junk: [Data] = [
            Data(),
            Data([0x00]),
            Data([0xFF, 0xFF, 0xFF, 0xFF]),
            Data(repeating: 0x5A, count: 148),
            Data(repeating: 0x00, count: 92),
            // A transport data message with an unknown receiver index.
            WireGuardTransportData(receiverIndex: 0xDEAD_BEEF,
                                   counter: 0,
                                   encryptedPacket: Data(repeating: 0x11, count: 64)).serialized(),
            // A handshake response with a valid shape but a bogus MAC.
            WireGuardResponse(senderIndex: 1, receiverIndex: 1,
                              ephemeral: Data(repeating: 0x22, count: 32),
                              encryptedEmpty: Data(repeating: 0x33, count: 16),
                              mac1: Data(repeating: 0x44, count: 16),
                              mac2: Data(repeating: 0x55, count: 16)).serialized(),
            // A cookie reply with a bogus tag.
            WireGuardCookieReply(receiverIndex: 1,
                                 nonce: Data(repeating: 0x66, count: 24),
                                 encryptedCookie: Data(repeating: 0x77, count: 32)).serialized(),
        ]
        for datagram in junk {
            try await fixture.transportA.send(datagram)
        }
        try await Task.sleep(for: .milliseconds(200))

        XCTAssertEqual(fixture.sessionB.statistics.state, stateBefore, "the session must survive junk")
        XCTAssertEqual(fixture.sessionA.statistics.bytesSent, sentBefore, "junk must not be counted as traffic")
        XCTAssertEqual(receivedByB.count, 0)

        // And the tunnel still works afterwards.
        let packet = outboundPacket()
        fixture.sessionA.writeOutbound([packet])
        let delivered = await waitUntil { receivedByB.count >= 1 }
        XCTAssertTrue(delivered, "the tunnel stopped working after junk")
        XCTAssertBytesEqual(receivedByB.values[0][0], packet)
    }

    func testOutboundPacketsWithNoPeerAreDropped() async throws {
        let fixture = makeFixture()
        try await fixture.sessionA.start()
        defer { Task { await fixture.sessionA.stop() } }

        // 203.0.113.7 is not inside any of A's allowed IPs.
        var unroutable = hexData(PacketVectors.ipv4UDP)
        unroutable[12] = 203; unroutable[13] = 0; unroutable[14] = 113; unroutable[15] = 7
        IPPacket.recomputeChecksums(&unroutable)

        let unroutableBefore = fixture.sessionA.statistics.bytesSent
        fixture.sessionA.writeOutbound([unroutable])
        XCTAssertEqual(fixture.sessionA.statistics.bytesSent, unroutableBefore)

        // Neither does a payload that is not an IP packet at all.
        fixture.sessionA.writeOutbound([Data([0x01, 0x02, 0x03])])
        fixture.sessionA.writeOutbound([])
        XCTAssertEqual(fixture.sessionA.statistics.bytesSent, unroutableBefore)
    }

    /// Packets offered before the handshake completes are held and then sent,
    /// in order.
    func testPacketsAreQueuedUntilTheSessionIsUp() async throws {
        let fixture = makeFixture()
        let receivedByB = Collector<[Data]>()
        fixture.sessionB.onInboundPackets = { receivedByB.append($0) }

        // Both sessions start, but the write happens immediately, before the
        // handshake can have completed.
        try await fixture.sessionA.start()
        try await fixture.sessionB.start()
        defer { Task { await fixture.sessionA.stop(); await fixture.sessionB.stop() } }

        var first = outboundPacket()
        first[20] = 0x12
        var second = outboundPacket()
        second[20] = 0x34
        fixture.sessionA.writeOutbound([first, second])

        let delivered = await waitUntil(timeout: 10) { receivedByB.count >= 2 }
        XCTAssertTrue(delivered, "queued packets were never sent")
        XCTAssertBytesEqual(receivedByB.values[0][0], first, "packets must keep their order")
        XCTAssertBytesEqual(receivedByB.values[1][0], second)
    }

    func testStopClosesTheTransportAndResetsState() async throws {
        let fixture = makeFixture()
        try await fixture.sessionA.start()
        try await fixture.sessionB.start()

        let established = await waitUntil(timeout: 10) {
            fixture.sessionA.statistics.state.isEstablished
        }
        XCTAssertTrue(established)

        await fixture.sessionA.stop()
        XCTAssertEqual(fixture.sessionA.statistics.state, .idle)
        XCTAssertTrue(fixture.transportA.closed, "stopping must close the transport")
        XCTAssertFalse(fixture.sessionA.isRunningSession)

        // Writing after a stop is refused rather than queued.
        let sentBefore = fixture.sessionA.statistics.bytesSent
        fixture.sessionA.writeOutbound([outboundPacket()])
        XCTAssertEqual(fixture.sessionA.statistics.bytesSent, sentBefore,
                       "a stopped session must not send")

        // Stopping twice is harmless.
        await fixture.sessionA.stop()
        await fixture.sessionB.stop()
    }

    func testStartRejectsBadKeys() async throws {
        let peerKey = WireGuardKey.generatePrivateKey()

        let shortPrivate = WireGuardSession(
            configuration: WireGuardConfiguration(
                interface: WireGuardInterface(privateKey: Data(repeating: 0, count: 31), addresses: []),
                peers: []
            ),
            transport: InMemoryDatagramTransport.pair().0
        )
        do {
            try await shortPrivate.start()
            XCTFail("a 31 byte private key must be refused")
        } catch {
            XCTAssertEqual(error as? VPNCryptoError, .invalidKeySize(expected: 32, actual: 31))
        }

        let badPeer = WireGuardSession(
            configuration: WireGuardConfiguration(
                interface: WireGuardInterface(privateKey: WireGuardKey.generatePrivateKey().rawValue,
                                              addresses: []),
                peers: [WireGuardPeer(publicKey: Data(repeating: 0, count: 3))]
            ),
            transport: InMemoryDatagramTransport.pair().0
        )
        do {
            try await badPeer.start()
            XCTFail("a three byte peer key must be refused")
        } catch {
            XCTAssertEqual(error as? VPNCryptoError, .invalidKeySize(expected: 32, actual: 3))
        }

        let badPreshared = WireGuardSession(
            configuration: WireGuardConfiguration(
                interface: WireGuardInterface(privateKey: WireGuardKey.generatePrivateKey().rawValue,
                                              addresses: []),
                peers: [WireGuardPeer(publicKey: peerKey.rawValue,
                                      presharedKey: Data(repeating: 0, count: 16))]
            ),
            transport: InMemoryDatagramTransport.pair().0
        )
        do {
            try await badPreshared.start()
            XCTFail("a sixteen byte preshared key must be refused")
        } catch {
            XCTAssertEqual(error as? VPNCryptoError, .invalidKeySize(expected: 32, actual: 16))
        }
    }

    /// Starting and stopping repeatedly must leave nothing running.
    func testRestartIsClean() async throws {
        let fixture = makeFixture()
        try await fixture.sessionA.start()
        try await fixture.sessionB.start()

        var established = await waitUntil(timeout: 10) { fixture.sessionA.statistics.state.isEstablished }
        XCTAssertTrue(established)

        await fixture.sessionA.stop()
        await fixture.sessionB.stop()
        XCTAssertEqual(fixture.sessionA.statistics.state, .idle)

        // A fresh pair of transports, since the old ones are closed.
        let second = makeFixture()
        try await second.sessionA.start()
        try await second.sessionB.start()
        established = await waitUntil(timeout: 10) { second.sessionA.statistics.state.isEstablished }
        XCTAssertTrue(established)
        await second.sessionA.stop()
        await second.sessionB.stop()
    }
}

final class DatagramTransportTests: XCTestCase {

    func testPairDeliversDatagrams() async throws {
        let (first, second) = InMemoryDatagramTransport.pair()
        try await first.send(Data([1, 2, 3]))
        try await second.send(Data([4, 5]))

        let receivedBySecond = try await second.receive()
        let receivedByFirst = try await first.receive()
        XCTAssertEqual(receivedBySecond, Data([1, 2, 3]))
        XCTAssertEqual(receivedByFirst, Data([4, 5]))
        XCTAssertEqual(first.sentCount, 1)
        XCTAssertEqual(second.sentCount, 1)
        XCTAssertEqual(first.receivedCount, 1)
        XCTAssertEqual(second.receivedCount, 1)
    }

    func testReceiveWaitsForADatagram() async throws {
        let (first, second) = InMemoryDatagramTransport.pair()
        let expectation = expectation(description: "received")
        Task {
            let datagram = try? await second.receive()
            XCTAssertEqual(datagram, Data([9]))
            expectation.fulfill()
        }
        try await Task.sleep(for: .milliseconds(50))
        try await first.send(Data([9]))
        await fulfillment(of: [expectation], timeout: 2)
    }

    func testQueueDropsTheOldestWhenFull() async throws {
        let (first, second) = InMemoryDatagramTransport.pair(capacity: 2)
        try await first.send(Data([1]))
        try await first.send(Data([2]))
        try await first.send(Data([3]))
        XCTAssertEqual(second.droppedCount, 1)

        let firstReceived = try await second.receive()
        let secondReceived = try await second.receive()
        XCTAssertEqual(firstReceived, Data([2]))
        XCTAssertEqual(secondReceived, Data([3]))
    }

    func testCloseReleasesReceiversAndRefusesSends() async throws {
        let (first, second) = InMemoryDatagramTransport.pair()
        let expectation = expectation(description: "closed")
        Task {
            do {
                _ = try await second.receive()
                XCTFail("receive should have failed")
            } catch {
                XCTAssertEqual(error as? DatagramTransportError, .closed)
                expectation.fulfill()
            }
        }
        try await Task.sleep(for: .milliseconds(50))
        await second.close()
        await fulfillment(of: [expectation], timeout: 2)

        // The first transport is still open, so a send succeeds even though the
        // second one's receive queue is closed.
        try await first.send(Data([1]))

        await first.close()
        do {
            try await first.send(Data([2]))
            XCTFail("a closed transport must refuse to send")
        } catch {
            XCTAssertEqual(error as? DatagramTransportError, .closed)
        }
        await first.close()
        XCTAssertTrue(first.closed)
    }

    func testQueueOrdersAndCloses() async {
        let queue = AsyncDatagramQueue(capacity: 2)
        queue.push(Data([1]))
        queue.push(Data([2]))
        queue.push(Data([3]))
        XCTAssertEqual(queue.count, 2)
        XCTAssertEqual(queue.droppedCount, 1)

        let first = await queue.pop()
        let second = await queue.pop()
        XCTAssertEqual(first, Data([2]))
        XCTAssertEqual(second, Data([3]))

        let pending = Task { await queue.pop() }
        try? await Task.sleep(for: .milliseconds(20))
        queue.close()
        let released = await pending.value
        let afterClose = await queue.pop()
        XCTAssertNil(released)
        XCTAssertNil(afterClose)
        XCTAssertEqual(queue.count, 0)
    }

    func testQueueWakesAWaitingConsumer() async {
        let queue = AsyncDatagramQueue(capacity: 4)
        let consumer = Task { await queue.pop() }
        try? await Task.sleep(for: .milliseconds(20))
        queue.push(Data([7]))
        let value = await consumer.value
        XCTAssertEqual(value, Data([7]))
    }
}

final class SessionTimersTests: XCTestCase {

    func testDefaultsMatchTheSpecification() {
        let timers = WireGuardSessionTimers()
        XCTAssertEqual(timers.rekeyAfterTime, 180)
        XCTAssertEqual(timers.rejectAfterTime, 180)
        XCTAssertEqual(timers.handshakeRetryInterval, 5)
        XCTAssertEqual(timers.handshakeAttemptTimeout, 180)
        XCTAssertEqual(timers.keepaliveTimeout, 10)
        XCTAssertEqual(timers.rekeyAfterMessages, 1 << 60)
        XCTAssertEqual(timers.rejectAfterMessages, UInt64.max - (1 << 13))
        XCTAssertEqual(timers.tickInterval, 0.25)
    }

    func testPaddingRules() {
        // A small packet is padded to the next sixteen byte boundary.
        XCTAssertEqual(WireGuardPeerRuntime.paddingSize(forPacketSize: 1, mtu: 1420), 15)
        XCTAssertEqual(WireGuardPeerRuntime.paddingSize(forPacketSize: 16, mtu: 1420), 0)
        XCTAssertEqual(WireGuardPeerRuntime.paddingSize(forPacketSize: 17, mtu: 1420), 15)
        XCTAssertEqual(WireGuardPeerRuntime.paddingSize(forPacketSize: 100, mtu: 1420), 12)
        XCTAssertEqual(WireGuardPeerRuntime.paddingSize(forPacketSize: 0, mtu: 1420), 0)

        // Padding never pushes a packet past the MTU: 1410 rounds up to 1424,
        // which is over the limit, so it stops at the MTU instead.
        XCTAssertEqual(WireGuardPeerRuntime.paddingSize(forPacketSize: 1410, mtu: 1420), 10)
        XCTAssertEqual(WireGuardPeerRuntime.paddingSize(forPacketSize: 1411, mtu: 1420), 9)

        // A packet larger than the MTU is measured modulo the MTU.
        XCTAssertEqual(WireGuardPeerRuntime.paddingSize(forPacketSize: 1500, mtu: 1420), 0)
        XCTAssertEqual(WireGuardPeerRuntime.paddingSize(forPacketSize: 1424, mtu: 1420), 12)
        XCTAssertEqual(WireGuardPeerRuntime.paddingSize(forPacketSize: 2000, mtu: 1420), 12)

        // An MTU of zero means "always round up".
        XCTAssertEqual(WireGuardPeerRuntime.paddingSize(forPacketSize: 100, mtu: 0), 12)
        XCTAssertEqual(WireGuardPeerRuntime.paddingSize(forPacketSize: 16, mtu: 0), 0)
    }

    func testPaddingIsStrippedUsingTheInnerLength() {
        var packet = hexData(PacketVectors.ipv4UDP)
        let original = packet
        packet.append(contentsOf: [UInt8](repeating: 0, count: 12))
        XCTAssertBytesEqual(WireGuardPeerRuntime.stripTransportPadding(packet), original)

        // A keepalive has no padding to strip.
        XCTAssertEqual(WireGuardPeerRuntime.stripTransportPadding(Data()).count, 0)

        // Something that is not an IP packet is handed over unchanged.
        let junk = Data([0xFF, 0xFF, 0xFF, 0xFF])
        XCTAssertBytesEqual(WireGuardPeerRuntime.stripTransportPadding(junk), junk)
    }
}
