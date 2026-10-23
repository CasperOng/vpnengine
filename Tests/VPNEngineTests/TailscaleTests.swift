//
//  TailscaleTests.swift
//  VPNEngineTests
//
//  Tests for the Tailscale/Headscale layer.
//
//  Scope note, stated plainly: these verify the parts that can be verified without
//  a live coordination server — the Noise handshake, the record framing, the netmap
//  merge rules, the key encoding, and the netmap→WireGuard translation. They do
//  **not** prove the client interoperates with a real Headscale, because there is no
//  Headscale here to talk to.
//
//  The netmap fixtures are built from **JSON**, not from a convenience initialiser,
//  because the wire shape is the contract: a decoder that accepts the wrong field
//  name is exactly the bug these tests need to catch.
//

import XCTest
@testable import VPNEngine

// MARK: - Fixtures

enum TailscaleFixtures {

    /// A `tailcfg.Node` as the coordination server sends it.
    static func node(id: Int64,
                     stableID: String,
                     hostname: String,
                     address: String,
                     online: Bool = true,
                     allowedIPs: [String] = [],
                     primaryRoutes: [String] = [],
                     expired: Bool = false,
                     tags: [String] = []) -> String {
        let nodeHex = String(repeating: String(format: "%02x", Int(id % 255) + 1), count: 32)
        let allowed = (allowedIPs + primaryRoutes).map { "\"\($0)\"" }.joined(separator: ",")
        let tagsJSON = tags.map { "\"\($0)\"" }.joined(separator: ",")
        return """
        {
          "ID": \(id),
          "StableID": "\(stableID)",
          "Name": "\(hostname).tailnet.ts.net.",
          "User": 1,
          "Key": "nodekey:\(nodeHex)",
          "Addresses": ["\(address)"],
          "AllowedIPs": [\(allowed)],
          "Endpoints": ["203.0.113.\(id):41641"],
          "HomeDERP": 1,
          "Hostinfo": { "Hostname": "\(hostname)", "OS": "linux" },
          "Cap": 0,
          "Tags": [\(tagsJSON)],
          "PrimaryRoutes": [],
          "Online": \(online),
          "Expired": \(expired)
        }
        """
    }

    /// A `tailcfg.MapResponse` carrying one of the three peer-set fields.
    static func mapResponse(peers: [String]? = nil,
                            peersChanged: [String]? = nil,
                            peersRemoved: [Int64]? = nil,
                            domain: String? = nil,
                            selfNode: String? = nil) -> TailscaleMapResponse {
        var fields: [String] = []
        // The mapper derives the interface addresses from our own node, so a netmap
        // without one is not usable. Default to a plausible self node.
        fields.append("\"Node\": " + (selfNode ?? node(id: 100, stableID: "self",
                                                        hostname: "ipad",
                                                        address: "100.64.0.5/32")))
        if let peers { fields.append("\"Peers\": [\(peers.joined(separator: ","))]") }
        if let peersChanged { fields.append("\"PeersChanged\": [\(peersChanged.joined(separator: ","))]") }
        if let peersRemoved {
            fields.append("\"PeersRemoved\": [\(peersRemoved.map(String.init).joined(separator: ","))]")
        }
        if let domain { fields.append("\"Domain\": \"\(domain)\"") }
        let json = "{\(fields.joined(separator: ","))}"
        do {
            return try JSONDecoder().decode(TailscaleMapResponse.self, from: Data(json.utf8))
        } catch {
            fatalError("the fixture failed to decode, so the test is wrong: \(error)\n\(json)")
        }
    }
}

// MARK: - Noise

final class TailscaleNoiseTests: XCTestCase {

    /// Two independent handshake states must agree on all four session keys.
    func testNoiseIKRoundTripAgreesOnBothDirections() throws {
        let responderStatic = NoiseIKHandshake.generateStatic()
        let initiatorStatic = NoiseIKHandshake.generateStatic()

        let initiator = try NoiseIKHandshake(parameters: NoiseIKParameters(
            prologue: Data("test".utf8),
            localStatic: initiatorStatic.privateKey,
            remoteStatic: responderStatic.publicKey,
            isInitiator: true))
        let responder = try NoiseIKHandshake(parameters: NoiseIKParameters(
            prologue: Data("test".utf8),
            localStatic: responderStatic.privateKey,
            remoteStatic: Data(),
            isInitiator: false))

        let message1 = try initiator.writeMessage1(payload: Data("hello".utf8))
        XCTAssertEqual(try responder.readMessage1(message1), Data("hello".utf8),
                       "the initiator's payload must survive message 1")

        let message2 = try responder.writeMessage2(payload: Data("world".utf8))
        XCTAssertEqual(try initiator.readMessage2(message2), Data("world".utf8),
                       "the responder's payload must survive message 2")

        let initiatorKeys = try initiator.split()
        let responderKeys = try responder.split()

        let ciphertext = try initiatorKeys.send.encryptWithAd(Data("ping".utf8))
        XCTAssertEqual(try responderKeys.receive.decryptWithAd(ciphertext), Data("ping".utf8))

        let reply = try responderKeys.send.encryptWithAd(Data("pong".utf8))
        XCTAssertEqual(try initiatorKeys.receive.decryptWithAd(reply), Data("pong".utf8))
    }

    /// A tampered message must fail to authenticate, not decode to garbage.
    func testNoiseIKRejectsTamperedMessage() throws {
        let responderStatic = NoiseIKHandshake.generateStatic()
        let initiator = try NoiseIKHandshake(parameters: NoiseIKParameters(
            prologue: Data(),
            localStatic: NoiseIKHandshake.generateStatic().privateKey,
            remoteStatic: responderStatic.publicKey,
            isInitiator: true))
        let responder = try NoiseIKHandshake(parameters: NoiseIKParameters(
            prologue: Data(),
            localStatic: responderStatic.privateKey,
            remoteStatic: Data(),
            isInitiator: false))

        var message = try initiator.writeMessage1()
        message[message.count - 1] ^= 0xFF
        XCTAssertThrowsError(try responder.readMessage1(message))
    }

    /// The protocol name is fixed by Tailscale; a typo silently breaks interop.
    func testProtocolNameMatchesTailscale() {
        XCTAssertEqual(NoiseIKHandshake.protocolName, "Noise_IK_25519_ChaChaPoly_BLAKE2s")
    }
}

// MARK: - Framing

final class TailscaleFrameTests: XCTestCase {

    func testRecordRoundTrip() throws {
        let payload = Data(#"{"MapResponse":{}}"#.utf8)
        var buffer = try TailscaleControlFrameCodec.encode(.record(payload))
        XCTAssertEqual(try TailscaleControlFrameCodec.decode(&buffer), .record(payload))
        XCTAssertTrue(buffer.isEmpty, "a complete frame must consume the whole buffer")
    }

    /// A frame split across two reads must decode only once the tail arrives. This is
    /// the case that breaks a naive implementation when the server packs the HTTP
    /// response and the first record into one segment.
    func testPartialFrameNeedsTheRest() throws {
        let encoded = try TailscaleControlFrameCodec.encode(.record(Data("abcdef".utf8)))
        var buffer = encoded.prefix(5)
        XCTAssertNil(try TailscaleControlFrameCodec.decode(&buffer))
        buffer.append(encoded.dropFirst(5))
        XCTAssertEqual(try TailscaleControlFrameCodec.decode(&buffer), .record(Data("abcdef".utf8)))
    }

    func testPingRoundTrip() throws {
        let nonce = Data([1, 2, 3, 4, 5, 6, 7, 8])
        var buffer = try TailscaleControlFrameCodec.encode(.ping(nonce))
        XCTAssertEqual(try TailscaleControlFrameCodec.decode(&buffer), .ping(nonce))
    }

    func testTwoFramesInOneBuffer() throws {
        var buffer = try TailscaleControlFrameCodec.encode(.record(Data("one".utf8)))
        buffer.append(try TailscaleControlFrameCodec.encode(.record(Data("two".utf8))))
        XCTAssertEqual(try TailscaleControlFrameCodec.decode(&buffer), .record(Data("one".utf8)))
        XCTAssertEqual(try TailscaleControlFrameCodec.decode(&buffer), .record(Data("two".utf8)))
        XCTAssertTrue(buffer.isEmpty)
    }
}

// MARK: - Netmap

final class TailscaleNetmapTests: XCTestCase {

    /// `Peers` replaces the whole set — merging instead is the classic netmap bug.
    func testPeersReplacesTheSet() {
        var netmap = TailscaleNetmap()
        netmap.apply(TailscaleFixtures.mapResponse(peers: [
            TailscaleFixtures.node(id: 1, stableID: "1", hostname: "a", address: "100.64.0.1/32"),
            TailscaleFixtures.node(id: 2, stableID: "2", hostname: "b", address: "100.64.0.2/32"),
        ]))
        XCTAssertEqual(netmap.peers.count, 2)

        netmap.apply(TailscaleFixtures.mapResponse(peers: [
            TailscaleFixtures.node(id: 3, stableID: "3", hostname: "c", address: "100.64.0.3/32"),
        ]))
        XCTAssertEqual(netmap.peers.map(\.hostname), ["c"],
                       "a full Peers list must replace, not merge")
    }

    /// `PeersChanged` upserts by StableID and leaves the rest alone.
    func testPeersChangedUpserts() {
        var netmap = TailscaleNetmap()
        netmap.apply(TailscaleFixtures.mapResponse(peers: [
            TailscaleFixtures.node(id: 1, stableID: "1", hostname: "a", address: "100.64.0.1/32"),
            TailscaleFixtures.node(id: 2, stableID: "2", hostname: "b", address: "100.64.0.2/32"),
        ]))

        netmap.apply(TailscaleFixtures.mapResponse(peersChanged: [
            TailscaleFixtures.node(id: 2, stableID: "2", hostname: "b2", address: "100.64.0.2/32", online: false),
            TailscaleFixtures.node(id: 3, stableID: "3", hostname: "c", address: "100.64.0.3/32"),
        ]))

        XCTAssertEqual(netmap.peers.count, 3, "an upsert must add the new peer and keep the old one")
        let b = netmap.peers.first { $0.id == "2" }
        XCTAssertEqual(b?.hostname, "b2")
        XCTAssertEqual(b?.isOnline, false)
    }

    /// `PeersRemoved` deletes by node ID.
    func testPeersRemovedDeletes() {
        var netmap = TailscaleNetmap()
        netmap.apply(TailscaleFixtures.mapResponse(peers: [
            TailscaleFixtures.node(id: 1, stableID: "1", hostname: "a", address: "100.64.0.1/32"),
            TailscaleFixtures.node(id: 2, stableID: "2", hostname: "b", address: "100.64.0.2/32"),
        ]))
        netmap.apply(TailscaleFixtures.mapResponse(peersRemoved: [1]))
        XCTAssertEqual(netmap.peers.map(\.hostname), ["b"])
    }

    func testHostnameResolution() {
        var netmap = TailscaleNetmap()
        netmap.apply(TailscaleFixtures.mapResponse(peers: [
            TailscaleFixtures.node(id: 1, stableID: "1", hostname: "nas", address: "100.64.0.9/32"),
        ]))
        XCTAssertEqual(netmap.address(forHostname: "nas"), "100.64.0.9")
        XCTAssertEqual(netmap.address(forHostname: "nas.tailnet.ts.net"), "100.64.0.9")
        XCTAssertNil(netmap.address(forHostname: "nope"))
    }

    func testDomainIsCaptured() {
        var netmap = TailscaleNetmap()
        netmap.apply(TailscaleFixtures.mapResponse(peers: [], domain: "example.ts.net"))
        XCTAssertEqual(netmap.domain, "example.ts.net")
    }
}

// MARK: - Netmap -> WireGuard

final class TailscalePeerMapperTests: XCTestCase {

    private let nodeKey = Data(repeating: 3, count: 32)

    private func netmap(exitNode: Bool = false, expired: Bool = false, subnet: Bool = true) -> TailscaleNetmap {
        var allowed = ["100.64.0.9/32"]
        var routes: [String] = []
        if exitNode { allowed = ["0.0.0.0/0", "::/0"] }
        if subnet && !exitNode { routes = ["192.168.1.0/24"] }
        var netmap = TailscaleNetmap()
        netmap.apply(TailscaleFixtures.mapResponse(peers: [
            TailscaleFixtures.node(id: 9, stableID: "peer-1", hostname: "nas",
                                   address: "100.64.0.9/32",
                                   allowedIPs: allowed, primaryRoutes: routes,
                                   expired: expired),
        ]))
        return netmap
    }

    func testPeerBecomesWireGuardPeer() throws {
        let configuration = try TailscalePeerMapper.wireGuardConfiguration(
            netmap: netmap(), nodePrivateKey: nodeKey,
            listenPort: nil, acceptRoutes: false, exitNodeID: nil)

        XCTAssertEqual(configuration.interface.privateKey, nodeKey,
                       "the node key's private half *is* the WireGuard private key")
        XCTAssertEqual(configuration.peers.count, 1)
        XCTAssertEqual(configuration.peers[0].publicKey.count, 32)
        XCTAssertEqual(configuration.peers[0].allowedIPs.map(\.description), ["100.64.0.9/32"],
                       "without acceptRoutes a subnet route must not be installed")
    }

    func testAcceptRoutesAddsSubnetRoutes() throws {
        let configuration = try TailscalePeerMapper.wireGuardConfiguration(
            netmap: netmap(), nodePrivateKey: nodeKey,
            listenPort: nil, acceptRoutes: true, exitNodeID: nil)

        XCTAssertTrue(configuration.peers[0].allowedIPs.map(\.description).contains("192.168.1.0/24"),
                      "acceptRoutes must install the peer's advertised subnet")
    }

    func testExitNodeTakesTheDefaultRoute() throws {
        let configuration = try TailscalePeerMapper.wireGuardConfiguration(
            netmap: netmap(exitNode: true), nodePrivateKey: nodeKey,
            listenPort: nil, acceptRoutes: true, exitNodeID: "peer-1")

        let allowed = configuration.peers[0].allowedIPs.map(\.description)
        XCTAssertTrue(allowed.contains("0.0.0.0/0"), "an exit node must own the default route")
        XCTAssertTrue(allowed.contains("::/0"))
    }

    func testExpiredPeersAreSkipped() throws {
        let configuration = try TailscalePeerMapper.wireGuardConfiguration(
            netmap: netmap(expired: true), nodePrivateKey: nodeKey,
            listenPort: nil, acceptRoutes: true, exitNodeID: nil)
        XCTAssertTrue(configuration.peers.isEmpty, "an expired peer cannot carry traffic")
    }

    /// Tailscale's interface MTU is 1280 so a tailnet packet never fragments inside
    /// the smallest common path MTU.
    func testInterfaceUsesTheTailscaleMTU() throws {
        let configuration = try TailscalePeerMapper.wireGuardConfiguration(
            netmap: netmap(), nodePrivateKey: nodeKey,
            listenPort: nil, acceptRoutes: false, exitNodeID: nil)
        XCTAssertEqual(configuration.interface.mtu, 1280)
    }
}

// MARK: - Keys

final class TailscaleKeysTests: XCTestCase {

    func testPublicKeyParsesThePrefixedHexForm() {
        let hex = String(repeating: "ab", count: 32)
        let key = TailscalePublicKey(role: .node, text: "nodekey:\(hex)")
        XCTAssertNotNil(key)
        XCTAssertEqual(key?.rawValue.count, 32)
        XCTAssertEqual(key?.role, .node)
    }

    func testPublicKeyRejectsAPrivateKeyString() {
        let hex = String(repeating: "ab", count: 32)
        XCTAssertNil(TailscalePublicKey(role: .node, text: "privkey:\(hex)"),
                     "a private key must never be accepted where a public one is expected")
    }

    func testRoleIsInferredFromTheWirePrefix() throws {
        let hex = String(repeating: "cd", count: 32)
        let json = Data("\"discokey:\(hex)\"".utf8)
        let key = try JSONDecoder().decode(TailscalePublicKey.self, from: json)
        XCTAssertEqual(key.role, .disco)
    }
}
