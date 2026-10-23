//
//  CIDRTests.swift
//  VPNEngineTests
//
//  Address ranges, key parsing and cryptokey routing.
//

import XCTest
@testable import VPNEngine

final class CIDRTests: XCTestCase {

    // MARK: - Parsing

    func testParsesIPv4() {
        guard let range = CIDR(string: "10.0.0.0/8") else {
            XCTFail("10.0.0.0/8 did not parse")
            return
        }
        XCTAssertEqual(range.address, Data([10, 0, 0, 0]))
        XCTAssertEqual(range.prefixLength, 8)
        XCTAssertEqual(range.family, .ipv4)
        XCTAssertEqual(range.description, "10.0.0.0/8")
    }

    func testBareAddressBecomesAHostRoute() {
        XCTAssertEqual(CIDR(string: "192.0.2.7")?.prefixLength, 32)
        XCTAssertEqual(CIDR(string: "2001:db8::1")?.prefixLength, 128)
        XCTAssertEqual(CIDR(string: "192.0.2.7")?.description, "192.0.2.7/32")
        XCTAssertEqual(CIDR(string: "2001:db8::1")?.description, "2001:db8::1/128")
    }

    func testParsesIPv6Forms() {
        let cases: [(text: String, expected: String, prefix: Int)] = [
            ("::/0", "::/0", 0),
            // A bare address is a host route, including the all-zero address.
            ("::", "::/128", 128),
            ("2001:db8::/32", "2001:db8::/32", 32),
            ("fe80::1/64", "fe80::1/64", 64),
            ("2001:0db8:0000:0000:0000:0000:0000:0001/128",
             "2001:db8::1/128", 128),
            ("::ffff:192.0.2.1/120", "::ffff:c000:201/120", 120),
            ("64:ff9b::/96", "64:ff9b::/96", 96),
        ]
        for testCase in cases {
            guard let range = CIDR(string: testCase.text) else {
                XCTFail("\(testCase.text) did not parse")
                continue
            }
            XCTAssertEqual(range.prefixLength, testCase.prefix, testCase.text)
            XCTAssertEqual(range.description, testCase.expected, testCase.text)
            XCTAssertEqual(range.family, .ipv6, testCase.text)
            XCTAssertEqual([UInt8](range.address).count, 16, testCase.text)
        }
    }

    /// Whitespace and a trailing slash are the kind of thing a configuration
    /// file picks up; the former is tolerated and the latter is not.
    func testTrimsWhitespaceAndRejectsMalformedText() {
        XCTAssertEqual(CIDR(string: "  10.0.0.0/8\n")?.description, "10.0.0.0/8")
        XCTAssertEqual(CIDR(string: "\t2001:db8::/32 ")?.description, "2001:db8::/32")

        let invalid = [
            "",
            "   ",
            "10.0.0.0/",
            "10.0.0.0/33",
            "10.0.0.0/-1",
            "10.0.0.0/8/8",
            "10.0.0",
            "10.0.0.0.0/8",
            "256.0.0.1/8",
            "10.0.0.256/8",
            "10.0..0.1/8",
            "::/129",
            ":::",
            "2001:db8:::1/64",
            "2001:db8::1::2/64",
            "1:2:3:4:5:6:7/64",
            "1:2:3:4:5:6:7:8:9/64",
            "gggg::/16",
            "2001:db8::ffff:1.2.3.4.5/64",
        ]
        for text in invalid {
            XCTAssertNil(CIDR(string: text), "\(text.debugDescription) should not parse")
        }
    }

    func testAddressInitialiserValidatesSizes() {
        XCTAssertNil(CIDR(address: Data([10, 0, 0]), prefixLength: 8))
        XCTAssertNil(CIDR(address: Data(repeating: 0, count: 5), prefixLength: 8))
        XCTAssertNil(CIDR(address: Data(repeating: 0, count: 4), prefixLength: 33))
        XCTAssertNil(CIDR(address: Data(repeating: 0, count: 16), prefixLength: 129))
        XCTAssertNil(CIDR(address: Data(repeating: 0, count: 4), prefixLength: -1))
        XCTAssertNotNil(CIDR(address: Data(repeating: 0, count: 4), prefixLength: 32))
        XCTAssertNotNil(CIDR(address: Data(repeating: 0, count: 16), prefixLength: 0))
    }

    // MARK: - Matching

    func testIPv4Containment() {
        guard let private8 = CIDR(string: "10.0.0.0/8"),
              let subnet = CIDR(string: "10.7.1.0/24") else {
            XCTFail("fixtures")
            return
        }
        XCTAssertTrue(private8.contains(hexData("0a070101")))       // 10.7.1.1
        XCTAssertTrue(private8.contains(hexData("0affffff")))       // 10.255.255.255
        XCTAssertFalse(private8.contains(hexData("0b000001")))      // 11.0.0.1

        XCTAssertTrue(subnet.contains(hexData("0a070101")))
        XCTAssertTrue(subnet.contains(hexData("0a0701ff")))
        XCTAssertFalse(subnet.contains(hexData("0a070201")))
    }

    func testDefaultRoutesContainEverythingOfTheirFamily() {
        guard let v4Default = CIDR(string: "0.0.0.0/0"),
              let v6Default = CIDR(string: "::/0") else {
            XCTFail("fixtures")
            return
        }
        XCTAssertTrue(v4Default.isDefaultRoute)
        XCTAssertTrue(v6Default.isDefaultRoute)

        for address in ["00000000", "ffffffff", "0a070101", "c6336414"] {
            XCTAssertTrue(v4Default.contains(hexData(address)), address)
        }
        for address in ["00000000000000000000000000000000",
                        "ffffffffffffffffffffffffffffffff",
                        "20010db8000000000000000000000001"] {
            XCTAssertTrue(v6Default.contains(hexData(address)), address)
        }

        // A default route never matches the other family.
        XCTAssertFalse(v4Default.contains(hexData("00000000000000000000000000000000")))
        XCTAssertFalse(v6Default.contains(hexData("00000000")))
    }

    func testFamilyMismatchNeverMatches() {
        guard let v4 = CIDR(string: "10.0.0.0/8"), let v6 = CIDR(string: "2001:db8::/32") else {
            XCTFail("fixtures")
            return
        }
        XCTAssertFalse(v4.contains(hexData("20010db8000000000000000000000001")))
        XCTAssertFalse(v6.contains(hexData("0a070101")))
        XCTAssertFalse(v4.contains(Data()))
        XCTAssertFalse(v6.contains(Data([1, 2, 3])))
    }

    /// Every prefix length must mask exactly the right number of bits, including
    /// the awkward ones that are not a whole number of bytes.
    func testOddPrefixLengths() {
        let cases: [(prefix: Int, text: String, inside: String, outside: String)] = [
            (1, "128.0.0.0/1", "ffffffff", "7fffffff"),
            (7, "10.0.0.0/7", "0bffffff", "0c000000"),
            (13, "10.0.0.0/13", "0a07ffff", "0a080000"),
            (25, "192.0.2.0/25", "c000027f", "c0000280"),
            (31, "192.0.2.0/31", "c0000201", "c0000202"),
            (32, "192.0.2.1/32", "c0000201", "c0000202"),
        ]
        for testCase in cases {
            guard let range = CIDR(string: testCase.text) else {
                XCTFail("\(testCase.text) did not parse")
                continue
            }
            XCTAssertTrue(range.contains(hexData(testCase.inside)),
                          "\(testCase.text) should contain \(testCase.inside)")
            XCTAssertFalse(range.contains(hexData(testCase.outside)),
                           "\(testCase.text) should not contain \(testCase.outside)")
        }
    }

    func testNetworkAddressClearsHostBits() {
        XCTAssertEqual(CIDR(string: "10.7.1.5/24")?.networkAddress, hexData("0a070100"))
        XCTAssertEqual(CIDR(string: "10.7.1.5/32")?.networkAddress, hexData("0a070105"))
        XCTAssertEqual(CIDR(string: "10.7.1.5/0")?.networkAddress, hexData("00000000"))
        XCTAssertEqual(CIDR(string: "10.7.1.5/12")?.networkAddress, hexData("0a000000"))
        XCTAssertEqual(CIDR(string: "10.96.1.5/12")?.networkAddress, hexData("0a600000"))
        XCTAssertEqual(CIDR(string: "192.0.2.130/25")?.networkAddress, hexData("c0000280"))
        XCTAssertEqual(CIDR(string: "2001:db8:1:2::5/48")?.networkAddress,
                       hexData("20010db8000100000000000000000000"))
    }

    /// The address is kept as written so that an interface address survives a
    /// round trip, while matching ignores the host bits.
    func testHostBitsArePreservedButIgnoredForMatching() {
        guard let interface = CIDR(string: "10.7.0.2/24") else {
            XCTFail("fixtures")
            return
        }
        XCTAssertEqual(interface.description, "10.7.0.2/24")
        XCTAssertEqual(interface.address, hexData("0a070002"))
        XCTAssertEqual(interface.networkAddress, hexData("0a070000"))
        XCTAssertTrue(interface.contains(hexData("0a070009")))
    }

    // MARK: - Codable

    func testCodableUsesTheTextualForm() throws {
        let ranges = ["0.0.0.0/0", "10.7.0.2/24", "::/0", "2001:db8::/32", "192.0.2.7/32"]
        let encoded = try JSONEncoder().encode(ranges.compactMap { CIDR(string: $0) })
        // Foundation escapes the solidus in JSON, so undo that before looking
        // for readable text.
        let text = String(decoding: encoded, as: UTF8.self)
            .replacingOccurrences(of: "\\/", with: "/")
        XCTAssertTrue(text.contains("\"0.0.0.0/0\""), text)
        XCTAssertTrue(text.contains("\"2001:db8::/32\""), text)

        let decoded = try JSONDecoder().decode([CIDR].self, from: encoded)
        XCTAssertEqual(decoded.map(\.description), ranges)

        XCTAssertThrowsError(try JSONDecoder().decode(CIDR.self, from: Data("\"nonsense\"".utf8)))
    }

    func testEqualityAndHashing() {
        XCTAssertEqual(CIDR(string: "10.0.0.0/8"), CIDR(string: "10.0.0.0/8"))
        XCTAssertNotEqual(CIDR(string: "10.0.0.0/8"), CIDR(string: "10.0.0.0/9"))
        XCTAssertEqual(Set([CIDR(string: "::/0"), CIDR(string: "::/0")]).count, 1)
    }
}

final class WireGuardKeyTests: XCTestCase {

    func testParsesBase64Keys() {
        // The public key from RFC 7748 section 6.1, base64 encoded.
        let text = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
        guard let key = WireGuardKey(base64: text) else {
            XCTFail("a 44 character base64 key did not parse")
            return
        }
        XCTAssertEqual(key.rawValue.count, 32)
        XCTAssertEqual(hexString(key.rawValue), TestVectors.x25519AlicePublic)
        XCTAssertEqual(key.base64String, text)
        XCTAssertEqual(key.description, text)

        XCTAssertEqual(WireGuardKey(base64: "  \(text)\n")?.base64String, text)
    }

    func testRejectsMalformedKeys() {
        let invalid = [
            "",
            "short",
            "aGVsbG8gd29ybGQ=",                                        // 11 bytes
            "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo",             // 43 characters
            "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo==",           // 45 characters
            "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
        ]
        for text in invalid {
            XCTAssertNil(WireGuardKey(base64: text), "\(text) should not parse")
        }
        XCTAssertNil(WireGuardKey(rawValue: Data(repeating: 0, count: 31)))
        XCTAssertNil(WireGuardKey(rawValue: Data(repeating: 0, count: 33)))
    }

    func testGeneratedKeysDerivePublicKeys() {
        let privateKey = WireGuardKey.generatePrivateKey()
        XCTAssertEqual(privateKey.rawValue.count, 32)
        guard let publicKey = privateKey.derivedPublicKey else {
            XCTFail("could not derive a public key")
            return
        }
        XCTAssertEqual(publicKey.rawValue.count, 32)

        // Deriving again must be stable, and two keys must not collide.
        XCTAssertEqual(privateKey.derivedPublicKey, publicKey)
        XCTAssertNotEqual(WireGuardKey.generatePrivateKey().derivedPublicKey, publicKey)
    }

    func testKeyRoundTripsThroughJSON() throws {
        let key = WireGuardKey.generatePrivateKey()
        let encoded = try JSONEncoder().encode(key)
        // Foundation escapes the solidus inside base64, so undo that before
        // comparing text.
        let text = String(decoding: encoded, as: UTF8.self)
            .replacingOccurrences(of: "\\/", with: "/")
        XCTAssertEqual(text, "\"\(key.base64String)\"")
        XCTAssertEqual(try JSONDecoder().decode(WireGuardKey.self, from: encoded), key)
        XCTAssertThrowsError(try JSONDecoder().decode(WireGuardKey.self, from: Data("\"oops\"".utf8)))
    }
}

final class WireGuardConfigurationTests: XCTestCase {

    private func makeKey() -> Data {
        WireGuardKey.generatePrivateKey().rawValue
    }

    func testDestinationLookupPicksTheMostSpecificPrefix() {
        let specific = WireGuardPeer(publicKey: makeKey(),
                                     endpoint: "192.0.2.1:51820",
                                     allowedIPs: [CIDR(string: "10.7.1.0/24")!])
        let general = WireGuardPeer(publicKey: makeKey(),
                                    endpoint: "198.51.100.1:51820",
                                    allowedIPs: [CIDR(string: "10.0.0.0/8")!])
        let everything = WireGuardPeer(publicKey: makeKey(),
                                       endpoint: "203.0.113.1:51820",
                                       allowedIPs: [CIDR(string: "0.0.0.0/0")!])
        let configuration = WireGuardConfiguration(
            interface: WireGuardInterface(privateKey: makeKey(), addresses: [CIDR(string: "10.7.0.2/24")!]),
            peers: [everything, general, specific]
        )

        XCTAssertEqual(configuration.peer(forDestination: hexData("0a070101"))?.publicKey, specific.publicKey)
        XCTAssertEqual(configuration.peer(forDestination: hexData("0a020101"))?.publicKey, general.publicKey)
        XCTAssertEqual(configuration.peer(forDestination: hexData("c6336401"))?.publicKey, everything.publicKey)
    }

    func testDestinationLookupAcceptsIPv6() {
        let peer = WireGuardPeer(publicKey: makeKey(),
                                 endpoint: "2001:db8::1:51820",
                                 allowedIPs: [CIDR(string: "2001:db8::/32")!])
        let configuration = WireGuardConfiguration(
            interface: WireGuardInterface(privateKey: makeKey(),
                                          addresses: [CIDR(string: "2001:db8::2/64")!]),
            peers: [peer]
        )
        XCTAssertEqual(configuration.peer(forDestination: hexData("20010db8000000000000000000000001"))?.publicKey,
                       peer.publicKey)
        XCTAssertNil(configuration.peer(forDestination: hexData("20010dff000000000000000000000001")))
        XCTAssertNil(configuration.peer(forDestination: hexData("0a070101")))
    }

    func testNoPeerClaimsAnAddress() {
        let configuration = WireGuardConfiguration(
            interface: WireGuardInterface(privateKey: makeKey(), addresses: []),
            peers: [WireGuardPeer(publicKey: makeKey(), allowedIPs: [CIDR(string: "10.7.1.0/24")!])]
        )
        XCTAssertNil(configuration.peer(forDestination: hexData("0a070201")))
        XCTAssertNil(configuration.peer(forDestination: Data()))
    }

    func testDefaultMTUAndClaimedDefaultRoutes() {
        let interface = WireGuardInterface(privateKey: makeKey(), addresses: [])
        XCTAssertEqual(interface.mtu, 1420)
        XCTAssertEqual(WireGuardInterface.defaultMTU, 1420)

        let configuration = WireGuardConfiguration(
            interface: interface,
            peers: [WireGuardPeer(publicKey: makeKey(),
                                  allowedIPs: [CIDR(string: "0.0.0.0/0")!, CIDR(string: "::/0")!])]
        )
        XCTAssertEqual(configuration.claimedDefaultRoutes.count, 2)
    }

    func testConfigurationRoundTripsThroughJSON() throws {
        let privateKey = WireGuardKey.generatePrivateKey()
        let peerKey = WireGuardKey.generatePrivateKey()
        let preshared = WireGuardKey.generatePrivateKey()

        let configuration = WireGuardConfiguration(
            interface: WireGuardInterface(privateKey: privateKey.rawValue,
                                          addresses: [CIDR(string: "10.7.0.2/24")!],
                                          dnsServers: ["10.7.0.1"],
                                          mtu: 1380,
                                          listenPort: 51820),
            peers: [WireGuardPeer(publicKey: peerKey.rawValue,
                                  presharedKey: preshared.rawValue,
                                  endpoint: "vpn.example.com:51820",
                                  allowedIPs: [CIDR(string: "0.0.0.0/0")!, CIDR(string: "::/0")!],
                                  persistentKeepalive: 25)]
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let encoded = try encoder.encode(configuration)

        // Foundation escapes the solidus in JSON; undo that before looking for
        // readable text.
        let text = String(decoding: encoded, as: UTF8.self)
            .replacingOccurrences(of: "\\/", with: "/")
        XCTAssertTrue(text.contains(privateKey.base64String), text)
        XCTAssertTrue(text.contains(peerKey.base64String), text)
        XCTAssertTrue(text.contains(preshared.base64String), text)
        XCTAssertTrue(text.contains("0.0.0.0/0"), text)

        let decoded = try JSONDecoder().decode(WireGuardConfiguration.self, from: encoded)
        XCTAssertEqual(decoded, configuration)
    }

    /// A configuration file may leave out the optional fields; the defaults
    /// must come back.
    func testDecodesMinimalConfiguration() throws {
        let privateKey = WireGuardKey.generatePrivateKey()
        let peerKey = WireGuardKey.generatePrivateKey()
        let json = """
        {
          "interface": { "privateKey": "\(privateKey.base64String)" },
          "peers": [ { "publicKey": "\(peerKey.base64String)" } ]
        }
        """
        let configuration = try JSONDecoder().decode(WireGuardConfiguration.self, from: Data(json.utf8))
        XCTAssertEqual(configuration.interface.mtu, 1420)
        XCTAssertTrue(configuration.interface.addresses.isEmpty)
        XCTAssertTrue(configuration.interface.dnsServers.isEmpty)
        XCTAssertNil(configuration.interface.listenPort)
        XCTAssertEqual(configuration.peers.count, 1)
        XCTAssertNil(configuration.peers[0].presharedKey)
        XCTAssertNil(configuration.peers[0].endpoint)
        XCTAssertTrue(configuration.peers[0].allowedIPs.isEmpty)
        XCTAssertNil(configuration.peers[0].persistentKeepalive)
    }

    func testRejectsMalformedKeysWhenDecoding() {
        let json = """
        {
          "interface": { "privateKey": "not-a-key" },
          "peers": []
        }
        """
        XCTAssertThrowsError(try JSONDecoder().decode(WireGuardConfiguration.self, from: Data(json.utf8)))

        let peerJSON = """
        {
          "interface": { "privateKey": "\(WireGuardKey.generatePrivateKey().base64String)" },
          "peers": [ { "publicKey": "\(WireGuardKey.generatePrivateKey().base64String)", "presharedKey": "x" } ]
        }
        """
        XCTAssertThrowsError(try JSONDecoder().decode(WireGuardConfiguration.self, from: Data(peerJSON.utf8)))
    }
}
