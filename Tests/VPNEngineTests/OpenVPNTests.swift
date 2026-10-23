//
//  OpenVPNTests.swift
//  VPNEngineTests
//
//  Tests for the OpenVPN engine in `Sources/VPNEngine/OpenVPN`.
//
//  Everything here is deterministic: the codecs are driven with explicit
//  packet ids and the reliability layer with explicit timestamps, so no test
//  depends on wall-clock behaviour.
//

import Foundation
import XCTest
@testable import VPNEngine

// MARK: - Fixtures

/// 16 lines of 32 hex characters, byte `n` equal to `n`. The layout makes the
/// 256-byte split of the key file readable in a failure message.
private let ovpnStaticKeyBody: String = {
    var lines: [String] = []
    for line in 0..<16 {
        var text = ""
        for column in 0..<16 {
            let value = line * 16 + column
            text += String(format: "%02x", value)
        }
        lines.append(text)
    }
    return lines.joined(separator: "\n")
}()

private var ovpnStaticKeyPEM: String {
    """
    -----BEGIN OpenVPN Static key V1-----
    \(ovpnStaticKeyBody)
    -----END OpenVPN Static key V1-----
    """
}

/// Deterministic 256-byte static key: byte `n` is `n`.
private var ovpnStaticKey: OVPNStaticKey {
    get throws {
        try OVPNStaticKey(raw: Data((0..<256).map { UInt8($0) }))
    }
}

private func ovpnHex(_ text: String) -> Data {
    var out = Data()
    var index = text.startIndex
    while index < text.endIndex {
        let next = text.index(index, offsetBy: 2)
        out.append(UInt8(text[index..<next], radix: 16) ?? 0)
        index = next
    }
    return out
}

/// A realistic full client configuration, of the shape a provider hands out.
private let ovpnClientConfig = """
# Sample client configuration handed out by an OpenVPN 2.6 server.
; lines may start with a hash or a semicolon
client
dev tun
dev-type tun
proto udp
port 1194
remote vpn.example.com 1194 udp          # primary
remote vpn-backup.example.com 443 tcp-client ; fallback
remote-random
resolv-retry infinite
nobind
persist-key
persist-tun
auth-user-pass
verb 3
mute 20

<ca>
-----BEGIN CERTIFICATE-----
MIIB1TCCAXugAwIBAgIUJmNDgyZXJ0aWZpY2F0ZTBhc2RmcXdl
cmFzZGZhc2RmYXNkZmFzZGZhc2RmYXNkZmFzZGZhc2RmYXNkZg==
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIIB1TCCAXugAwIBAgIUJmNDgyZXJ0aWZpY2F0ZTBhc2RmcXdl
Y2xpZW50Q2VydGlmaWNhdGVCbG9iQmFzZTY0RW5jb2RlZA==
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC3
Y2xpZW50UHJpdmF0ZUtleUJsb2I=
-----END PRIVATE KEY-----
</key>
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
\(ovpnStaticKeyBody)
-----END OpenVPN Static key V1-----
</tls-auth>
key-direction 1

data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-256-CBC
cipher AES-256-GCM
auth SHA256
tls-version-min 1.2
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
remote-cert-tls server
verify-x509-name "vpn.example.com" name
reneg-sec 3600
hand-window 60
tls-timeout 2
mtu 1400
mssfix 1360
replay-window 64 15
redirect-gateway def1
block-outside-dns
route 10.10.0.0 255.255.0.0
route 192.168.50.0 255.255.255.0 vpn_gateway 5
route-ipv6 2001:db8::/32 vpn_gateway
pull-filter ignore "redirect-gateway"
pull-filter accept "route" 10.10.0.0
dhcp-option DNS 10.8.0.1
dhcp-option DNS 1.1.1.1
dhcp-option DOMAIN example.internal
ping 10
ping-restart 60
comp-lzo no
explicit-exit-notify 1
topology subnet
"""

/// `--secret` static key configuration.
private let ovpnStaticKeyConfig = """
dev tun
proto udp
remote 203.0.113.5 1194
lport 1194
cipher AES-256-CBC
auth SHA256
<secret>
\(ovpnStaticKeyPEM)
</secret>
persist-tun
verb 4
"""

/// `--tls-crypt` configuration, key referenced from disk.
private let ovpnTLSCryptConfig = """
client
dev tun
proto tcp
remote vpn.example.net 443 tcp-server
tls-crypt ta.key 0
key-direction 0
cipher AES-256-GCM
auth SHA1
"""

/// `--tls-crypt-v2` configuration with the client key inlined.
private var ovpnTLSCryptV2Config: String {
    // 200 bytes of wrapped client key followed by a 128-byte key block, which
    // is what `--tls-crypt-v2-genkey` writes.
    var blob = Data()
    blob.append(Data((0..<200).map { UInt8($0 % 251) }))
    blob.append(Data((0..<128).map { UInt8(($0 * 7) % 256) }))
    let base64 = blob.base64EncodedString()
    var lines: [String] = []
    var index = base64.startIndex
    while index < base64.endIndex {
        let next = base64.index(index, offsetBy: 64, limitedBy: base64.endIndex) ?? base64.endIndex
        lines.append(String(base64[index..<next]))
        index = next
    }
    return """
    client
    dev tun
    proto udp
    remote 198.51.100.9 1194
    remote-random-hostname
    <tls-crypt-v2>
    -----BEGIN OpenVPN tls-crypt-v2 client key-----
    \(lines.joined(separator: "\n"))
    -----END OpenVPN tls-crypt-v2 client key-----
    </tls-crypt-v2>
    cipher AES-256-GCM
    """
}

// MARK: - Configuration parsing

final class OVPNConfigurationTests: XCTestCase {

    func testParsesFullClientConfiguration() throws {
        let config = try OVPNConfiguration.parse(ovpnClientConfig)

        // Transport
        XCTAssertEqual(config.remotes.count, 2)
        XCTAssertEqual(config.remotes[0].host, "vpn.example.com")
        XCTAssertEqual(config.remotes[0].port, 1194)
        XCTAssertEqual(config.remotes[0].proto, .udp)
        XCTAssertEqual(config.remotes[1].host, "vpn-backup.example.com")
        XCTAssertEqual(config.remotes[1].port, 443)
        XCTAssertEqual(config.remotes[1].proto, .tcpClient)
        XCTAssertTrue(config.remotes[0].isRandom, "remote-random marks every remote as part of the pool")
        XCTAssertEqual(config.proto, .udp)
        XCTAssertEqual(config.port, 1194)
        XCTAssertTrue(config.nobind)
        XCTAssertTrue(config.remoteRandom)
        XCTAssertTrue(config.pull)
        XCTAssertTrue(config.tlsClient)
        XCTAssertFalse(config.isStaticKeyMode)

        // Device
        XCTAssertEqual(config.dev, "tun")
        XCTAssertEqual(config.devType, .tun)

        // Embedded credentials and certificates
        XCTAssertTrue(config.authUserPass)
        XCTAssertTrue(config.ca?.hasPrefix("-----BEGIN CERTIFICATE-----") ?? false)
        XCTAssertTrue(config.ca?.hasSuffix("-----END CERTIFICATE-----") ?? false)
        XCTAssertTrue(config.cert?.contains("BEGIN CERTIFICATE") ?? false)
        XCTAssertTrue(config.key?.contains("BEGIN PRIVATE KEY") ?? false)
        XCTAssertNil(config.caPath)
        XCTAssertNil(config.certPath)
        XCTAssertNil(config.keyPath)

        // tls-auth
        XCTAssertNil(config.tlsCrypt)
        XCTAssertEqual(config.tlsAuth?.inline != nil, true)
        XCTAssertNil(config.tlsAuth?.path)
        XCTAssertEqual(config.keyDirection, 1)
        let tlsAuthKey = try XCTUnwrap(config.tlsAuthKeyFile)
        XCTAssertEqual(tlsAuthKey.direction, 1)
        XCTAssertEqual(tlsAuthKey.key.raw.count, 256)
        XCTAssertEqual(tlsAuthKey.key.raw, try ovpnStaticKey.raw)

        // Crypto
        XCTAssertEqual(config.cipher, "AES-256-GCM")
        XCTAssertEqual(config.dataCiphers, ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"])
        XCTAssertEqual(config.dataCiphersFallback, "AES-256-CBC")
        XCTAssertEqual(config.auth, "SHA256")
        XCTAssertEqual(config.negotiationCiphers, ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-256-CBC"])
        XCTAssertEqual(config.tlsVersionMin, "1.2")
        XCTAssertEqual(config.tlsCipher, "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384")
        XCTAssertEqual(config.replayWindow, 64)
        XCTAssertFalse(config.replayDisabled)

        // Certificate verification
        XCTAssertEqual(config.nsCertType, "server")
        XCTAssertEqual(config.verifyX509Name, "vpn.example.com")
        XCTAssertEqual(config.verifyX509NameType, "name")
        XCTAssertNil(config.tlsRemote)

        // Routing
        XCTAssertTrue(config.redirectGateway)
        XCTAssertTrue(config.blockOutsideDNS)
        XCTAssertEqual(config.routes.count, 3)
        XCTAssertEqual(config.routes[0].network, "10.10.0.0")
        XCTAssertEqual(config.routes[0].netmask, "255.255.0.0")
        XCTAssertNil(config.routes[0].gateway)
        XCTAssertEqual(config.routes[0].cidrNotation, "10.10.0.0/16")
        XCTAssertEqual(config.routes[1].gateway, "vpn_gateway")
        XCTAssertEqual(config.routes[1].metric, 5)
        XCTAssertEqual(config.routes[2].network, "2001:db8::/32")
        XCTAssertTrue(config.routes[2].isIPv6)
        XCTAssertEqual(config.routes[2].gateway, "vpn_gateway")

        // Pull filters
        XCTAssertEqual(config.pullFilters.count, 2)
        XCTAssertEqual(config.typedPullFilters.count, 2)
        XCTAssertEqual(config.typedPullFilters[0].action, .ignore)
        XCTAssertEqual(config.typedPullFilters[0].option, "redirect-gateway")
        XCTAssertEqual(config.typedPullFilters[1].action, .accept)
        XCTAssertEqual(config.typedPullFilters[1].value, "10.10.0.0")

        // DNS
        XCTAssertEqual(config.dnsServers, ["10.8.0.1", "1.1.1.1"])

        // Timing and tuning
        XCTAssertEqual(config.renegSec, 3600)
        XCTAssertEqual(config.handWindow, 60)
        XCTAssertEqual(config.mtu, 1400)
        XCTAssertEqual(config.mssFix, 1360)
        XCTAssertEqual(config.pingInterval, 10)
        XCTAssertEqual(config.pingRestart, 60)
        XCTAssertTrue(config.persistentTun)
        XCTAssertTrue(config.persistKey)
        XCTAssertEqual(config.verb, 3)
        XCTAssertEqual(config.topology, "subnet")
        XCTAssertEqual(config.explicitExitNotify, 1)
        XCTAssertEqual(config.compLZO, "no")

        // The comments must not have leaked into values.
        XCTAssertFalse(config.parseWarnings.contains { $0.contains("primary") })
        XCTAssertFalse(config.parseWarnings.contains { $0.contains("fallback") })
        XCTAssertFalse(config.parseWarnings.contains { $0.contains("No 'remote'") })
    }

    func testPreservesUnknownDirectivesAndWarnsAboutUnsupportedOnes() throws {
        let config = try OVPNConfiguration.parse("""
        client
        remote vpn.example.com
        made-up-directive some value here
        made-up-directive second value
        socks-proxy 127.0.0.1 1080
        """)

        XCTAssertEqual(config.extra["made-up-directive"], ["some value here", "second value"])
        XCTAssertTrue(config.parseWarnings.contains { $0.contains("socks-proxy") })
    }

    func testParsesStaticKeyConfiguration() throws {
        let config = try OVPNConfiguration.parse(ovpnStaticKeyConfig)

        XCTAssertTrue(config.isStaticKeyMode)
        XCTAssertFalse(config.isTLSMode)
        XCTAssertNil(config.tlsAuth)
        XCTAssertNil(config.tlsCrypt)
        XCTAssertEqual(config.cipher, "AES-256-CBC")
        XCTAssertEqual(config.auth, "SHA256")
        XCTAssertEqual(config.remotes.count, 1)
        XCTAssertEqual(config.remotes[0].host, "203.0.113.5")
        XCTAssertEqual(config.remotes[0].port, 1194)
        XCTAssertEqual(config.localPort, 1194)
        XCTAssertEqual(config.verb, 4)

        let keyFile = try config.loadStaticKeyFile()
        XCTAssertNil(keyFile.direction, "no key-direction means bidirectional")
        XCTAssertEqual(keyFile.key.raw, try ovpnStaticKey.raw)
        XCTAssertEqual(config.staticKey?.key.raw, try ovpnStaticKey.raw)
    }

    func testParsesTLSCryptConfiguration() throws {
        let config = try OVPNConfiguration.parse(ovpnTLSCryptConfig)

        XCTAssertFalse(config.isStaticKeyMode)
        XCTAssertNil(config.tlsAuth)
        XCTAssertNil(config.tlsCrypt?.inline)
        XCTAssertEqual(config.tlsCrypt?.path, "ta.key")
        XCTAssertEqual(config.tlsCrypt?.direction, 0)
        XCTAssertEqual(config.keyDirection, 0)
        XCTAssertEqual(config.proto, .tcpClient)
        XCTAssertEqual(config.remotes[0].proto, .tcpServer)
        XCTAssertEqual(config.cipher, "AES-256-GCM")
        XCTAssertEqual(config.auth, "SHA1")

        // Inline form: the same block the tls-auth config used.
        let inline = try OVPNConfiguration.parse("""
        client
        remote vpn.example.net
        <tls-crypt>
        \(ovpnStaticKeyPEM)
        </tls-crypt>
        key-direction 0
        """)
        let keyFile = try XCTUnwrap(inline.tlsCryptKeyFile)
        XCTAssertEqual(keyFile.key.raw.count, 256)
        XCTAssertEqual(inline.tlsCrypt?.inline?.contains("BEGIN OpenVPN Static key V1"), true)
    }

    func testParsesTLSCryptV2Configuration() throws {
        let config = try OVPNConfiguration.parse(ovpnTLSCryptV2Config)

        XCTAssertNotNil(config.tlsCryptV2)
        let clientKey = try XCTUnwrap(config.tlsCryptV2ClientKey)
        XCTAssertEqual(clientKey.wrappedClientKey.count, 200)
        XCTAssertEqual(clientKey.key.raw.count, 128)
        XCTAssertEqual(clientKey.raw.count, 328)
        XCTAssertEqual(try config.loadTLSCryptV2ClientKey()?.raw, clientKey.raw)

        // The wrapped key round trips through its textual representation.
        XCTAssertEqual(OVPNTlsCryptV2ClientKey.parse(clientKey.pemRepresentation)?.raw, clientKey.raw)
    }

    func testQuotedValuesAndContinuations() throws {
        let config = try OVPNConfiguration.parse("""
        remote "vpn with space.example.com" 1194
        push "route 10.0.0.0 255.0.0.0" \\
             "dhcp-option DNS 10.0.0.1"
        """)

        XCTAssertEqual(config.remotes[0].host, "vpn with space.example.com")
        XCTAssertEqual(config.remotes[0].port, 1194)
        XCTAssertEqual(config.pushes.count, 1)
        // Values that contain spaces are re-quoted so the stored form can be
        // tokenised again.
        XCTAssertEqual(config.pushes[0], #""route 10.0.0.0 255.0.0.0" "dhcp-option DNS 10.0.0.1""#)
    }

    func testConnectionBlocksAreFlattened() throws {
        let config = try OVPNConfiguration.parse("""
        client
        <connection>
        remote first.example.com 1194 udp
        </connection>
        <connection>
        remote second.example.com 443 tcp
        </connection>
        """)

        XCTAssertEqual(config.remotes.map(\.host), ["first.example.com", "second.example.com"])
        XCTAssertEqual(config.remotes[1].port, 443)
        XCTAssertEqual(config.remotes[1].proto, .tcpClient)
        XCTAssertTrue(config.parseWarnings.contains { $0.contains("flattened") })
    }
}

// MARK: - Static key format

final class OVPNStaticKeyTests: XCTestCase {

    func testParsesSixteenLineKeyBody() throws {
        let key = try XCTUnwrap(OVPNStaticKey.parse(ovpnStaticKeyPEM))

        XCTAssertEqual(key.raw.count, 256)
        XCTAssertEqual(key.raw[0], 0x00)
        XCTAssertEqual(key.raw[15], 0x0F)
        XCTAssertEqual(key.raw[16], 0x10)
        XCTAssertEqual(key.raw[255], 0xFF)

        // The documented split: keys[0] = cipher[64] || hmac[64],
        // keys[1] = cipher[64] || hmac[64].
        XCTAssertEqual(key.cipherKey.count, 64)
        XCTAssertEqual(key.hmacKey.count, 64)
        XCTAssertEqual(key.clientSendKey.count, 128)
        XCTAssertEqual(key.serverSendKey.count, 128)
        XCTAssertEqual(key.cipherKey, key.raw.prefix(64))
        XCTAssertEqual(key.hmacKey, key.raw[64..<128])
        XCTAssertEqual(key.clientSendKey, key.raw.prefix(128))
        XCTAssertEqual(key.serverSendKey, key.raw.suffix(128))

        // The identities that make `key-direction` work.
        XCTAssertEqual(key.clientSendKey, key.serverRecvKey)
        XCTAssertEqual(key.serverSendKey, key.clientRecvKey)
        XCTAssertNotEqual(key.clientSendKey, key.serverSendKey)

        // Key blocks must line up with the direction helper.
        XCTAssertEqual(key.sendKey(direction: .normal).cipherKey, key.cipherKey)
        XCTAssertEqual(key.recvKey(direction: .normal).cipherKey, key.raw[128..<192])
        XCTAssertEqual(key.sendKey(direction: .inverse).cipherKey, key.raw[128..<192])
        XCTAssertEqual(key.recvKey(direction: .inverse).cipherKey, key.cipherKey)
        XCTAssertEqual(key.sendKey(direction: nil).cipherKey, key.cipherKey)
        XCTAssertEqual(key.recvKey(direction: nil).cipherKey, key.cipherKey, "bidirectional always uses keys[0]")
    }

    func testRejectsMalformedKeyBodies() {
        XCTAssertNil(OVPNStaticKey.parse("not a key at all"))
        XCTAssertNil(OVPNStaticKey.parse("-----BEGIN OpenVPN Static key V1-----\n00ff\n-----END OpenVPN Static key V1-----"))
        XCTAssertNil(OVPNStaticKey.parse(""))
        // Odd number of hex digits.
        XCTAssertNil(OVPNStaticKey.parse(String(repeating: "a", count: 511)))
    }

    func testPEMRoundTrip() throws {
        let key = try ovpnStaticKey
        let text = key.pemRepresentation
        XCTAssertTrue(text.hasPrefix(OVPNStaticKey.beginMarker))
        XCTAssertTrue(text.hasSuffix(OVPNStaticKey.endMarker + "\n"))
        XCTAssertEqual(OVPNStaticKey.parse(text)?.raw, key.raw)

        // Freshly generated material is the right shape too.
        let generated = OVPNStaticKey.generate()
        XCTAssertEqual(generated.raw.count, 256)
        XCTAssertEqual(OVPNStaticKey.parse(generated.pemRepresentation)?.raw, generated.raw)
    }

    func testKeyBlockImplicitIV() throws {
        let key = try ovpnStaticKey
        // Two 64-byte halves, and the implicit IV comes from the *start of the
        // HMAC field*, placed at offset 4 of a 12-byte nonce.
        let block = try OVPNKeyBlock(raw: key.clientSendKey)
        XCTAssertEqual(block.cipherKey, key.raw.prefix(64))
        XCTAssertEqual(block.hmacKey, key.raw[64..<128])
        XCTAssertEqual(try block.cipherKey(length: 32), key.raw.prefix(32))
        XCTAssertEqual(try block.hmacKey(digestLength: 32), key.raw[64..<96])

        let iv = block.implicitIV(ivLength: 12)
        XCTAssertEqual(iv.count, 12)
        XCTAssertEqual(iv.prefix(4), Data(repeating: 0, count: 4))
        XCTAssertEqual(iv.suffix(8), key.raw[64..<72])
    }
}

// MARK: - Data channel

final class OVPNDataChannelTests: XCTestCase {

    private func bidirectionalKeys(cipher: OVPNCipherSpec) -> OVPNDataKeys {
        OVPNDataKeys.bidirectional(
            cipherKey: ovpnHex(String(repeating: "ab", count: cipher.keyLength)),
            hmacKey: ovpnHex(String(repeating: "cd", count: 32)),
            implicitIV: ovpnHex("010203040506070800000000")
        )
    }

    private func makePair(cipher: String, digest: String?) throws -> (OVPNPacketCodec, OVPNPacketCodec) {
        let spec = try XCTUnwrap(OVPNCipherSpec.parse(cipher))
        var sender = try OVPNPacketCodec(cipher: cipher, digest: digest, staticKeyMode: true, senderKeyId: 0)
        var receiver = try OVPNPacketCodec(cipher: cipher, digest: digest, staticKeyMode: true, senderKeyId: 0)
        let keys = bidirectionalKeys(cipher: spec)
        sender.installKeys(keys)
        receiver.installKeys(keys)
        return (sender, receiver)
    }

    /// A believable IPv4 + UDP packet (20 byte header + 8 byte UDP header).
    private var samplePacket: Data {
        var packet = Data()
        packet.append(contentsOf: [0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, 0x11])
        packet.append(contentsOf: [0x00, 0x00])            // checksum
        packet.append(contentsOf: [10, 8, 0, 2])           // source
        packet.append(contentsOf: [10, 8, 0, 1])           // destination
        packet.append(contentsOf: [0x04, 0xD2, 0x00, 0x35, 0x00, 0x28, 0x00, 0x00])
        packet.append(Data("openvpn test payload".utf8))
        return packet
    }

    func testAES256CBCRoundTripIncludingFullPaddingBlock() throws {
        let (sender, receiver) = try makePair(cipher: "AES-256-CBC", digest: "SHA256")
        XCTAssertEqual(sender.cipher, .aesCBC(name: "AES-256-CBC"))
        XCTAssertEqual(sender.digest, .sha256)
        XCTAssertTrue(sender.longFormPacketID, "non-AEAD ciphers use the long form packet id")

        // Payload sized so that packet id (8) + payload is exactly one block:
        // PKCS#7 then has to add a whole extra block of padding.
        let alignedPayload = Data(repeating: 0x45, count: 8)
        let datagram = try sender.encode(packet: alignedPayload, sequence: 1)
        XCTAssertEqual(datagram.count, 1 + 32 + 16 + 32, "opcode + HMAC-SHA256 + IV + two cipher blocks")
        XCTAssertEqual(datagram[0] >> 3, OVPNControlOpcode.dataV1.rawValue)
        XCTAssertEqual(datagram[0] & OVPNControlOpcode.keyIDMask, 0)
        XCTAssertEqual(try receiver.decode(datagram), alignedPayload)

        // A payload that needs partial padding, and a realistic IP packet for
        // good measure.
        let partialPayload = Data(repeating: 0x46, count: 20)
        let partial = try sender.encode(packet: partialPayload, sequence: 2)
        XCTAssertEqual(partial.count, 1 + 32 + 16 + 32)
        XCTAssertEqual(try receiver.decode(partial), partialPayload)

        let realistic = try sender.encode(packet: samplePacket, sequence: 3)
        XCTAssertEqual(try receiver.decode(realistic), samplePacket)

        // A full block payload.
        let block = Data(repeating: 0x47, count: 16)
        XCTAssertEqual(try receiver.decode(try sender.encode(packet: block, sequence: 4)), block)

        // Every packet used a fresh IV, so the ciphertexts differ.
        XCTAssertNotEqual(datagram.suffix(32), try sender.encode(packet: alignedPayload, sequence: 5).suffix(32))
    }

    func testAES256CBCRejectsTamperedCiphertext() throws {
        let (sender, receiver) = try makePair(cipher: "AES-256-CBC", digest: "SHA256")
        var datagram = try sender.encode(packet: samplePacket, sequence: 9)
        datagram[datagram.count - 1] ^= 0x01
        XCTAssertThrowsError(try receiver.decode(datagram)) { error in
            XCTAssertEqual(error as? OVPNError, .authenticationFailed)
        }

        // A tampered IV fails the HMAC as well.
        var ivTampered = try sender.encode(packet: samplePacket, sequence: 10)
        ivTampered[1 + 32] ^= 0x80
        XCTAssertThrowsError(try receiver.decode(ivTampered)) { error in
            XCTAssertEqual(error as? OVPNError, .authenticationFailed)
        }

        // Truncated packets must throw, never crash.
        XCTAssertThrowsError(try receiver.decode(Data([0x30, 0x00])))
        XCTAssertThrowsError(try receiver.decode(Data()))
    }

    func testAES256GCMRoundTrip() throws {
        let (sender, receiver) = try makePair(cipher: "AES-256-GCM", digest: nil)
        XCTAssertEqual(sender.cipher, .aesGCM(name: "AES-256-GCM"))
        XCTAssertEqual(sender.digest, .none)
        XCTAssertFalse(sender.longFormPacketID, "AEAD ciphers use the short packet id as the nonce")

        let datagram = try sender.encode(packet: samplePacket, sequence: 42)
        // opcode + packet id + tag + ciphertext
        XCTAssertEqual(datagram.count, 1 + 4 + 16 + samplePacket.count)
        XCTAssertEqual(try OVPNWire.readUInt32(datagram, at: 1, field: "packet id"), 42)
        XCTAssertEqual(try receiver.decode(datagram), samplePacket)

        // The 4-byte packet id is authenticated: changing it breaks the tag.
        var wrongID = datagram
        wrongID[1] ^= 0x01
        XCTAssertThrowsError(try receiver.decode(wrongID)) { error in
            XCTAssertEqual(error as? OVPNError, .authenticationFailed)
        }

        // ... and so is the opcode byte, which is part of the additional data.
        var wrongOpcode = datagram
        wrongOpcode[0] = OVPNControlOpcode.opcodeByte(.dataV1, keyID: 1)
        XCTAssertThrowsError(try receiver.decode(wrongOpcode))
    }

    func testChaCha20Poly1305RoundTrip() throws {
        let (sender, receiver) = try makePair(cipher: "CHACHA20-POLY1305", digest: nil)
        XCTAssertEqual(sender.cipher, .chacha20Poly1305)

        let datagram = try sender.encode(packet: samplePacket, sequence: 7)
        XCTAssertEqual(datagram.count, 1 + 4 + 16 + samplePacket.count)
        XCTAssertEqual(try receiver.decode(datagram), samplePacket)

        // A tag/payload bit flip on a *fresh* packet id must fail
        // authentication (a replay of the same id is caught earlier).
        var tampered = try sender.encode(packet: samplePacket, sequence: 8)
        tampered[tampered.count - 1] ^= 0xFF
        XCTAssertThrowsError(try receiver.decode(tampered)) { error in
            XCTAssertEqual(error as? OVPNError, .authenticationFailed)
        }
        var flippedTag = try sender.encode(packet: samplePacket, sequence: 9)
        flippedTag[flippedTag.count - (samplePacket.count + 1)] ^= 0x01
        XCTAssertThrowsError(try receiver.decode(flippedTag)) { error in
            XCTAssertEqual(error as? OVPNError, .authenticationFailed)
        }
    }

    func testReplayProtectionRejectsCapturedDatagrams() throws {
        let (sender, receiver) = try makePair(cipher: "AES-256-CBC", digest: "SHA256")
        let datagram = try sender.encode(packet: samplePacket, sequence: 7)

        XCTAssertEqual(try receiver.decode(datagram), samplePacket)
        XCTAssertThrowsError(try receiver.decode(datagram)) { error in
            XCTAssertEqual(error as? OVPNError, .replayDetected(id: 7))
        }

        // Out of order but inside the window is fine, once.
        let later = try sender.encode(packet: Data("later".utf8), sequence: 9)
        XCTAssertEqual(try receiver.decode(later), Data("later".utf8))
        let earlier = try sender.encode(packet: Data("earlier".utf8), sequence: 8)
        XCTAssertEqual(try receiver.decode(earlier), Data("earlier".utf8))
        XCTAssertThrowsError(try receiver.decode(earlier)) { error in
            XCTAssertEqual(error as? OVPNError, .replayDetected(id: 8))
        }

        // Anything below the 64-packet window is rejected as too old.
        let ancient = try sender.encode(packet: Data("ancient".utf8), sequence: 200)
        XCTAssertEqual(try receiver.decode(ancient), Data("ancient".utf8))
        let stale = try sender.encode(packet: Data("stale".utf8), sequence: 100)
        XCTAssertThrowsError(try receiver.decode(stale)) { error in
            XCTAssertEqual(error as? OVPNError, .replayDetected(id: 100))
        }
    }

    func testReplayProtectionForAEADAndWindowClass() throws {
        let (sender, receiver) = try makePair(cipher: "AES-256-GCM", digest: nil)
        let datagram = try sender.encode(packet: samplePacket, sequence: 12)
        XCTAssertEqual(try receiver.decode(datagram), samplePacket)
        XCTAssertThrowsError(try receiver.decode(datagram)) { error in
            XCTAssertEqual(error as? OVPNError, .replayDetected(id: 12))
        }

        // The window itself: duplicate, too old, in-window and ahead.
        let window = OVPNReplayWindow(windowSize: 4, timeBacktrack: nil)
        try window.testAndMark(sequence: 10)
        XCTAssertThrowsError(try window.testAndMark(sequence: 10))
        try window.testAndMark(sequence: 11)
        try window.testAndMark(sequence: 9)
        try window.testAndMark(sequence: 8)
        XCTAssertThrowsError(try window.testAndMark(sequence: 7), "outside the 4 packet window")
        try window.testAndMark(sequence: 100)
        XCTAssertEqual(window.highestSequence, 100)
        XCTAssertThrowsError(try window.testAndMark(sequence: 11), "the window was reset by the jump")
        // Sequence 0 means "no packet id" and is not replay protected.
        try window.testAndMark(sequence: 0)
        try window.testAndMark(sequence: 0)

        // A long-form id of 0 with a timestamp is still a real packet id.
        let timestamped = OVPNReplayWindow(windowSize: 4, timeBacktrack: 15)
        try timestamped.testAndMark(sequence: 0, timestamp: 1_000)
        XCTAssertThrowsError(try timestamped.testAndMark(sequence: 0, timestamp: 1_000))
        XCTAssertThrowsError(try timestamped.testAndMark(sequence: 1, timestamp: 900)) { error in
            XCTAssertEqual(error as? OVPNError, .replayDetected(id: 1))
        }
    }

    func testCodecRejectsUnsupportedAlgorithmsAndMissingKeys() throws {
        XCTAssertThrowsError(try OVPNPacketCodec(cipher: "BF-CBC", digest: "SHA1", staticKeyMode: true, senderKeyId: 0)) { error in
            XCTAssertEqual(error as? OVPNError, .unsupportedCipher("BF-CBC"))
        }
        XCTAssertThrowsError(try OVPNPacketCodec(cipher: "AES-256-GCM", digest: "MD5", staticKeyMode: true, senderKeyId: 0)) { error in
            XCTAssertEqual(error as? OVPNError, .unsupportedDigest("MD5"))
        }
        XCTAssertThrowsError(try OVPNPacketCodec(cipher: "AES-256-CBC", digest: "none", staticKeyMode: true, senderKeyId: 0))

        let codec = try OVPNPacketCodec(cipher: "AES-256-GCM", digest: nil, staticKeyMode: true, senderKeyId: 0)
        XCTAssertThrowsError(try codec.encode(packet: samplePacket, sequence: 1)) { error in
            XCTAssertEqual(error as? OVPNError, .keyNotInstalled)
        }
        XCTAssertThrowsError(try codec.decode(Data(repeating: 0, count: 64))) { error in
            XCTAssertEqual(error as? OVPNError, .keyNotInstalled)
        }
    }

    func testPacketModeTAPDoesNotPad() throws {
        let spec = try XCTUnwrap(OVPNCipherSpec.parse("AES-256-CBC"))
        var sender = try OVPNPacketCodec(cipher: "AES-256-CBC", digest: "SHA256", staticKeyMode: true, senderKeyId: 0)
        var receiver = try OVPNPacketCodec(cipher: "AES-256-CBC", digest: "SHA256", staticKeyMode: true, senderKeyId: 0)
        sender.packetMode = .tap
        receiver.packetMode = .tap
        let keys = bidirectionalKeys(cipher: spec)
        sender.installKeys(keys)
        receiver.installKeys(keys)

        // 8 bytes of packet id + 40 bytes of frame = 48 bytes: exactly three
        // blocks, no padding at all.
        let frame = Data((0..<40).map { UInt8($0) })
        let datagram = try sender.encode(packet: frame, sequence: 1)
        XCTAssertEqual(datagram.count, 1 + 32 + 16 + 48)
        XCTAssertEqual(try receiver.decode(datagram), frame)
    }

    func testDataV2CarriesPeerID() throws {
        let spec = try XCTUnwrap(OVPNCipherSpec.parse("AES-256-GCM"))
        var sender = try OVPNPacketCodec(cipher: "AES-256-GCM", digest: nil, staticKeyMode: false, senderKeyId: 0)
        var receiver = try OVPNPacketCodec(cipher: "AES-256-GCM", digest: nil, staticKeyMode: false, senderKeyId: 0)
        receiver.useDataV2 = true
        sender.useDataV2 = true
        sender.peerID = 3
        let keys = bidirectionalKeys(cipher: spec)
        sender.installKeys(keys)
        receiver.installKeys(keys)

        let datagram = try sender.encode(packet: samplePacket, sequence: 1)
        XCTAssertEqual(datagram[0] >> 3, OVPNControlOpcode.dataV2.rawValue)
        XCTAssertEqual(datagram.count, 1 + 3 + 4 + 16 + samplePacket.count)

        let inbound = try receiver.decodeAnnotated(datagram)
        XCTAssertEqual(inbound.peerID, 3)
        XCTAssertEqual(inbound.opcode, .dataV2)
        XCTAssertEqual(inbound.payload, samplePacket)
    }

    func testKeyDerivationFromStaticKeyFile() throws {
        let keyFile = OVPNStaticKeyFile(direction: nil, key: try ovpnStaticKey)
        let spec = try XCTUnwrap(OVPNCipherSpec.parse("AES-256-GCM"))
        let keys = try OVPNKeyDerivation.dataKeys(fromStaticKeyFile: keyFile, cipher: spec, hmac: nil)
        XCTAssertEqual(keys.sendCipherKey, try ovpnStaticKey.cipherKey.prefix(32))
        XCTAssertEqual(keys.sendCipherKey, keys.receiveCipherKey, "bidirectional")
        // The implicit IV sits at offset 4 and is the start of the HMAC field.
        XCTAssertEqual(keys.implicitIVSend.suffix(8), try ovpnStaticKey.hmacKey.prefix(8))
        XCTAssertEqual(keys.implicitIVSend.prefix(4), Data(repeating: 0, count: 4))

        // Client and server derive mirror-image keys from the same material.
        let client = try OVPNKeyDerivation.dataKeys(
            fromKeyMaterial: ovpnStaticKey.raw,
            isServer: false,
            cipher: spec,
            hmac: nil
        )
        let server = try OVPNKeyDerivation.dataKeys(
            fromKeyMaterial: ovpnStaticKey.raw,
            isServer: true,
            cipher: spec,
            hmac: nil
        )
        XCTAssertEqual(client.sendCipherKey, server.receiveCipherKey)
        XCTAssertEqual(client.receiveCipherKey, server.sendCipherKey)
    }

    func testNegotiatedCipherDefaults() throws {
        let config = try OVPNConfiguration.parse(ovpnStaticKeyConfig)
        let negotiated = try OVPNKeyDerivation.negotiatedCipher(configuration: config)
        XCTAssertEqual(negotiated.cipher.name, "AES-256-CBC")
        XCTAssertEqual(negotiated.hmac, .sha256)

        // A pushed AEAD cipher needs no digest at all.
        let client = try OVPNConfiguration.parse(ovpnClientConfig)
        let pushed = try OVPNKeyDerivation.negotiatedCipher(configuration: client, pushedCipher: "AES-128-GCM")
        XCTAssertEqual(pushed.cipher.name, "AES-128-GCM")
        XCTAssertNil(pushed.hmac)

        XCTAssertThrowsError(try OVPNKeyDerivation.negotiatedCipher(configuration: OVPNConfiguration(), pushedCipher: "SEED-CBC"))
    }
}

// MARK: - PUSH_REPLY

final class OVPNPushReplyTests: XCTestCase {

    func testParsesTypicalPushReply() throws {
        let text = "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,route-gateway 10.8.0.1,"
            + "topology subnet,redirect-gateway def1,dhcp-option DNS 10.0.0.1,"
            + "dhcp-option DOMAIN \"corp.example.com\",cipher AES-256-GCM,peer-id 3,"
            + "ping 10,ping-restart 60,mssfix 1400,key-derivation tls-ekm,"
            + "route 10.10.0.0 255.255.0.0,explicit-exit-notify 1,made-up-option value\0"

        let reply = OVPNPushReply.parse(text)

        XCTAssertEqual(reply.ifconfig?.localAddress, "10.8.0.2")
        XCTAssertEqual(reply.ifconfig?.secondArgument, "255.255.255.0")
        XCTAssertTrue(reply.ifconfig?.secondArgumentIsNetmask ?? false)
        XCTAssertEqual(reply.ifconfig?.prefixLength, 24)
        XCTAssertNil(reply.ifconfigIPv6)
        XCTAssertEqual(reply.routeGateway, "10.8.0.1")
        XCTAssertEqual(reply.topology, "subnet")
        XCTAssertTrue(reply.redirectGateway)
        XCTAssertEqual(reply.redirectGatewayFlags, ["def1"])
        XCTAssertEqual(reply.dnsServers, ["10.0.0.1"])
        XCTAssertEqual(reply.dnsSearchDomains, ["corp.example.com"])
        XCTAssertEqual(reply.cipher, "AES-256-GCM")
        XCTAssertEqual(reply.peerID, 3)
        XCTAssertEqual(reply.pingInterval, 10)
        XCTAssertEqual(reply.pingRestart, 60)
        XCTAssertEqual(reply.mssFix, 1400)
        XCTAssertEqual(reply.keyDerivation, "tls-ekm")
        XCTAssertEqual(reply.explicitExitNotify, 1)
        XCTAssertEqual(reply.routes.count, 1)
        XCTAssertEqual(reply.routes[0].cidrNotation, "10.10.0.0/16")
        XCTAssertEqual(reply.unknown["made-up-option"], ["value"])
        XCTAssertTrue(reply.parseWarnings.isEmpty)
        XCTAssertEqual(reply.rawOptions.count, 15)
    }

    func testParsesPushReplyWithoutPrefixOrNull() throws {
        let reply = OVPNPushReply.parse("ifconfig 10.8.0.6 10.8.0.5,cipher AES-256-CBC")
        XCTAssertEqual(reply.ifconfig?.localAddress, "10.8.0.6")
        XCTAssertEqual(reply.ifconfig?.secondArgument, "10.8.0.5")
        XCTAssertFalse(reply.ifconfig?.secondArgumentIsNetmask ?? true, "net30 peer address, not a netmask")
        XCTAssertNil(reply.ifconfig?.prefixLength)
        XCTAssertEqual(reply.cipher, "AES-256-CBC")
    }

    func testPushReplyHonoursPullFilters() throws {
        let filters = [
            OVPNPullFilter(action: .ignore, option: "redirect-gateway"),
            OVPNPullFilter(action: .reject, option: "route", value: "192.168."),
        ]
        let reply = OVPNPushReply.parse(
            "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,redirect-gateway def1,"
                + "route 192.168.1.0 255.255.255.0,route 10.0.0.0 255.0.0.0",
            filters: filters
        )
        XCTAssertFalse(reply.redirectGateway)
        XCTAssertEqual(reply.ignoredOptions.count, 1)
        XCTAssertEqual(reply.rejectedOptions.count, 1)
        XCTAssertEqual(reply.routes.map(\.network), ["10.0.0.0"])
    }

    func testPushRequestPayloadIsNULTerminated() throws {
        XCTAssertEqual(OVPNPushReply.pushRequestPayload, Data("PUSH_REQUEST\0".utf8))
    }
}

// MARK: - Control channel

final class OVPNControlChannelTests: XCTestCase {

    /// Two reliability layers with an unprotected control channel.
    private func makeLayerPair(
        tlsAuthKey: OVPNStaticKeyFile? = nil,
        tlsCryptKey: OVPNStaticKeyFile? = nil
    ) throws -> (client: OVPNReliabilityLayer, server: OVPNReliabilityLayer) {
        let client = OVPNReliabilityLayer(keyID: 0, isServer: false, tlsAuthKey: tlsAuthKey, tlsCryptKey: tlsCryptKey)
        let server = OVPNReliabilityLayer(keyID: 0, isServer: true, tlsAuthKey: tlsAuthKey, tlsCryptKey: tlsCryptKey)
        return (client, server)
    }

    /// Drive the reset exchange and return both layers.
    private func completeResetExchange(
        t0: Date
    ) throws -> (client: OVPNReliabilityLayer, server: OVPNReliabilityLayer) {
        let (client, server) = try makeLayerPair()

        let clientReset = try client.beginHandshake(now: t0)
        XCTAssertEqual(clientReset[0] >> 3, OVPNControlOpcode.hardResetClientV2.rawValue)
        XCTAssertEqual(clientReset.count, 1 + 8 + 1 + 4, "opcode + session id + empty ack array + packet id 0")
        XCTAssertEqual(Array(clientReset.suffix(4)), [0, 0, 0, 0])

        _ = try server.receive(clientReset, now: t0)
        XCTAssertTrue(server.drainEvents().contains(.hardResetReceived(keyID: 0)))

        let serverAck = try XCTUnwrap(server.pendingAcks(now: t0).first)
        let clientEvents = try client.receive(serverAck, now: t0).isEmpty ? client.drainEvents() : []
        XCTAssertTrue(clientEvents.contains(.ackReceived([0])))
        XCTAssertTrue(client.isResetAcknowledged)

        let serverReset = try server.beginHandshake(now: t0)
        _ = try client.receive(serverReset, now: t0)
        XCTAssertTrue(client.drainEvents().contains(.hardResetReceived(keyID: 0)))
        XCTAssertTrue(client.isHandshakeComplete)
        return (client, server)
    }

    func testHandshakeAndACKHandling() throws {
        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        let (client, server) = try completeResetExchange(t0: t0)

        // The server learned who it is talking to.
        XCTAssertEqual(server.remoteSessionID, client.localSessionID)
        XCTAssertEqual(client.remoteSessionID, server.localSessionID)
        XCTAssertNotEqual(client.localSessionID, server.localSessionID)

        // Three TLS chunks, each its own control packet.
        let chunks = [Data("chunk-one".utf8), Data("chunk-two".utf8), Data("chunk-three".utf8)]
        var datagrams: [Data] = []
        for chunk in chunks {
            datagrams.append(contentsOf: client.wrapOutgoingTLS(chunk, now: t0))
        }
        XCTAssertEqual(datagrams.count, 3)
        XCTAssertEqual(client.outstandingPacketCount, 3)
        XCTAssertEqual(datagrams[0][0] >> 3, OVPNControlOpcode.controlV1.rawValue)
        // The first packet acknowledges the server's reset.
        XCTAssertEqual(datagrams[0][1 + 8], 1, "one acknowledgement in the ack array")

        // Deliver 1 and 3, dropping 2 on the floor.
        let first = try server.receive(datagrams[0], now: t0)
        XCTAssertEqual(first, [chunks[0]])
        let third = try server.receive(datagrams[2], now: t0)
        XCTAssertTrue(third.isEmpty, "packet id 3 must wait for packet id 2")

        // The server acknowledges what it has seen.
        let ack = try XCTUnwrap(server.pendingAcks(now: t0).first)
        _ = try client.receive(ack, now: t0)
        // The ack array repeats the acknowledgements it has already sent (the
        // "ack MRU" list), so assert on the set and on the effect.
        XCTAssertTrue(acknowledgedIDs(in: client.drainEvents()).isSuperset(of: [0, 1, 3]))
        XCTAssertEqual(client.outstandingPacketCount, 1, "only packet 2 is still outstanding")

        // Before the timeout nothing is retransmitted.
        XCTAssertTrue(try client.tick(now: t0.addingTimeInterval(0.5)).isEmpty)

        // One second later the missing packet is retransmitted exactly once.
        let retransmissions = try client.tick(now: t0.addingTimeInterval(1.5))
        XCTAssertEqual(retransmissions.count, 1)
        // An unprotected control channel has nothing to freshen, so the
        // retransmission is byte identical and the peer recognises it by its
        // message packet id (see the tls-crypt retransmission test below for
        // the wrapped case).
        XCTAssertEqual(retransmissions[0], datagrams[1])

        // The retransmission releases both the lost chunk and the buffered one,
        // in order.
        let delivered = try server.receive(retransmissions[0], now: t0.addingTimeInterval(1.5))
        XCTAssertEqual(delivered, [chunks[1], chunks[2]])

        // And the ACK for it clears the queue.
        let finalAck = try XCTUnwrap(server.pendingAcks(now: t0.addingTimeInterval(1.5)).first)
        _ = try client.receive(finalAck, now: t0)
        XCTAssertTrue(acknowledgedIDs(in: client.drainEvents()).contains(2))
        XCTAssertEqual(client.outstandingPacketCount, 0)

        // Backoff: the next retransmission is two seconds after the first.
        XCTAssertTrue(try client.tick(now: t0.addingTimeInterval(2.5)).isEmpty)
    }

    func testDuplicateDeliveryIsAcknowledgedButNotRepeated() throws {
        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        let (client, server) = try completeResetExchange(t0: t0)

        let chunk = Data("chunk".utf8)
        let datagram = try XCTUnwrap(client.wrapOutgoingTLS(chunk, now: t0).first)
        XCTAssertEqual(try server.receive(datagram, now: t0), [chunk])
        XCTAssertTrue(try server.receive(datagram, now: t0).isEmpty, "a duplicate is never delivered twice")
        XCTAssertFalse(
            server.drainEvents().contains { event in
                if case .dropped = event { return true }
                return false
            },
            "a duplicate is not an error, only a retransmission to re-acknowledge"
        )

        // It is acknowledged again so the sender stops retrying.
        let ack = try XCTUnwrap(server.pendingAcks(now: t0).first)
        _ = try client.receive(ack, now: t0)
        XCTAssertEqual(client.outstandingPacketCount, 0)
    }

    func testHardResetIsRetriedUntilAcknowledged() throws {
        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        let client = OVPNReliabilityLayer(keyID: 0, isServer: false, tlsAuthKey: nil, tlsCryptKey: nil)
        _ = try client.beginHandshake(now: t0)

        // 1s, 2s, 4s, 8s, 8s ... until the handshake window expires.
        XCTAssertTrue(try client.tick(now: t0.addingTimeInterval(0.9)).isEmpty)
        XCTAssertEqual(try client.tick(now: t0.addingTimeInterval(1.1)).count, 1)
        XCTAssertTrue(try client.tick(now: t0.addingTimeInterval(2.6)).isEmpty)
        XCTAssertEqual(try client.tick(now: t0.addingTimeInterval(3.2)).count, 1)
        XCTAssertEqual(try client.tick(now: t0.addingTimeInterval(7.3)).count, 1)

        // After the 60 second handshake window it gives up.
        XCTAssertThrowsError(try client.tick(now: t0.addingTimeInterval(61))) { error in
            XCTAssertEqual(error as? OVPNError, .controlChannelTimeout(seconds: 60))
        }
    }

    func testSoftResetStartsANewKeyState() throws {
        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        let (client, server) = try completeResetExchange(t0: t0)

        // A renegotiation uses key id 1 but keeps the session id: the layer is
        // created with the session id of the key state it replaces.
        let renegotiation = OVPNReliabilityLayer(
            keyID: 1,
            isServer: false,
            crypto: .unprotected,
            localSessionID: client.localSessionID,
            initialOpcode: .softResetV1
        )
        let softReset = try renegotiation.sendSoftReset(now: t0)
        XCTAssertEqual(softReset[0] >> 3, OVPNControlOpcode.softResetV1.rawValue)
        XCTAssertEqual(softReset[0] & OVPNControlOpcode.keyIDMask, 1)
        XCTAssertEqual(softReset.subdata(in: 1..<9), client.localSessionID.bytes, "the session id survives renegotiation")

        // Not yet started key id 1.
        let serverKeyState = OVPNReliabilityLayer(keyID: 1, isServer: true, tlsAuthKey: nil, tlsCryptKey: nil)
        _ = try serverKeyState.receive(softReset, now: t0)
        XCTAssertTrue(serverKeyState.drainEvents().contains(.softResetReceived(keyID: 1)))
        XCTAssertEqual(serverKeyState.remoteSessionID, client.localSessionID)
    }

    func testPacketsForAnotherKeyStateAreReported() throws {
        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        let (client, server) = try completeResetExchange(t0: t0)
        _ = server

        let otherKeyState = OVPNReliabilityLayer(keyID: 4, isServer: false, tlsAuthKey: nil, tlsCryptKey: nil)
        let datagram = try otherKeyState.beginHandshake(now: t0)
        let layer = OVPNReliabilityLayer(keyID: 0, isServer: true, tlsAuthKey: nil, tlsCryptKey: nil)
        _ = try layer.receive(datagram, now: t0)
        XCTAssertTrue(layer.drainEvents().contains(.packetForOtherKeyState(keyID: 4, opcode: .hardResetClientV2)))
        XCTAssertNotEqual(client.localSessionID, layer.localSessionID)
    }

    func testTLSCryptWrappingRoundTrip() throws {
        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        let key = try ovpnStaticKey
        let keyFile = OVPNStaticKeyFile(direction: nil, key: key)

        var wrap = try XCTUnwrap(OVPNControlCrypto(tlsAuthKey: nil, tlsCryptKey: keyFile))
        var unwrap = wrap
        XCTAssertEqual(wrap.mode, .tlsCrypt)
        XCTAssertEqual(wrap.overhead, 40, "packet id (8) + tag (32)")

        let payload = Data("ack + tls record".utf8)
        let sessionID = OVPNSessionID.random()
        let packetID = OVPNPacketID(sequence: 5, timestamp: 1_700_000_000)
        let datagram = try wrap.wrap(
            opcodeByte: OVPNControlOpcode.opcodeByte(.controlV1, keyID: 0),
            sessionID: sessionID,
            packetID: packetID,
            payload: payload
        )
        // opcode + session id + packet id + tag, then the ciphertext (stream
        // cipher, so the length is unchanged).
        XCTAssertEqual(datagram.count, 1 + 8 + 8 + 32 + payload.count)
        XCTAssertEqual(datagram.subdata(in: 1..<9), sessionID.bytes)

        let result = try unwrap.unwrap(datagram)
        XCTAssertEqual(result.plaintext, payload)
        XCTAssertEqual(result.sessionID, sessionID)
        XCTAssertEqual(result.packetID, packetID)
        XCTAssertEqual(result.opcode, .controlV1)

        // Replaying it is refused.
        XCTAssertThrowsError(try unwrap.unwrap(datagram)) { error in
            XCTAssertEqual(error as? OVPNError, .replayDetected(id: 5))
        }

        // A single flipped ciphertext bit breaks the HMAC.
        var tampered = datagram
        tampered[tampered.count - 1] ^= 0x01
        XCTAssertThrowsError(try unwrap.unwrap(tampered)) { error in
            XCTAssertEqual(error as? OVPNError, .authenticationFailed)
        }

        // So does a flipped opcode byte, which is part of the tag input.
        var wrongOpcode = datagram
        wrongOpcode[0] = OVPNControlOpcode.opcodeByte(.ackV1, keyID: 0)
        XCTAssertThrowsError(try unwrap.unwrap(wrongOpcode)) { error in
            XCTAssertEqual(error as? OVPNError, .authenticationFailed)
        }

        // Truncated input must throw instead of trapping.
        XCTAssertThrowsError(try unwrap.unwrap(Data(datagram.prefix(20))))
        XCTAssertThrowsError(try unwrap.unwrap(Data()))
        XCTAssertThrowsError(try unwrap.unwrap(Data([0xFF])))
    }

    func testTLSAuthWrappingRoundTrip() throws {
        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        let key = try ovpnStaticKey
        // The client uses direction 1, the server direction 0, so the client's
        // send key is the server's receive key.
        let client = OVPNReliabilityLayer(
            keyID: 0,
            isServer: false,
            tlsAuthKey: OVPNStaticKeyFile(direction: 1, key: key),
            tlsCryptKey: nil
        )
        let server = OVPNReliabilityLayer(
            keyID: 0,
            isServer: true,
            tlsAuthKey: OVPNStaticKeyFile(direction: 0, key: key),
            tlsCryptKey: nil
        )
        XCTAssertEqual(client.crypto.mode, .tlsAuth)
        XCTAssertEqual(client.crypto.digest, .sha256)
        XCTAssertEqual(client.crypto.overhead, 40, "MAC (32) + packet id (8)")

        let reset = try client.beginHandshake(now: t0)
        // opcode + session id + MAC + packet id (long form) + ack array +
        // message packet id.
        XCTAssertEqual(reset.count, 1 + 8 + 32 + 8 + 1 + 4)
        XCTAssertEqual(reset[0] >> 3, OVPNControlOpcode.hardResetClientV2.rawValue)

        _ = try server.receive(reset, now: t0)
        XCTAssertTrue(server.drainEvents().contains(.hardResetReceived(keyID: 0)))

        // A packet authenticated with the wrong key is rejected outright.
        let stranger = OVPNReliabilityLayer(
            keyID: 0,
            isServer: false,
            tlsAuthKey: OVPNStaticKeyFile(direction: nil, key: OVPNStaticKey.generate()),
            tlsCryptKey: nil
        )
        let badReset = try stranger.beginHandshake(now: t0)
        XCTAssertThrowsError(try server.receive(badReset, now: t0)) { error in
            XCTAssertEqual(error as? OVPNError, .authenticationFailed)
        }
    }

    func testServerSideResetExchangeWithTLSCrypt() throws {
        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        let keyFile = OVPNStaticKeyFile(direction: nil, key: try ovpnStaticKey)
        let (client, server) = try makeLayerPair(tlsCryptKey: keyFile)

        let clientReset = try client.beginHandshake(now: t0)
        XCTAssertEqual(clientReset[0] >> 3, OVPNControlOpcode.hardResetClientV2.rawValue)
        _ = try server.receive(clientReset, now: t0)
        XCTAssertTrue(server.drainEvents().contains(.hardResetReceived(keyID: 0)))
        XCTAssertEqual(server.remoteSessionID, client.localSessionID)

        let ack = try XCTUnwrap(server.pendingAcks(now: t0).first)
        _ = try client.receive(ack, now: t0)
        XCTAssertTrue(client.drainEvents().contains(.ackReceived([0])))

        let serverReset = try server.beginHandshake(now: t0)
        _ = try client.receive(serverReset, now: t0)
        XCTAssertTrue(client.isHandshakeComplete)

        let chunk = Data(repeating: 0x16, count: 300)
        let datagram = try XCTUnwrap(client.wrapOutgoingTLS(chunk, now: t0).first)
        XCTAssertEqual(try server.receive(datagram, now: t0), [chunk])
    }

    func testTLSCryptRetransmissionUsesAFreshCryptoPacketID() throws {
        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        let keyFile = OVPNStaticKeyFile(direction: nil, key: try ovpnStaticKey)
        let (client, server) = try makeLayerPair(tlsCryptKey: keyFile)

        // Complete the reset exchange so only the TLS chunk is outstanding.
        _ = try server.receive(try client.beginHandshake(now: t0), now: t0)
        let resetAck = try XCTUnwrap(server.pendingAcks(now: t0).first)
        _ = try client.receive(resetAck, now: t0)
        XCTAssertEqual(client.outstandingPacketCount, 0)

        let chunk = Data("chunk-that-gets-lost".utf8)
        let first = try XCTUnwrap(client.wrapOutgoingTLS(chunk, now: t0).first)
        let retransmission = try XCTUnwrap(try client.tick(now: t0.addingTimeInterval(1.5)).first)

        // Same reliable payload, different tls-crypt header: the crypto packet
        // id advanced, so the tag and the ciphertext differ.
        XCTAssertNotEqual(first, retransmission)
        let unwrappedFirst = try server.crypto.unwrap(first)
        let unwrappedSecond = try server.crypto.unwrap(retransmission)
        XCTAssertEqual(unwrappedFirst.plaintext, unwrappedSecond.plaintext)
        XCTAssertEqual(unwrappedSecond.packetID?.sequence, (unwrappedFirst.packetID?.sequence ?? 0) + 1)
    }

    func testTLSCryptV2ResetCarriesTheWrappedClientKey() throws {
        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        var blob = Data()
        blob.append(Data(repeating: 0x11, count: 64))
        blob.append(Data(repeating: 0x22, count: 128))
        let clientKey = try OVPNTlsCryptV2ClientKey(raw: blob)
        let crypto = try OVPNControlCrypto(tlsAuthKey: nil, tlsCryptKey: nil, tlsCryptV2ClientKey: clientKey)
        XCTAssertEqual(crypto.mode, .tlsCrypt)

        let client = OVPNReliabilityLayer(
            keyID: 0,
            isServer: false,
            crypto: crypto,
            initialOpcode: .hardResetClientV3,
            tlsCryptV2WrappedKey: clientKey.wrappedClientKey
        )
        let reset = try client.beginHandshake(now: t0)
        XCTAssertEqual(reset[0] >> 3, OVPNControlOpcode.hardResetClientV3.rawValue)
        // The wrapped key trails the ciphertext.
        XCTAssertEqual(reset.suffix(64), clientKey.wrappedClientKey)

        // The server (which only knows the tls-crypt key) can still unwrap the
        // packet; the trailing key is outside the ciphertext.
        let server = OVPNReliabilityLayer(
            keyID: 0,
            isServer: true,
            tlsAuthKey: nil,
            tlsCryptKey: OVPNStaticKeyFile(direction: nil, key: OVPNStaticKey(uncheckedRaw: appendKeyMaterial(clientKey)))
        )
        // The receiver has to be told how many bytes after the ciphertext are
        // the wrapped client key (`tls_crypt_v2_unwrap` reads that length out
        // of the blob itself).
        let unwrapped = try server.crypto.unwrap(reset, trailingBytes: 64)
        XCTAssertEqual(unwrapped.opcode, .hardResetClientV3)
        XCTAssertEqual(unwrapped.appended, clientKey.wrappedClientKey)
        XCTAssertTrue(unwrapped.plaintext.count == 5, "ack array + message packet id")
        // Without that hint the extra bytes are taken as ciphertext and the
        // packet fails authentication, which is the safe failure mode.
        XCTAssertThrowsError(try server.crypto.unwrap(reset)) { error in
            XCTAssertEqual(error as? OVPNError, .authenticationFailed)
        }
    }

    /// Build a 256-byte static key whose first block is `clientKey`'s block.
    private func appendKeyMaterial(_ clientKey: OVPNTlsCryptV2ClientKey) -> Data {
        var out = clientKey.key.raw
        out.append(Data(repeating: 0, count: 128))
        return out
    }

    func testUnauthenticatedControlChannelThrowsOnBadOpcode() throws {
        let layer = OVPNReliabilityLayer(keyID: 0, isServer: false, tlsAuthKey: nil, tlsCryptKey: nil)
        XCTAssertThrowsError(try layer.receive(Data([0x7F] + Array(repeating: 0, count: 16)))) { error in
            XCTAssertEqual(error as? OVPNError, .unknownOpcode(0x0F))
        }
        XCTAssertThrowsError(try layer.receive(Data(repeating: 0, count: 16))) { error in
            XCTAssertEqual(error as? OVPNError, .unknownOpcode(0))
        }
        XCTAssertThrowsError(try layer.receive(Data())) { error in
            guard case .packetTooShort = (error as? OVPNError) else {
                return XCTFail("expected packetTooShort, got \(error)")
            }
        }
    }

    func testAckArrayEncoding() throws {
        let ack = OVPNControlAck(ids: [3, 1], remoteSessionID: Data(repeating: 0xAB, count: 8))
        XCTAssertEqual(ack.wireLength, 1 + 8 + 8)
        let encoded = ack.encode()
        XCTAssertEqual(encoded.count, ack.wireLength)
        XCTAssertEqual(try OVPNControlAck.decode(encoded, at: 0).ack, ack)

        let empty = OVPNControlAck.empty
        XCTAssertEqual(empty.encode(), Data([0]))
        XCTAssertEqual(try OVPNControlAck.decode(Data([0]), at: 0).ack, empty)

        // More than RELIABLE_ACK_SIZE ids is refused, as OpenVPN does.
        XCTAssertThrowsError(try OVPNControlAck.decode(Data([9, 0, 0, 0, 1]), at: 0))
        XCTAssertThrowsError(try OVPNControlAck.decode(Data(), at: 0))
    }

    func testSessionIDFormatting() throws {
        let sessionID = try XCTUnwrap(OVPNSessionID(ovpnHex("00112233445566aa")))
        XCTAssertEqual(sessionID.description, "00112233445566aa")
        XCTAssertNil(OVPNSessionID(Data(repeating: 0, count: 7)))
        XCTAssertNotEqual(OVPNSessionID.random(), OVPNSessionID.random())
    }

    func testPacketIDWireOrder() throws {
        let packetID = OVPNPacketID(sequence: 0x01020304, timestamp: 0x05060708)
        XCTAssertEqual(packetID.wireLength, 8)
        XCTAssertEqual(packetID.wireBytes, ovpnHex("0102030405060708"))
        let decoded = try OVPNPacketID.decode(ovpnHex("0102030405060708"), at: 0, longForm: true)
        XCTAssertEqual(decoded.packetID, packetID)
        XCTAssertEqual(decoded.nextOffset, 8)
        XCTAssertEqual(OVPNPacketID(sequence: 5).wireBytes, ovpnHex("00000005"))
    }

    func testOpcodeByteLayout() throws {
        for opcode in OVPNControlOpcode.allCases {
            for keyID in UInt8(0)...UInt8(7) {
                let byte = OVPNControlOpcode.opcodeByte(opcode, keyID: keyID)
                let parsed = try XCTUnwrap(OVPNControlOpcode.parse(byte))
                XCTAssertEqual(parsed.opcode, opcode)
                XCTAssertEqual(parsed.keyID, keyID)
            }
        }
        XCTAssertEqual(OVPNControlOpcode.opcodeByte(.hardResetClientV2, keyID: 0), 0x38)
        XCTAssertEqual(OVPNControlOpcode.opcodeByte(.dataV1, keyID: 0), 0x30)
        XCTAssertEqual(OVPNControlOpcode.initialOpcode(isServer: false, hasTLSCryptV2: false), .hardResetClientV2)
        XCTAssertEqual(OVPNControlOpcode.initialOpcode(isServer: false, hasTLSCryptV2: true), .hardResetClientV3)
        XCTAssertEqual(OVPNControlOpcode.initialOpcode(isServer: true, hasTLSCryptV2: false), .hardResetServerV2)
        XCTAssertTrue(OVPNControlOpcode.controlV1.isControl)
        XCTAssertTrue(OVPNControlOpcode.dataV1.isData)
    }
}

// MARK: - Session driver

/// Collects every packet id acknowledged by a list of events.
private func acknowledgedIDs(in events: [OVPNControlEvent]) -> Set<UInt32> {
    var out: Set<UInt32> = []
    for event in events {
        if case let .ackReceived(ids) = event { out.formUnion(ids) }
    }
    return out
}

/// An IPv4 + UDP packet that looks like something a tun device would hand over.
private func ovpnSamplePacket(payload: String = "openvpn test payload") -> Data {
    var packet = Data()
    packet.append(contentsOf: [0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00, 0x40, 0x11])
    packet.append(contentsOf: [0x00, 0x00])
    packet.append(contentsOf: [10, 8, 0, 2])
    packet.append(contentsOf: [10, 8, 0, 1])
    packet.append(contentsOf: [0x04, 0xD2, 0x00, 0x35, 0x00, 0x28, 0x00, 0x00])
    packet.append(Data(payload.utf8))
    return packet
}

/// `NSLock` is unavailable from async contexts, so the test doubles take their
/// lock through this tiny wrapper (the library does the same with
/// `OVPNMutex`).
private final class TestMutex: @unchecked Sendable {
    private let mutex = NSLock()
    func lock() { mutex.lock() }
    func unlock() { mutex.unlock() }
}

/// An in-memory datagram pipe: everything the session sends can be inspected,
/// and the test can push datagrams in as if they came from the server.
private final class MockDatagramTransport: DatagramTransport, @unchecked Sendable {
    private let lock = TestMutex()
    private var outbound: [Data] = []
    private var inbound: [Data] = []
    private var waiter: CheckedContinuation<Data, Error>?
    private var isClosed = false

    func send(_ datagram: Data) async throws {
        lock.lock()
        defer { lock.unlock() }
        guard !isClosed else { throw OVPNError.transportFailure("transport closed") }
        outbound.append(datagram)
    }

    func receive() async throws -> Data {
        lock.lock()
        if !inbound.isEmpty {
            let datagram = inbound.removeFirst()
            lock.unlock()
            return datagram
        }
        if isClosed {
            lock.unlock()
            throw OVPNError.transportFailure("transport closed")
        }
        if waiter != nil {
            lock.unlock()
            throw OVPNError.transportFailure("concurrent receive()")
        }
        lock.unlock()
        return try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            if inbound.isEmpty, !isClosed {
                waiter = continuation
                lock.unlock()
            } else if !inbound.isEmpty {
                let datagram = inbound.removeFirst()
                lock.unlock()
                continuation.resume(returning: datagram)
            } else {
                lock.unlock()
                continuation.resume(throwing: OVPNError.transportFailure("transport closed"))
            }
        }
    }

    func close() async {
        lock.lock()
        isClosed = true
        let continuation = waiter
        waiter = nil
        lock.unlock()
        continuation?.resume(throwing: OVPNError.transportFailure("transport closed"))
    }

    /// Datagrams the session has handed to the transport.
    var sent: [Data] {
        lock.lock()
        defer { lock.unlock() }
        return outbound
    }

    /// Push a datagram in as if the server sent it.
    func deliver(_ datagram: Data) {
        lock.lock()
        if let continuation = waiter {
            waiter = nil
            lock.unlock()
            continuation.resume(returning: datagram)
        } else {
            inbound.append(datagram)
            lock.unlock()
        }
    }
}

/// A TLS stack stand-in: records what the session hands it, and lets the test
/// pretend the handshake finished and the server pushed options.
private final class FakeTLSProvider: OVPNTLSProvider, OVPNTLSApplicationData, @unchecked Sendable {
    var onTLSData: (([Data]) -> Void)?
    var onApplicationData: (([Data]) -> Void)?

    private let lock = TestMutex()
    private var _started = false
    private var _received: [Data] = []
    private var _applicationData: [Data] = []
    private var _handshakeComplete = false
    private var _serverName: String?
    private var _tlsAuthRemoteName: String?

    func startTLS(
        serverName: String?,
        caCertificates: [Data],
        clientCertificate: Data?,
        clientKey: Data?,
        tlsAuthRemoteName: String?
    ) async throws {
        lock.lock()
        _started = true
        _serverName = serverName
        _tlsAuthRemoteName = tlsAuthRemoteName
        lock.unlock()
    }

    func writeTLS(_ data: Data) async throws {
        lock.lock()
        _received.append(data)
        lock.unlock()
    }

    func writeApplicationData(_ data: Data) async throws {
        lock.lock()
        _applicationData.append(data)
        lock.unlock()
    }

    var negotiatedCipherSuite: String? { "TLS_AES_256_GCM_SHA384" }
    var started: Bool { lock.lock(); defer { lock.unlock() }; return _started }
    var receivedTLS: [Data] { lock.lock(); defer { lock.unlock() }; return _received }
    var applicationData: [Data] { lock.lock(); defer { lock.unlock() }; return _applicationData }
    var serverName: String? { lock.lock(); defer { lock.unlock() }; return _serverName }
    var tlsAuthRemoteName: String? { lock.lock(); defer { lock.unlock() }; return _tlsAuthRemoteName }

    var isHandshakeComplete: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _handshakeComplete }
        set { lock.lock(); _handshakeComplete = newValue; lock.unlock() }
    }

    /// Pretend the server pushed an option string inside TLS.
    func pushServerData(_ text: String) {
        onApplicationData?([Data(text.utf8)])
    }
}

/// Collects inbound tunnel packets.
private final class InboundCollector: @unchecked Sendable {
    private let lock = TestMutex()
    private var storage: [Data] = []

    func append(_ packets: [Data]) {
        lock.lock()
        storage.append(contentsOf: packets)
        lock.unlock()
    }

    var packets: [Data] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }
}

/// Poll until `condition` holds or `timeout` expires.
private func ovpnWait(
    _ timeout: TimeInterval = 3,
    file: StaticString = #filePath,
    line: UInt = #line,
    until condition: () -> Bool
) async throws {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if condition() { return }
        try await Task.sleep(nanoseconds: 10_000_000)
    }
    if condition() { return }
    XCTFail("condition not met within \(timeout)s", file: file, line: line)
}

final class OVPNTunnelSessionTests: XCTestCase {

    /// `--secret` mode end to end: no TLS, no push exchange, straight to the
    /// data channel.
    func testStaticKeySessionCarriesPacketsBothWays() async throws {
        let config = try OVPNConfiguration.parse(ovpnStaticKeyConfig)
        let transport = MockDatagramTransport()
        let tls = FakeTLSProvider()
        let session = OVPNTunnelSession(configuration: config, transport: transport, tls: tls)
        let inbound = InboundCollector()
        session.onInboundPackets = { packets in inbound.append(packets) }

        try await session.start()
        XCTAssertEqual(session.currentState, .connected)
        XCTAssertFalse(tls.started, "static key mode must not touch TLS")
        XCTAssertNotNil(session.statistics.connectedSince)

        // Outbound: the session encrypts and hands the datagram to the
        // transport.
        let outboundPacket = ovpnSamplePacket()
        session.writeOutbound([outboundPacket])
        try await ovpnWait { transport.sent.count == 1 }

        let keyFile = try config.loadStaticKeyFile()
        let spec = try XCTUnwrap(OVPNCipherSpec.parse("AES-256-CBC"))
        let keys = try OVPNKeyDerivation.dataKeys(fromStaticKeyFile: keyFile, cipher: spec, hmac: .sha256)
        var peer = try OVPNPacketCodec(cipher: "AES-256-CBC", digest: "SHA256", staticKeyMode: true, senderKeyId: 0)
        peer.installKeys(keys)
        XCTAssertEqual(try peer.decode(try XCTUnwrap(transport.sent.first)), outboundPacket)

        // Inbound: a datagram from the peer reaches the callback.
        let replyPacket = ovpnSamplePacket(payload: "reply from server")
        transport.deliver(try peer.encode(packet: replyPacket, sequence: 1))
        try await ovpnWait { inbound.packets.count == 1 }
        XCTAssertEqual(inbound.packets.first, replyPacket)
        XCTAssertEqual(session.statistics.bytesOut, UInt64(outboundPacket.count))
        XCTAssertGreaterThan(session.statistics.bytesIn, 0)
        XCTAssertGreaterThanOrEqual(session.statistics.datagramsIn, 1)

        await session.stop()
        XCTAssertEqual(session.currentState, .idle)
    }

    /// TLS mode: the hard reset and every TLS record travel through the
    /// control channel, and the push exchange is driven by the session.
    func testTLSSessionDrivesHandshakeAndPushExchange() async throws {
        let config = try OVPNConfiguration.parse("""
        client
        dev tun
        proto udp
        remote vpn.example.com 1194
        <tls-crypt>
        \(ovpnStaticKeyPEM)
        </tls-crypt>
        verify-x509-name "vpn.example.com" name
        cipher AES-256-GCM
        """)
        let transport = MockDatagramTransport()
        let tls = FakeTLSProvider()
        let session = OVPNTunnelSession(configuration: config, transport: transport, tls: tls)

        try await session.start()
        XCTAssertTrue(tls.started)
        XCTAssertEqual(tls.serverName, "vpn.example.com")
        XCTAssertEqual(tls.tlsAuthRemoteName, "vpn.example.com")

        // 1. The first packet on the wire is the hard reset, tls-crypt wrapped,
        //    and a server-side layer with the same key can unwrap it.
        try await ovpnWait { transport.sent.count >= 1 }
        let server = OVPNReliabilityLayer(
            keyID: 0,
            isServer: true,
            tlsAuthKey: nil,
            tlsCryptKey: OVPNStaticKeyFile(direction: nil, key: try ovpnStaticKey)
        )
        let reset = try XCTUnwrap(transport.sent.first)
        XCTAssertEqual(reset[0] >> 3, OVPNControlOpcode.hardResetClientV2.rawValue)
        XCTAssertTrue(try server.receive(reset).isEmpty, "a reset carries no TLS bytes")
        XCTAssertTrue(server.drainEvents().contains(.hardResetReceived(keyID: 0)))
        XCTAssertEqual(server.remoteSessionID, session.sessionID)

        // 2. The server's reset moves the client on and is acknowledged.
        XCTAssertEqual(session.currentState, .tlsHandshake)
        transport.deliver(try server.beginHandshake())
        try await ovpnWait { transport.sent.count >= 2 }
        XCTAssertTrue(transport.sent.contains { $0[0] >> 3 == OVPNControlOpcode.ackV1.rawValue },
                      "the client must acknowledge the server's reset")

        // 3. TLS records flow in both directions.
        tls.onTLSData?([Data("client-hello".utf8)])
        try await ovpnWait { transport.sent.count >= 3 }
        let controlPackets = transport.sent.filter { $0[0] >> 3 == OVPNControlOpcode.controlV1.rawValue }
        let tlsRecord = try XCTUnwrap(controlPackets.first)
        XCTAssertEqual(try server.receive(tlsRecord), [Data("client-hello".utf8)])

        let serverRecord = try XCTUnwrap(server.wrapOutgoingTLS(Data("server-hello".utf8)).first)
        transport.deliver(serverRecord)
        try await ovpnWait { tls.receivedTLS.count == 1 }
        XCTAssertEqual(tls.receivedTLS.first, Data("server-hello".utf8))

        // 4. Once the TLS stack reports the handshake is done, the session
        //    sends PUSH_REQUEST through it.
        tls.isHandshakeComplete = true
        try await ovpnWait(5) { !tls.applicationData.isEmpty }
        XCTAssertEqual(tls.applicationData.first, Data("PUSH_REQUEST\0".utf8))
        XCTAssertEqual(session.currentState, .authenticating)

        // 5. The server's PUSH_REPLY is parsed.
        tls.pushServerData(
            "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,redirect-gateway def1,"
                + "dhcp-option DNS 10.0.0.1,cipher AES-256-GCM,peer-id 3\0"
        )
        try await ovpnWait { session.pushReply != nil }
        XCTAssertEqual(session.pushReply?.peerID, 3)
        XCTAssertEqual(session.pushReply?.cipher, "AES-256-GCM")
        XCTAssertEqual(session.pushReply?.ifconfig?.localAddress, "10.8.0.2")
        XCTAssertEqual(session.pushReply?.dnsServers, ["10.0.0.1"])
        XCTAssertTrue(session.pushReply?.redirectGateway ?? false)
        try await ovpnWait { session.currentState == .connected }

        // 6. The host can still install the data channel keys itself.
        try session.installDataChannelKeyMaterial(Data((0..<256).map { UInt8($0) }))
        XCTAssertEqual(session.currentState, .connected)

        await session.stop()
        XCTAssertEqual(session.currentState, .idle)
    }

    func testSessionWithoutRemoteFails() async throws {
        var config = OVPNConfiguration()
        config.isStaticKeyMode = true
        let session = OVPNTunnelSession(
            configuration: config,
            transport: MockDatagramTransport(),
            tls: FakeTLSProvider()
        )
        do {
            try await session.start()
            XCTFail("expected start() to throw without a remote")
        } catch let error as OVPNError {
            XCTAssertEqual(error, .missingRequiredDirective("remote"))
            XCTAssertEqual(session.currentState, .failed(error.localizedDescription))
        }
    }

    func testWriteOutboundBeforeKeysIsDroppedNotCrashed() async throws {
        let config = try OVPNConfiguration.parse(ovpnStaticKeyConfig)
        let session = OVPNTunnelSession(
            configuration: config,
            transport: MockDatagramTransport(),
            tls: FakeTLSProvider()
        )
        session.writeOutbound([ovpnSamplePacket()])
        XCTAssertEqual(session.statistics.droppedOutbound, 1)
    }
}
