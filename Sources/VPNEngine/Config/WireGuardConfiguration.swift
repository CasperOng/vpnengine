//
//  WireGuardConfiguration.swift
//  VPNEngine
//
//  The declarative surface of a WireGuard tunnel: one interface and a list of
//  peers (whitepaper, section 3, "Cryptokey Routing").
//
//  The types mirror WireGuard's own configuration model rather than the shape
//  of any particular `.conf` file, so a caller can build them from `wg-quick`
//  syntax, from an MDM payload, or from a QR code. Keys are held as 32 raw
//  bytes exactly as they appear on the wire.
//

import Foundation

/// The local side of a WireGuard tunnel.
public struct WireGuardInterface: Equatable, Sendable, Codable {

    /// The interface's private key: 32 raw bytes.
    ///
    /// WireGuard requires this to be the X25519 scalar, not the base64 text;
    /// use ``WireGuardKey`` to parse a textual key.
    public var privateKey: Data

    /// The addresses assigned to this interface, for example `10.7.0.2/24`.
    ///
    /// These are the addresses the kernel (or the tunnel's own NAT stage) uses
    /// as the source of packets that go into the tunnel.
    public var addresses: [CIDR]

    /// DNS servers to use while the tunnel is up.
    public var dnsServers: [String]

    /// The MTU of the tunnel interface.
    public var mtu: Int

    /// The local UDP port to listen on. `nil` means "pick an ephemeral port".
    public var listenPort: UInt16?

    /// The default tunnel MTU: 1500 byte ethernet minus IPv4+UDP+WireGuard
    /// overhead.
    public static let defaultMTU = 1420

    /// Creates an interface configuration.
    ///
    /// - Parameters:
    ///   - privateKey: 32 raw bytes of private key.
    ///   - addresses: Interface addresses.
    ///   - dnsServers: DNS servers. Defaults to empty.
    ///   - mtu: Tunnel MTU. Defaults to ``defaultMTU``.
    ///   - listenPort: Local UDP port, or `nil` for an ephemeral one.
    public init(privateKey: Data,
                addresses: [CIDR],
                dnsServers: [String] = [],
                mtu: Int = WireGuardInterface.defaultMTU,
                listenPort: UInt16? = nil) {
        self.privateKey = privateKey
        self.addresses = addresses
        self.dnsServers = dnsServers
        self.mtu = mtu
        self.listenPort = listenPort
    }

    /// Decodes an interface, defaulting the MTU and optional fields.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when `privateKey` is missing or malformed.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let key = try container.decode(String.self, forKey: .privateKey)
        guard let parsed = WireGuardKey(base64: key) else {
            throw DecodingError.dataCorruptedError(forKey: .privateKey,
                                                   in: container,
                                                   debugDescription: "\"\(key)\" is not a 32 byte WireGuard key")
        }
        self.privateKey = parsed.rawValue
        self.addresses = try container.decodeIfPresent([CIDR].self, forKey: .addresses) ?? []
        self.dnsServers = try container.decodeIfPresent([String].self, forKey: .dnsServers) ?? []
        self.mtu = try container.decodeIfPresent(Int.self, forKey: .mtu) ?? WireGuardInterface.defaultMTU
        self.listenPort = try container.decodeIfPresent(UInt16.self, forKey: .listenPort)
    }

    /// Encodes the interface, writing the private key as base64.
    ///
    /// - Parameter encoder: The encoder to write to.
    /// - Throws: A coding error when the private key is not 32 bytes.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        guard let key = WireGuardKey(rawValue: privateKey) else {
            throw EncodingError.invalidValue(privateKey,
                                             EncodingError.Context(codingPath: [CodingKeys.privateKey],
                                                                   debugDescription: "a WireGuard private key must be 32 bytes"))
        }
        try container.encode(key.base64String, forKey: .privateKey)
        try container.encode(addresses, forKey: .addresses)
        try container.encode(dnsServers, forKey: .dnsServers)
        try container.encode(mtu, forKey: .mtu)
        try container.encodeIfPresent(listenPort, forKey: .listenPort)
    }

    /// The keys used by the synthesized `Codable` implementation.
    enum CodingKeys: String, CodingKey {
        case privateKey
        case addresses
        case dnsServers
        case mtu
        case listenPort
    }
}

/// A remote WireGuard peer.
public struct WireGuardPeer: Equatable, Sendable, Codable {

    /// The peer's public key: 32 raw bytes.
    public var publicKey: Data

    /// The optional preshared key: 32 raw bytes.
    ///
    /// When present it is mixed into the handshake as the Noise `IKpsk2` `psk`;
    /// when absent WireGuard mixes 32 zero bytes instead, so the handshake
    /// transcript is identical in shape either way.
    public var presharedKey: Data?

    /// The peer's endpoint as `host:port`.
    ///
    /// A peer with an endpoint is one this side may initiate handshakes to;
    /// a peer without one can only be reached when it initiates.
    public var endpoint: String?

    /// The destination addresses routed to this peer.
    ///
    /// WireGuard calls this the peer's `allowed-ips`, and it is the only thing
    /// that decides whether an outbound packet is encrypted for this peer and
    /// whether an inbound packet is accepted from it.
    public var allowedIPs: [CIDR]

    /// Send a keepalive every this many seconds when no traffic is sent, or
    /// `nil` to only send keepalives in response to received traffic.
    public var persistentKeepalive: UInt16?

    /// Creates a peer configuration.
    ///
    /// - Parameters:
    ///   - publicKey: 32 raw bytes of public key.
    ///   - presharedKey: Optional 32 raw bytes of preshared key.
    ///   - endpoint: Optional `host:port`.
    ///   - allowedIPs: Destinations routed to this peer.
    ///   - persistentKeepalive: Keepalive interval in seconds, or `nil`.
    public init(publicKey: Data,
                presharedKey: Data? = nil,
                endpoint: String? = nil,
                allowedIPs: [CIDR] = [],
                persistentKeepalive: UInt16? = nil) {
        self.publicKey = publicKey
        self.presharedKey = presharedKey
        self.endpoint = endpoint
        self.allowedIPs = allowedIPs
        self.persistentKeepalive = persistentKeepalive
    }

    /// Decodes a peer, reading keys from their base64 form.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a present key is malformed.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        let publicText = try container.decode(String.self, forKey: .publicKey)
        guard let publicKey = WireGuardKey(base64: publicText) else {
            throw DecodingError.dataCorruptedError(forKey: .publicKey,
                                                   in: container,
                                                   debugDescription: "\"\(publicText)\" is not a 32 byte WireGuard key")
        }
        self.publicKey = publicKey.rawValue

        if let presharedText = try container.decodeIfPresent(String.self, forKey: .presharedKey) {
            guard let presharedKey = WireGuardKey(base64: presharedText) else {
                throw DecodingError.dataCorruptedError(forKey: .presharedKey,
                                                       in: container,
                                                       debugDescription: "\"\(presharedText)\" is not a 32 byte WireGuard key")
            }
            self.presharedKey = presharedKey.rawValue
        } else {
            self.presharedKey = nil
        }

        self.endpoint = try container.decodeIfPresent(String.self, forKey: .endpoint)
        self.allowedIPs = try container.decodeIfPresent([CIDR].self, forKey: .allowedIPs) ?? []
        self.persistentKeepalive = try container.decodeIfPresent(UInt16.self, forKey: .persistentKeepalive)
    }

    /// Encodes the peer, writing keys as base64.
    ///
    /// - Parameter encoder: The encoder to write to.
    /// - Throws: A coding error when a key is not 32 bytes.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        guard let publicKey = WireGuardKey(rawValue: self.publicKey) else {
            throw EncodingError.invalidValue(self.publicKey,
                                             EncodingError.Context(codingPath: [CodingKeys.publicKey],
                                                                   debugDescription: "a WireGuard public key must be 32 bytes"))
        }
        try container.encode(publicKey.base64String, forKey: .publicKey)

        if let presharedKey {
            guard let key = WireGuardKey(rawValue: presharedKey) else {
                throw EncodingError.invalidValue(presharedKey,
                                                 EncodingError.Context(codingPath: [CodingKeys.presharedKey],
                                                                       debugDescription: "a WireGuard preshared key must be 32 bytes"))
            }
            try container.encode(key.base64String, forKey: .presharedKey)
        }
        try container.encodeIfPresent(endpoint, forKey: .endpoint)
        try container.encode(allowedIPs, forKey: .allowedIPs)
        try container.encodeIfPresent(persistentKeepalive, forKey: .persistentKeepalive)
    }

    /// The keys used by the synthesized `Codable` implementation.
    enum CodingKeys: String, CodingKey {
        case publicKey
        case presharedKey
        case endpoint
        case allowedIPs
        case persistentKeepalive
    }
}

/// A complete WireGuard tunnel configuration.
public struct WireGuardConfiguration: Equatable, Sendable, Codable {

    /// The local interface.
    public var interface: WireGuardInterface

    /// The peers.
    public var peers: [WireGuardPeer]

    /// Creates a configuration.
    ///
    /// - Parameters:
    ///   - interface: The local interface.
    ///   - peers: The peers.
    public init(interface: WireGuardInterface, peers: [WireGuardPeer]) {
        self.interface = interface
        self.peers = peers
    }

    /// Finds the peer responsible for a destination address.
    ///
    /// This is WireGuard's cryptokey routing lookup. When several peers claim
    /// an address, the most specific prefix wins; if two peers claim equally
    /// specific prefixes the first one listed wins, because that is the order
    /// `wg-quick` would have installed them in.
    ///
    /// - Parameter destination: A 4 or 16 byte destination address.
    /// - Returns: The peer whose `allowedIPs` contains the address, or `nil`.
    public func peer(forDestination destination: Data) -> WireGuardPeer? {
        var best: (peer: WireGuardPeer, prefixLength: Int)?
        for peer in peers {
            for allowed in peer.allowedIPs where allowed.contains(destination) {
                if let current = best, current.prefixLength >= allowed.prefixLength { continue }
                best = (peer, allowed.prefixLength)
            }
        }
        return best?.peer
    }

    /// The private key as a ``WireGuardKey``, when it is well formed.
    public var privateKey: WireGuardKey? {
        WireGuardKey(rawValue: interface.privateKey)
    }

    /// The default route (`0.0.0.0/0`) that this configuration claims, if any.
    public var claimedDefaultRoutes: [CIDR] {
        peers.flatMap(\.allowedIPs).filter(\.isDefaultRoute)
    }
}
