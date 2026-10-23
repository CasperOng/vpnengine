//
//  TailscalePeer.swift
//  VPNEngine
//
//  One node in the netmap, reduced to the fields the engine and its UI need.
//
//  ``TailscalePeer`` is the engine's own model, so its names are Swift
//  style. The wire type it is built from (``TailscaleNode``) keeps Go's names.
//

import Foundation

/// A node in the tailnet: this device or one of its peers.
public struct TailscalePeer: Sendable, Equatable, Identifiable, Codable {

    /// The node's stable identifier (`tailcfg.Node.StableID`).
    ///
    /// This is what survives a re-registration, which is why an exit-node
    /// choice is stored as a stable ID rather than as an address or a node key.
    /// Older servers may not send one; when they do not, the numeric
    /// ``nodeID`` is used instead so that the value is still non-empty and
    /// still `Identifiable`.
    public var id: String

    /// The server's numeric node ID (`tailcfg.Node.ID`).
    ///
    /// Not stable across re-registrations, but it is the key that the
    /// incremental netmap updates use (`PeersRemoved`, `PeersChangedPatch`,
    /// `OnlineChange`), so it has to be kept.
    public var nodeID: Int64

    /// The short hostname.
    ///
    /// Taken from `Node.Hostinfo.Hostname` when the server sent it, and
    /// otherwise from the first label of `Node.Name`.
    public var hostname: String

    /// The node's fully-qualified MagicDNS name, **with** its trailing dot, for
    /// example `"host.tailnet.ts.net."` (`tailcfg.Node.Name`).
    ///
    /// `tailcfg` documents this field as both the FQDN and the MagicDNS name.
    public var dnsName: String

    /// The node's public key, 32 raw bytes (`tailcfg.Node.Key`).
    ///
    /// This is the peer's WireGuard public key: tailscale runs ordinary
    /// WireGuard and uses the node key as the static key, so it goes straight
    /// into ``WireGuardPeer/publicKey``.
    public var nodeKey: Data

    /// The node's disco key, 32 raw bytes (`tailcfg.Node.DiscoKey`).
    ///
    /// `nil` when the server did not send one, or sent the zero key. The disco
    /// protocol is not implemented here, but a peer's disco key is what a later
    /// implementation would need, so it is carried through the model rather
    /// than dropped.
    public var discoKey: Data?

    /// The node's own tailnet addresses (`tailcfg.Node.Addresses`), normally
    /// `100.x.y.z/32` plus an IPv6 `/128`.
    public var addresses: [CIDR]

    /// The node's UDP endpoints as `ip:port` (`tailcfg.Node.Endpoints`).
    ///
    /// Public addresses as seen by the coordination server, plus LAN addresses
    /// the node reported. An empty list means the peer has to initiate.
    public var endpoints: [String]

    /// Whether the node is connected to the coordination server
    /// (`tailcfg.Node.Online`).
    ///
    /// `tailcfg` models this as a tri-state; "unknown" becomes `false` here,
    /// because a peer that is not known to be online is not one to hand to the
    /// data plane as a first choice. Offline peers are still kept in the
    /// configuration: they may come back at any moment.
    public var isOnline: Bool

    /// Whether this peer offers to route all traffic
    /// (`tsaddr.ContainsExitRoutes` over `tailcfg.Node.AllowedIPs`).
    ///
    /// The test is "advertises both `0.0.0.0/0` and `::/0`", which is exactly
    /// what `ipn/ipnlocal` uses to set `PeerStatus.ExitNodeOption`.
    public var isExitNode: Bool

    /// Whether this peer routes subnets other than its own addresses.
    ///
    /// Derived rather than received: the protocol has no "I am a subnet router"
    /// flag, so a peer is one when its routes include something that is neither
    /// one of its own addresses nor an exit route. It is a display hint, not
    /// something to route on.
    public var isSubnetRouter: Bool

    /// The ranges this peer will route for us (`tailcfg.Node.AllowedIPs`).
    ///
    /// As of capability version 112 the server may send `AllowedIPs` as absent
    /// to mean "the same as `Addresses`"; this value is the resolved answer, so
    /// it always contains at least the peer's own addresses.
    public var allowedIPs: [CIDR]

    /// The peer's operating system (`Node.Hostinfo.OS`), empty when unknown.
    public var os: String

    /// The ACL tags applied to the peer (`tailcfg.Node.Tags`).
    public var tags: [String]

    /// When the peer was last seen online (`tailcfg.Node.LastSeen`).
    ///
    /// `nil` when the peer has never been online, or when this node is not
    /// permitted to know.
    public var lastSeen: Date?

    /// When the peer's node key expires (`tailcfg.Node.KeyExpiry`).
    ///
    /// `nil` means the key does not expire, which `tailcfg` spells as the zero
    /// time being omitted.
    public var keyExpiry: Date?

    /// Whether the peer's key is expired, as of when this value was built
    /// (`tailcfg.Node.Expired`, plus a local check against ``keyExpiry``).
    ///
    /// The protocol says clients compute this from `KeyExpiry` to avoid clock
    /// skew, and that an explicit `Expired` may only be turned from false to
    /// true. Use ``isExpired(at:)`` for a decision made "now" rather than "when
    /// this peer was decoded".
    public var isExpired: Bool

    /// The peer's home DERP region, zero when unknown
    /// (`tailcfg.Node.HomeDERP`).
    public var derpRegion: Int

    /// The user that owns the peer (`tailcfg.Node.User`), as a numeric ID.
    public var userID: Int64

    /// Creates a peer.
    ///
    /// - Parameters:
    ///   - id: The stable ID; falls back to the numeric ID when empty.
    ///   - nodeID: The numeric node ID.
    ///   - hostname: The short hostname.
    ///   - dnsName: The FQDN, with trailing dot.
    ///   - nodeKey: 32 raw bytes of WireGuard public key.
    ///   - discoKey: 32 raw bytes of disco key, or `nil`.
    ///   - addresses: The tailnet addresses.
    ///   - endpoints: The peer's endpoints.
    ///   - isOnline: Whether the peer is online.
    ///   - allowedIPs: The ranges the peer routes.
    ///   - os: The peer's operating system.
    ///   - tags: The peer's ACL tags.
    ///   - lastSeen: When the peer was last seen.
    ///   - keyExpiry: When the peer's key expires.
    ///   - isExpired: Whether the key is expired.
    ///   - derpRegion: The peer's home DERP region.
    ///   - userID: The peer's owner.
    public init(id: String,
                nodeID: Int64 = 0,
                hostname: String,
                dnsName: String,
                nodeKey: Data,
                discoKey: Data? = nil,
                addresses: [CIDR],
                endpoints: [String] = [],
                isOnline: Bool = false,
                allowedIPs: [CIDR] = [],
                os: String = "",
                tags: [String] = [],
                lastSeen: Date? = nil,
                keyExpiry: Date? = nil,
                isExpired: Bool = false,
                derpRegion: Int = 0,
                userID: Int64 = 0) {
        self.id = id
        self.nodeID = nodeID
        self.hostname = hostname
        self.dnsName = dnsName
        self.nodeKey = nodeKey
        self.discoKey = discoKey
        self.addresses = addresses
        self.endpoints = endpoints
        self.isOnline = isOnline
        self.isExitNode = TailscalePeer.containsExitRoutes(allowedIPs.isEmpty ? addresses : allowedIPs)
        self.isSubnetRouter = TailscalePeer.routesSubnets(allowedIPs: allowedIPs.isEmpty ? addresses : allowedIPs)
        self.allowedIPs = allowedIPs.isEmpty ? addresses : allowedIPs
        self.os = os
        self.tags = tags
        self.lastSeen = lastSeen
        self.keyExpiry = keyExpiry
        self.isExpired = isExpired
        self.derpRegion = derpRegion
        self.userID = userID
    }

    /// Builds a peer from a decoded `tailcfg.Node`.
    ///
    /// - Parameters:
    ///   - node: The wire node.
    ///   - now: The instant to evaluate key expiry at.
    /// - Returns: The peer.
    public init(node: TailscaleNode, now: Date = Date()) {
        let stableID = node.StableID.isEmpty ? String(node.ID) : node.StableID
        let hostname = TailscalePeer.shortHostname(fromName: node.Name,
                                                   hostinfoHostname: node.Hostinfo?.Hostname)
        // `AllowedIPs` absent (as of capability version 112) means "the same as
        // Addresses"; `tailcfg.Node` says so in the field's doc comment.
        let allowed = node.AllowedIPs ?? node.Addresses
        self.init(id: stableID,
                  nodeID: node.ID,
                  hostname: hostname,
                  dnsName: node.Name,
                  nodeKey: node.Key.rawValue,
                  discoKey: TailscalePeer.usableDiscoKey(node.DiscoKey),
                  addresses: node.Addresses,
                  endpoints: node.Endpoints,
                  isOnline: node.Online ?? false,
                  allowedIPs: allowed,
                  os: node.Hostinfo?.OS ?? "",
                  tags: node.Tags,
                  lastSeen: node.LastSeen,
                  keyExpiry: node.KeyExpiry,
                  isExpired: node.Expired || TailscalePeer.hasExpired(keyExpiry: node.KeyExpiry, now: now),
                  derpRegion: node.HomeDERP,
                  userID: node.User)
    }

    // MARK: - Derived properties

    /// Whether the peer's key has expired at a given moment.
    ///
    /// - Parameter now: The instant to evaluate.
    /// - Returns: `true` when the server marked the node expired or its key
    ///   expiry has passed.
    public func isExpired(at now: Date) -> Bool {
        isExpired || TailscalePeer.hasExpired(keyExpiry: keyExpiry, now: now)
    }

    /// The peer's first tailnet IPv4 address as text, if it has one.
    ///
    /// This is the `100.x.y.z` address a user would type, and the one MagicDNS
    /// resolves a name to.
    public var tailnetIPv4: String? {
        addresses.first { $0.family == .ipv4 }?.description.split(separator: "/").first.map(String.init)
    }

    /// The peer's first tailnet IPv6 address as text, if it has one.
    public var tailnetIPv6: String? {
        addresses.first { $0.family == .ipv6 }?.description.split(separator: "/").first.map(String.init)
    }

    /// The first endpoint that is usable as a WireGuard peer endpoint.
    ///
    /// ``TailscalePeerMapper`` uses this to fill `WireGuardPeer.endpoint`.
    ///
    /// IPv6 endpoints are accepted: an endpoint that this side cannot reach is
    /// harmless (the handshake simply never completes) and dropping them would
    /// break dual-stack peers on networks where IPv6 works. What is *not*
    /// usable is an empty string or an entry with no port, which the server
    /// occasionally sends for a node it has never seen connect.
    public var preferredEndpoint: String? {
        endpoints.first(where: TailscalePeer.isUsableEndpoint)
    }

    /// Whether a string is usable as a `host:port` endpoint.
    ///
    /// - Parameter endpoint: The candidate endpoint.
    /// - Returns: `true` when it has a host and a numeric port.
    public static func isUsableEndpoint(_ endpoint: String) -> Bool {
        let trimmed = endpoint.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return false }
        if trimmed.hasPrefix("[") {
            // "[2001:db8::1]:41641"
            guard let close = trimmed.firstIndex(of: "]") else { return false }
            let after = trimmed.index(after: close)
            guard after < trimmed.endIndex, trimmed[after] == ":" else { return false }
            return UInt16(trimmed[trimmed.index(after: after)...]) != nil
        }
        guard let colon = trimmed.lastIndex(of: ":") else { return false }
        guard trimmed[trimmed.startIndex ..< colon].contains(":") == false else { return false }
        return UInt16(trimmed[trimmed.index(after: colon)...]) != nil
    }

    // MARK: - Hostname matching

    /// Whether this peer answers to a hostname.
    ///
    /// The comparison is case-insensitive and accepts the short name
    /// (`"myhost"`), the FQDN with or without its trailing dot
    /// (`"myhost.tailnet.ts.net"`), and the numeric-ID fallback that
    /// ``id`` uses when the server sent no stable ID.
    ///
    /// - Parameter hostname: The name to match.
    /// - Returns: `true` when the name refers to this peer.
    public func matches(hostname: String) -> Bool {
        let candidate = TailscalePeer.normalize(hostname: hostname)
        guard !candidate.isEmpty else { return false }
        if candidate == TailscalePeer.normalize(hostname: self.hostname) { return true }
        if candidate == TailscalePeer.normalize(hostname: dnsName) { return true }
        if candidate == id.lowercased() { return true }
        return false
    }

    /// Lowercases a hostname and strips a trailing dot.
    ///
    /// - Parameter hostname: The name to normalise.
    /// - Returns: The comparable form.
    static func normalize(hostname: String) -> String {
        var text = hostname.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        while text.hasSuffix(".") { text.removeLast() }
        return text
    }

    /// The short hostname for a node, preferring what the node reported.
    ///
    /// - Parameters:
    ///   - name: `Node.Name`, the FQDN with a trailing dot.
    ///   - hostinfoHostname: `Node.Hostinfo.Hostname`, when present.
    /// - Returns: The short name, or an empty string.
    static func shortHostname(fromName name: String, hostinfoHostname: String?) -> String {
        if let hostinfoHostname, !hostinfoHostname.isEmpty { return hostinfoHostname }
        guard let firstLabel = name.split(separator: ".").first else { return "" }
        return String(firstLabel)
    }

    /// The disco key, when it is present and not the zero key.
    ///
    /// - Parameter key: The decoded key.
    /// - Returns: 32 raw bytes, or `nil`.
    static func usableDiscoKey(_ key: TailscalePublicKey?) -> Data? {
        guard let key, !key.isZero else { return nil }
        return key.rawValue
    }

    /// Whether a key expiry has passed.
    ///
    /// - Parameters:
    ///   - keyExpiry: The expiry, or `nil` for "never".
    ///   - now: The instant to evaluate.
    /// - Returns: `true` when there is an expiry and it is in the past.
    static func hasExpired(keyExpiry: Date?, now: Date) -> Bool {
        guard let keyExpiry else { return false }
        return keyExpiry <= now
    }

    /// Whether a route set contains both exit routes.
    ///
    /// Mirrors `tsaddr.ContainsExitRoutes`: `0.0.0.0/0` **and** `::/0`.
    ///
    /// - Parameter routes: The routes to test.
    /// - Returns: `true` when both default routes are present.
    static func containsExitRoutes(_ routes: [CIDR]) -> Bool {
        var hasV4 = false
        var hasV6 = false
        for route in routes where route.isDefaultRoute {
            if route.family == .ipv4 { hasV4 = true } else { hasV6 = true }
        }
        return hasV4 && hasV6
    }

    /// Whether a route set advertises subnets beyond the node's own addresses.
    ///
    /// A node's own addresses are always host routes (`/32`, `/128`), so
    /// anything else that is not an exit route is a subnet the node is offering
    /// to route. The protocol has no explicit flag for this, so this is a
    /// derivation rather than a field, and it is only used for display.
    ///
    /// - Parameter allowedIPs: The node's resolved routes.
    /// - Returns: `true` when a non-host, non-exit route is present.
    static func routesSubnets(allowedIPs: [CIDR]) -> Bool {
        for route in allowedIPs {
            if route.isDefaultRoute { continue }
            if route.prefixLength == 32 || route.prefixLength == 128 { continue }
            return true
        }
        return false
    }

    // MARK: - Incremental updates

    /// Applies a `tailcfg.PeerChange` patch.
    ///
    /// Only the fields the patch actually carries are touched: `tailcfg` uses
    /// absence to mean "unchanged", and a patch that is applied as a wholesale
    /// replacement would erase endpoints the server did not resend.
    ///
    /// - Parameter patch: The patch, which must be for this peer.
    /// - Returns: `true` when anything changed.
    @discardableResult
    public mutating func apply(_ patch: TailscalePeerChange) -> Bool {
        guard patch.NodeID == nodeID else { return false }
        var changed = false

        if let endpoints = patch.Endpoints, endpoints != self.endpoints {
            self.endpoints = endpoints
            changed = true
        }
        if let online = patch.Online, online != isOnline {
            self.isOnline = online
            changed = true
        }
        if let key = patch.Key, key.rawValue != nodeKey {
            self.nodeKey = key.rawValue
            changed = true
        }
        if let discoKey = patch.DiscoKey, discoKey.rawValue != self.discoKey {
            self.discoKey = discoKey.isZero ? nil : discoKey.rawValue
            changed = true
        }
        if let lastSeen = patch.LastSeen, lastSeen != self.lastSeen {
            self.lastSeen = lastSeen
            changed = true
        }
        if let keyExpiry = patch.KeyExpiry, keyExpiry != self.keyExpiry {
            self.keyExpiry = keyExpiry
            self.isExpired = keyExpiry <= Date()
            changed = true
        }
        if patch.DERPRegion != 0, patch.DERPRegion != derpRegion {
            self.derpRegion = patch.DERPRegion
            changed = true
        }
        return changed
    }

    /// Updates the online flag, returning whether it changed.
    ///
    /// - Parameter online: The new value.
    /// - Returns: `true` when the value changed.
    @discardableResult
    public mutating func setOnline(_ online: Bool) -> Bool {
        guard online != isOnline else { return false }
        isOnline = online
        if online { lastSeen = Date() }
        return true
    }

    /// Updates the last-seen time, returning whether it changed.
    ///
    /// - Parameter date: The new value.
    /// - Returns: `true` when the value changed.
    @discardableResult
    public mutating func setLastSeen(_ date: Date) -> Bool {
        guard date != lastSeen else { return false }
        lastSeen = date
        return true
    }
}
