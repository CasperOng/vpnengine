//
//  TailscalePeerMapper.swift
//  VPNEngine
//
//  The payoff: a Tailscale netmap is just a WireGuard configuration waiting to
//  be written down.
//
//  Tailscale runs ordinary WireGuard. The node key *is* the WireGuard static
//  key, the tailnet address is just an interface address, and a peer's
//  `AllowedIPs` are the routes that peer will carry. The only thing Tailscale
//  adds on top is where the endpoints come from (magicsock, disco and DERP)
//  and what the packet filter says; the cryptokey routing underneath is
//  vanilla.
//
//  So the translation is:
//
//    * interface private key  = the node key private half
//    * interface addresses    = this node's `tailnet` addresses
//    * peer public key        = the peer's node key
//    * peer endpoint          = the peer's first usable `Node.Endpoints` entry
//    * peer allowed IPs       = the peer's `Addresses`, plus its `AllowedIPs`
//                               (subnet routes) when the user asked for them
//
//  ## Address ranges
//
//  Tailnet addresses live in `100.64.0.0/10`, the CGNAT / shared address space
//  from RFC 6598, plus the IPv6 prefix `fd7a:115c:a1e0::/48` (Tailscale's ULA).
//  This engine does not have to hard-code either: the server assigns the
//  addresses and sends them in `Node.Addresses`. They are worth knowing about
//  anyway, because an app that wants to show "this is a tailnet address" or to
//  avoid capturing the range twice needs the number.
//
//  ## Why 1280
//
//  Tailscale uses an MTU of 1280 for its interface, and so does this mapper.
//  The reasons, in order of how much they matter:
//
//    1. **DERP.** When two peers cannot reach each other directly their traffic
//       is relayed over a TCP/TLS connection to a DERP server. That path adds
//       TLS records on top of the UDP encapsulation, and 1280 leaves room for
//       it without fragmenting.
//    2. **1280 is the IPv6 minimum link MTU** (RFC 8200, section 5). Any path
//       that carries IPv6 at all must be able to carry a 1280 byte packet
//       without fragmenting, so a 1280 byte tunnel payload is the largest size
//       that is safe on every link the tunnel might run over — including
//       PPPoE, mobile networks and the inside of another tunnel.
//    3. **It is what Tailscale's own peers expect.** A peer that receives a
//       larger packet than it agreed to is entitled to drop it, so using 1420
//       (WireGuard's usual LAN default) would produce connections that work on
//       one network and mysteriously stall on another.
//
//  The cost is about 15% more per-packet overhead than a 1420 MTU. That is the
//  trade Tailscale makes, and matching it keeps behaviour identical between
//  this engine and a real peer.
//

import Foundation

/// Errors from translating a netmap into a WireGuard configuration.
public enum TailscaleMapperError: Error, Equatable, Sendable {

    /// The netmap has no self node yet, so there is no interface to build.
    ///
    /// - Parameter reason: What was missing.
    case netmapNotReady(String)

    /// The node key is not 32 bytes, so it cannot be a WireGuard key.
    case invalidNodeKey(size: Int)

    /// An exit node was requested but no usable peer has that stable ID.
    ///
    /// This is deliberately an error rather than a fallback to direct routing:
    /// silently sending traffic out of the local interface when the user asked
    /// for an exit node would leak the very traffic the exit node was chosen to
    /// protect.
    ///
    /// - Parameter stableID: The `StableID` that was requested.
    case exitNodeUnavailable(String)
}

/// Which endpoint to prefer for a peer.
public enum TailscaleEndpointPreference: Sendable, Equatable {

    /// Take the peer's endpoints in the order the server sent them.
    ///
    /// This is what `tailscaled` effectively does: it tries them all, in order,
    /// and remembers which one worked. This engine's data plane has exactly one
    /// transport, so "tries them all" is not available to it — it takes the
    /// first, which for a dual-stack peer is normally the public IPv4 endpoint
    /// the server learned from STUN.
    case serverOrder

    /// Skip endpoints that are not IPv4.
    ///
    /// For a caller that knows it has no IPv6 path. Choosing this avoids
    /// handing WireGuard an endpoint it can never reach, at the cost of failing
    /// against an IPv6-only peer.
    case ipv4Only
}

/// Turns a ``TailscaleNetmap`` into a ``WireGuardConfiguration``.
public enum TailscalePeerMapper {

    /// The MTU Tailscale uses for its interface. See the file header for why.
    public static let tailnetMTU = 1280

    /// The IPv4 range tailnet addresses are allocated from: RFC 6598's shared
    /// address space, `100.64.0.0/10`.
    public static let cgnatRange = CIDR(string: "100.64.0.0/10")!

    /// The IPv6 prefix Tailscale allocates tailnet addresses from.
    public static let tailnetIPv6Range = CIDR(string: "fd7a:115c:a1e0::/48")!

    /// The keepalive interval given to the exit node, in seconds.
    ///
    /// An exit node is the one peer this node must keep reachable at all times:
    /// if a NAT mapping for the exit node expires, *all* internet traffic stops
    /// until the handshake is redone. 25 seconds is WireGuard's customary
    /// value and is short enough to survive NATs whose idle timeout is 30
    /// seconds. Other peers are left at `nil`: they are reached when traffic
    /// needs them, and the session's own handshake state machine retries.
    public static let exitNodeKeepalive: UInt16 = 25

    /// Builds the WireGuard configuration for reaching a netmap's peers.
    ///
    /// Every peer that is not expired becomes a WireGuard peer, including
    /// offline ones: an offline peer's endpoint may be stale, but its routes are
    /// still what decides whether a packet is *for* it, and WireGuard's
    /// handshake retry costs nothing when there is no traffic.
    ///
    /// - Parameters:
    ///   - netmap: The netmap to translate.
    ///   - nodePrivateKey: This node's private key, 32 raw bytes.
    ///   - listenPort: The local UDP port to bind, or `nil` for ephemeral.
    ///   - acceptRoutes: Whether to honour peers' subnet routes.
    ///   - exitNodeID: The `StableID` of the chosen exit node, or `nil`.
    ///   - endpointPreference: Which of a peer's endpoints to use.
    ///   - persistentKeepalive: The keepalive for the exit node, or `nil` to
    ///     send none.
    /// - Throws: ``TailscaleMapperError`` when the netmap cannot produce a
    ///   usable configuration.
    /// - Returns: The configuration to hand to ``WireGuardSession``.
    public static func wireGuardConfiguration(netmap: TailscaleNetmap,
                                             nodePrivateKey: Data,
                                             listenPort: UInt16?,
                                             acceptRoutes: Bool,
                                             exitNodeID: String?,
                                             endpointPreference: TailscaleEndpointPreference = .serverOrder,
                                             persistentKeepalive: UInt16? = TailscalePeerMapper.exitNodeKeepalive) throws -> WireGuardConfiguration {
        guard nodePrivateKey.count == WireGuardWireFormat.publicKeySize else {
            throw TailscaleMapperError.invalidNodeKey(size: nodePrivateKey.count)
        }
        guard let selfNode = netmap.selfNode else {
            throw TailscaleMapperError.netmapNotReady("the netmap has no self node yet")
        }
        guard !selfNode.addresses.isEmpty else {
            throw TailscaleMapperError.netmapNotReady("the self node has no assigned tailnet addresses")
        }

        let exitNode = try resolveExitNode(netmap: netmap, exitNodeID: exitNodeID)

        let interface = WireGuardInterface(privateKey: nodePrivateKey,
                                          addresses: selfNode.addresses,
                                          dnsServers: [],
                                          mtu: tailnetMTU,
                                          listenPort: listenPort)

        var peers: [WireGuardPeer] = []
        for peer in netmap.peers {
            // The self node is never its own peer; a server that listed it would
            // otherwise produce a peer whose endpoint is this node's own socket.
            if peer.nodeKey == selfNode.nodeKey { continue }
            // Expired keys cannot complete a handshake, and the server has
            // already stopped sending their routes to anyone else.
            if peer.isExpired { continue }

            let allowedIPs = allowedIPs(for: peer,
                                       isExitNode: peer.id == exitNode?.id,
                                       acceptRoutes: acceptRoutes,
                                       hasExitNode: exitNode != nil)
            guard !allowedIPs.isEmpty else { continue }

            peers.append(WireGuardPeer(publicKey: peer.nodeKey,
                                       presharedKey: nil,
                                       endpoint: endpoint(for: peer, preference: endpointPreference),
                                       allowedIPs: allowedIPs,
                                       persistentKeepalive: peer.id == exitNode?.id ? persistentKeepalive : nil))
        }

        return WireGuardConfiguration(interface: interface, peers: peers)
    }

    /// The DNS servers and search domains to hand the tunnel interface.
    ///
    /// With `acceptDNS` false the answer is empty, which is how a user says "do
    /// not touch my DNS": the app then leaves the system's own resolvers alone.
    ///
    /// With it true:
    ///
    ///   * the servers are the netmap's global resolvers, in the server's
    ///     preference order, plus `100.100.100.100` when MagicDNS is on —
    ///     that address is the tailnet's own resolver, served from inside the
    ///     tunnel, and it is where MagicDNS names resolve. It is not a real host
    ///     and only means anything while the tunnel is up.
    ///   * the search domains are the netmap's `Domains`, plus the MagicDNS
    ///     domain itself (`tailnet.ts.net`), so that a bare `myhost` resolves.
    ///
    /// DNS-over-HTTPS resolvers are dropped: a URL is not something a system
    /// resolver accepts, and doing DoH inside the tunnel needs an HTTP client
    /// this engine does not have.
    ///
    /// - Parameters:
    ///   - netmap: The netmap to read DNS settings from.
    ///   - acceptDNS: Whether the user accepts the server's DNS settings.
    /// - Returns: The resolver addresses and search domains.
    public static func dnsSettings(netmap: TailscaleNetmap, acceptDNS: Bool) -> (servers: [String], search: [String]) {
        guard acceptDNS else { return ([], []) }

        var servers = netmap.dns?.plainResolverAddresses ?? []
        if netmap.dns?.Proxied == true, !servers.contains(TailscalePeerMapper.magicDNSResolver) {
            servers.append(TailscalePeerMapper.magicDNSResolver)
        }

        var search = netmap.dns?.Domains ?? []
        if let domain = netmap.searchDomain, !search.contains(domain) {
            search.append(domain)
        }
        return (servers, search)
    }

    /// The tailnet's built-in resolver address, also known as "quad100".
    public static let magicDNSResolver = "100.100.100.100"

    // MARK: - Internals

    /// The peer selected as the exit node, if one was requested.
    ///
    /// - Parameters:
    ///   - netmap: The netmap to search.
    ///   - exitNodeID: The requested `StableID`, or `nil`.
    /// - Throws: ``TailscaleMapperError/exitNodeUnavailable(_:)`` when the ID
    ///   matches no usable peer.
    /// - Returns: The peer, or `nil` when no exit node was requested.
    static func resolveExitNode(netmap: TailscaleNetmap, exitNodeID: String?) throws -> TailscalePeer? {
        guard let exitNodeID, !exitNodeID.isEmpty else { return nil }
        // A numeric-ID fallback is accepted too, because ``TailscalePeer/id``
        // uses it when an older server sends no `StableID`.
        guard let peer = netmap.peer(withStableID: exitNodeID) ?? netmap.peers.first(where: { String($0.nodeID) == exitNodeID }),
              !peer.isExpired else {
            throw TailscaleMapperError.exitNodeUnavailable(exitNodeID)
        }
        return peer
    }

    /// The routes a peer should claim.
    ///
    /// - Parameters:
    ///   - peer: The peer.
    ///   - isExitNode: Whether this peer is the chosen exit node.
    ///   - acceptRoutes: Whether subnet routes are wanted at all.
    ///   - hasExitNode: Whether an exit node was chosen, in which case no other
    ///     peer may claim a route that overlaps the exit node's.
    /// - Returns: The allowed IPs, never empty for a peer with addresses.
    static func allowedIPs(for peer: TailscalePeer,
                           isExitNode: Bool,
                           acceptRoutes: Bool,
                           hasExitNode: Bool) -> [CIDR] {
        var routes: [CIDR]

        if isExitNode {
            // The exit node takes the default routes, which is what makes it an
            // exit node. Its own addresses come along too so that it stays
            // reachable at its tailnet address rather than only through itself.
            routes = peer.addresses
            if !routes.contains(where: { $0.isDefaultRoute && $0.family == .ipv4 }) {
                routes.append(CIDR(string: "0.0.0.0/0")!)
            }
            if !routes.contains(where: { $0.isDefaultRoute && $0.family == .ipv6 }) {
                routes.append(CIDR(string: "::/0")!)
            }
            return routes
        }

        if hasExitNode {
            // With an exit node chosen, every other peer keeps *only* its own
            // addresses. Sending a packet to a subnet route would otherwise
            // bypass the exit node the user asked for.
            return peer.addresses
        }

        routes = acceptRoutes ? peer.allowedIPs : peer.addresses
        if routes.isEmpty { routes = peer.addresses }
        return routes
    }

    /// The endpoint to install for a peer.
    ///
    /// - Parameters:
    ///   - peer: The peer.
    ///   - preference: Which endpoint family to prefer.
    /// - Returns: An `ip:port` string, or `nil` when the peer has none.
    static func endpoint(for peer: TailscalePeer, preference: TailscaleEndpointPreference) -> String? {
        switch preference {
        case .serverOrder:
            return peer.preferredEndpoint
        case .ipv4Only:
            return peer.endpoints.first { TailscalePeer.isUsableEndpoint($0) && TailscalePeerMapper.isIPv4Endpoint($0) }
        }
    }

    /// Whether an endpoint string names an IPv4 address.
    ///
    /// - Parameter endpoint: The endpoint text.
    /// - Returns: `true` for `1.2.3.4:5678` and for a bracketed IPv4-mapped
    ///   address, `false` otherwise.
    static func isIPv4Endpoint(_ endpoint: String) -> Bool {
        let host: Substring
        if endpoint.hasPrefix("[") {
            guard let close = endpoint.firstIndex(of: "]") else { return false }
            host = endpoint[endpoint.index(after: endpoint.startIndex) ..< close]
        } else {
            guard let colon = endpoint.lastIndex(of: ":") else { return false }
            host = endpoint[endpoint.startIndex ..< colon]
        }
        guard host.contains("."), !host.contains(":") else { return false }
        return CIDR(string: String(host))?.family == .ipv4
    }
}
