//
//  TailscaleNetmap.swift
//  VPNEngine
//
//  The network map: who is in the tailnet and how to reach them.
//
//  The map is *streaming*. The coordination server sends one `MapResponse` with
//  the whole world and then deltas, and each delta means something different
//  depending on which field it arrives in:
//
//    * `Peers` — the **complete** peer list. It replaces what we had.
//    * `PeersChanged` — peers to insert or replace, individually.
//    * `PeersRemoved` — node IDs to delete.
//    * `PeersChangedPatch` — field-level updates to peers we already know.
//    * `OnlineChange` / `PeerSeenChange` — one-field updates, keyed by node ID.
//
//  Getting the first three wrong is the classic netmap bug: applying `Peers` as
//  a merge leaves deleted peers behind forever, and applying `PeersChanged` as a
//  replacement drops every peer that did not change. `tailcfg` is explicit about
//  it ("If Peers is non-empty, PeersChanged and PeersRemoved should be ignored"),
//  and ``TailscaleNetmap/apply(_:)`` follows that order exactly.
//
//  Fields that are *absent* mean "no change from the last value in this stream",
//  which is why the map has to keep state rather than translate one response at
//  a time: `DNSConfig`, `Domain`, `DERPMap` and `PacketFilter` are all
//  remembered here.
//

import Foundation

/// The state of the tailnet, as far as this node knows.
public struct TailscaleNetmap: Sendable, Equatable, Codable {

    /// This node's own entry (`tailcfg.MapResponse.Node`).
    ///
    /// `nil` until the first response that carries one. Every response after
    /// that omits it unless something about this node changed, so the value
    /// persists.
    public var selfNode: TailscalePeer?

    /// The peers, keyed by nothing in particular: the order the server sent is
    /// preserved, because `tailcfg` documents `Peers` as sorted by `Node.ID`
    /// and a stable order makes UI diffs cheap.
    public var peers: [TailscalePeer]

    /// The DNS configuration (`tailcfg.MapResponse.DNSConfig`).
    ///
    /// Remembered, not reset: an absent `DNSConfig` means "unchanged".
    public var dns: TailscaleDNSConfig?

    /// The MagicDNS domain, for example `"tailnet.ts.net"`
    /// (`tailcfg.MapResponse.Domain`).
    ///
    /// Remembered: an empty `Domain` means "unchanged".
    public var domain: String?

    /// The relay regions, by region ID (`tailcfg.MapResponse.DERPMap`).
    ///
    /// A `DERPMap` is itself incremental — the protocol documents "The rest of
    /// the DERPMap fields, if zero, means unchanged" — so regions are merged
    /// into this dictionary rather than replacing it.
    public var derpRegions: [Int: TailscaleDERPRegion]

    /// Whether the packet filter permits everything.
    ///
    /// True when the merged filter contains a blanket rule (source `"*"`,
    /// destination `"*"`, all ports), which is what a default open tailnet
    /// policy and a bare Headscale install both produce. This is a *display*
    /// answer — "your traffic is unrestricted" — not an enforcement decision:
    /// this engine is a WireGuard device and does not impose the filter.
    public var packetFilterAllowsAll: Bool

    /// The server's clock (`tailcfg.MapResponse.ControlTime`), for skew
    /// detection and for stamping last-seen times.
    public var controlTime: Date?

    /// User profiles, by user ID (`tailcfg.MapResponse.UserProfiles`).
    ///
    /// The server only ever sends profiles that are new or changed, so this is
    /// merged. Not in the minimal field list, but a UI that shows "alice's
    /// laptop" needs it and the merge is one line.
    public var userProfiles: [Int64: TailscaleUserProfile]

    /// The merged packet filter rules.
    ///
    /// Kept so that ``packetFilterAllowsAll`` can be recomputed when a later
    /// frame patches the filter. `tailcfg` has two forms — the full
    /// `PacketFilter` and the incremental `PacketFilters` map — and the merging
    /// rules for both are in ``apply(_:)``.
    public var filterRules: [TailscaleFilterRule]

    /// The named packet filters from `MapResponse.PacketFilters`, by key.
    private var namedFilters: [String: [TailscaleFilterRule]]

    /// How many times the map has materially changed.
    ///
    /// Incremented by ``apply(_:)`` whenever it altered the state that
    /// ``TailscaleSession`` cares about, which is how the session decides
    /// whether a new ``WireGuardConfiguration`` has to be built. Keepalives and
    /// pure metadata updates do not move it.
    public var revision: Int

    /// Creates an empty map.
    public init() {
        self.selfNode = nil
        self.peers = []
        self.dns = nil
        self.domain = nil
        self.derpRegions = [:]
        self.packetFilterAllowsAll = false
        self.controlTime = nil
        self.userProfiles = [:]
        self.filterRules = []
        self.namedFilters = [:]
        self.revision = 0
    }

    /// Decodes a netmap, defaulting the fields an older snapshot may not have.
    ///
    /// Everything here is either public information (tailnet addresses, public
    /// keys) or derived from it, so a netmap is safe to persist — unlike the
    /// private keys, which live in a ``Keychain`` and never in a file.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a present field is malformed.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.selfNode = try container.decodeIfPresent(TailscalePeer.self, forKey: .selfNode)
        self.peers = try container.decodeIfPresent([TailscalePeer].self, forKey: .peers) ?? []
        self.dns = try container.decodeIfPresent(TailscaleDNSConfig.self, forKey: .dns)
        self.domain = try container.decodeIfPresent(String.self, forKey: .domain)
        self.derpRegions = try container.decodeIfPresent([String: TailscaleDERPRegion].self, forKey: .derpRegions)?
            .reduce(into: [Int: TailscaleDERPRegion]()) { result, entry in
                if let id = Int(entry.key) { result[id] = entry.value }
            } ?? [:]
        self.packetFilterAllowsAll = try container.decodeIfPresent(Bool.self, forKey: .packetFilterAllowsAll) ?? false
        self.controlTime = try container.decodeIfPresent(Date.self, forKey: .controlTime)
        self.userProfiles = try container.decodeIfPresent([String: TailscaleUserProfile].self, forKey: .userProfiles)?
            .reduce(into: [Int64: TailscaleUserProfile]()) { result, entry in
                if let id = Int64(entry.key) { result[id] = entry.value }
            } ?? [:]
        self.filterRules = try container.decodeIfPresent([TailscaleFilterRule].self, forKey: .filterRules) ?? []
        self.namedFilters = try container.decodeIfPresent([String: [TailscaleFilterRule]].self, forKey: .namedFilters) ?? [:]
        self.revision = try container.decodeIfPresent(Int.self, forKey: .revision) ?? 0
    }

    /// The keys the persisted netmap uses.
    enum CodingKeys: String, CodingKey {
        case selfNode, peers, dns, domain, derpRegions, packetFilterAllowsAll
        case controlTime, userProfiles, filterRules, namedFilters, revision
    }

    // MARK: - Applying an update

    /// Merges a streaming `MapResponse` into the map.
    ///
    /// The order is the order `tailcfg` documents and `tailscale`'s own
    /// `mapSession.updateStateFromResponse` follows:
    ///
    ///   1. the self node, if present;
    ///   2. `Peers`, which **replaces** the peer list, or
    ///      `PeersChanged`/`PeersRemoved`, which patch it;
    ///   3. `PeersChangedPatch`, applied to whatever survived step 2;
    ///   4. `OnlineChange` and `PeerSeenChange`, keyed by node ID;
    ///   5. DNS, domain, DERP, packet filter and user profiles, each of which
    ///      means "unchanged" when absent.
    ///
    /// A keepalive frame stops after recording the control time, because
    /// `tailcfg` says every other field on a keepalive is to be ignored.
    ///
    /// - Parameter response: The frame to merge.
    public mutating func apply(_ response: TailscaleMapResponse) {
        let now = Date()
        if let controlTime = response.ControlTime {
            if self.controlTime != controlTime {
                self.controlTime = controlTime
                revision += 1
            }
        }
        if response.KeepAlive { return }

        var changed = false

        if let node = response.Node {
            let updated = TailscalePeer(node: node, now: now)
            if selfNode != updated {
                selfNode = updated
                changed = true
            }
        }

        // Step 2: the peer list, or the deltas. `Peers` wins outright — a
        // response that carries both is documented never to happen, and if one
        // did, the complete list is the more trustworthy of the two.
        if let peers = response.Peers {
            let updated = peers.map { TailscalePeer(node: $0, now: now) }
            if self.peers != updated {
                self.peers = updated
                changed = true
            }
        } else {
            if let changedPeers = response.PeersChanged {
                for node in changedPeers {
                    let peer = TailscalePeer(node: node, now: now)
                    if let index = index(ofNodeID: peer.nodeID) {
                        if peers[index] != peer {
                            peers[index] = peer
                            changed = true
                        }
                    } else {
                        peers.append(peer)
                        changed = true
                    }
                }
            }
            if let removed = response.PeersRemoved {
                let doomed = Set(removed)
                if peers.contains(where: { doomed.contains($0.nodeID) }) {
                    peers.removeAll { doomed.contains($0.nodeID) }
                    changed = true
                }
            }
        }

        // Step 3: field-level patches, which arrive after the list updates and
        // are the form Headscale uses for endpoint and online-status changes.
        if let patches = response.PeersChangedPatch {
            for patch in patches {
                guard let index = index(ofNodeID: patch.NodeID) else { continue }
                if peers[index].apply(patch) { changed = true }
            }
        }

        // Step 4: the one-field maps.
        if let online = response.OnlineChange {
            for (key, value) in online {
                guard let nodeID = Int64(key), let index = index(ofNodeID: nodeID) else { continue }
                if peers[index].setOnline(value) { changed = true }
            }
        }
        if let seen = response.PeerSeenChange {
            for (key, value) in seen {
                guard let nodeID = Int64(key), let index = index(ofNodeID: nodeID) else { continue }
                if value {
                    if peers[index].setLastSeen(now) { changed = true }
                } else if peers[index].isOnline {
                    if peers[index].setOnline(false) { changed = true }
                }
            }
        }

        // Step 5: the remembered fields.
        if let dns = response.DNSConfig {
            if self.dns != dns {
                self.dns = dns
                changed = true
            }
        }
        if let domain = response.Domain, !domain.isEmpty, domain != self.domain {
            self.domain = domain
            changed = true
        }
        if let derpMap = response.DERPMap {
            var merged = derpRegions
            for (id, region) in derpMap.Regions { merged[id] = region }
            if merged != derpRegions {
                derpRegions = merged
                changed = true
            }
        }
        if let profiles = response.UserProfiles {
            for profile in profiles where userProfiles[profile.ID] != profile {
                userProfiles[profile.ID] = profile
                changed = true
            }
        }
        if applyPacketFilter(response) { changed = true }

        if changed { revision += 1 }
    }

    /// Merges the two packet-filter forms from a response.
    ///
    /// `tailcfg`'s rules, quoted from the field docs: a non-nil `PacketFilter`
    /// is equivalent to the named filter `"base"`; `PacketFilters` patches named
    /// filters, with a `null` value deleting a key and the key `"*"` with a
    /// `null` value clearing everything first. The merged result is the
    /// concatenation of `"base"` plus the sorted named filters.
    ///
    /// - Parameter response: The response to merge.
    /// - Returns: `true` when the filter changed.
    private mutating func applyPacketFilter(_ response: TailscaleMapResponse) -> Bool {
        var changed = false

        if let full = response.PacketFilter {
            // "A non-nil but empty list always means no PacketFilter (that is,
            // to block everything)" — so an empty array is a real value, which
            // is exactly the distinction `omitempty` cannot express.
            var updated = namedFilters
            updated["base"] = full.isEmpty ? [] : full
            if updated != namedFilters {
                namedFilters = updated
                changed = true
            }
        }

        if let patches = response.PacketFilters {
            for (key, value) in patches.sorted(by: { $0.key < $1.key }) {
                if key == "*", value == nil {
                    if !namedFilters.isEmpty {
                        namedFilters = [:]
                        changed = true
                    }
                    continue
                }
                if let value {
                    if namedFilters[key] != value {
                        namedFilters[key] = value
                        changed = true
                    }
                } else if namedFilters.removeValue(forKey: key) != nil {
                    changed = true
                }
            }
        }

        if changed {
            let merged = namedFilters.keys.sorted().flatMap { namedFilters[$0] ?? [] }
            filterRules = merged
            packetFilterAllowsAll = merged.contains(where: \.allowsEverything)
        }
        return changed
    }

    // MARK: - Lookups

    /// The index of a peer by numeric node ID.
    ///
    /// - Parameter nodeID: The `tailcfg.Node.ID` to find.
    /// - Returns: The index, or `nil`.
    func index(ofNodeID nodeID: Int64) -> Int? {
        peers.firstIndex { $0.nodeID == nodeID }
    }

    /// A peer by stable ID.
    ///
    /// - Parameter stableID: The `tailcfg.Node.StableID` to find.
    /// - Returns: The peer, or `nil`.
    public func peer(withStableID stableID: String) -> TailscalePeer? {
        peers.first { $0.id == stableID }
    }

    /// A peer by numeric node ID.
    ///
    /// - Parameter nodeID: The `tailcfg.Node.ID` to find.
    /// - Returns: The peer, or `nil`.
    public func peer(withNodeID nodeID: Int64) -> TailscalePeer? {
        peers.first { $0.nodeID == nodeID }
    }

    /// The peer a hostname refers to.
    ///
    /// This is what MagicDNS gives the user: `myhost` and
    /// `myhost.tailnet.ts.net` both name the same node, with or without the
    /// trailing dot, in any case. The self node is matched too, so a node can
    /// resolve its own name.
    ///
    /// - Parameter hostname: The name to resolve.
    /// - Returns: The peer, or `nil` when no node answers to the name.
    public func peer(matchingHostname hostname: String) -> TailscalePeer? {
        if let selfNode, selfNode.matches(hostname: hostname) { return selfNode }
        return peers.first { $0.matches(hostname: hostname) }
    }

    /// The tailnet address a hostname resolves to.
    ///
    /// The answer is the node's first IPv4 tailnet address (`100.x.y.z`), which
    /// is what a user or an app wants to type. Use
    /// ``peer(matchingHostname:)`` directly for the IPv6 address or the rest of
    /// the node's details.
    ///
    /// - Parameter hostname: The name to resolve.
    /// - Returns: The address as text, or `nil` when the name is unknown or the
    ///   node has no IPv4 address.
    public func address(forHostname hostname: String) -> String? {
        peer(matchingHostname: hostname)?.tailnetIPv4
    }

    /// The peer whose routes cover an address.
    ///
    /// The most specific matching prefix wins, which is the same tie-break
    /// ``WireGuardConfiguration/peer(forDestination:)`` uses, so that a packet
    /// sent to a subnet router's subnet and a packet sent to a peer's own
    /// address are attributed to the same node here and there.
    ///
    /// - Parameter address: 4 or 16 raw address bytes.
    /// - Returns: The peer, or `nil` when nothing routes the address.
    public func peer(routing address: Data) -> TailscalePeer? {
        var best: (peer: TailscalePeer, prefixLength: Int)?
        for peer in peers {
            for route in peer.allowedIPs where route.contains(address) {
                if let current = best, current.prefixLength >= route.prefixLength { continue }
                best = (peer, route.prefixLength)
            }
        }
        return best?.peer
    }

    /// Whether a peer's routes cover an address.
    ///
    /// - Parameter address: 4 or 16 raw address bytes.
    /// - Returns: `true` when some peer routes the address.
    public func routes(_ address: Data) -> Bool {
        peer(routing: address) != nil
    }

    // MARK: - Summary

    /// How many peers are in the map.
    public var peerCount: Int { peers.count }

    /// How many peers are online.
    public var onlinePeerCount: Int { peers.filter(\.isOnline).count }

    /// The peers that offer to be an exit node.
    public var exitNodeCandidates: [TailscalePeer] {
        peers.filter(\.isExitNode)
    }

    /// The MagicDNS domain in a form suitable for use as a DNS search domain.
    ///
    /// `tailcfg.MapResponse.Domain` has no trailing dot; a search domain does
    /// not either, so this is mostly a naming convenience — but it is the place
    /// to normalise if that ever changes.
    public var searchDomain: String? {
        guard let domain else { return nil }
        var text = domain
        while text.hasSuffix(".") { text.removeLast() }
        return text.isEmpty ? nil : text
    }
}
