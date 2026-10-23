//
//  TailscaleConfig.swift
//  VPNEngine
//
//  Everything the user (or the app's preferences screen) chooses about a
//  Tailscale connection. This is the app-facing surface: it maps one-to-one
//  onto the fields `tailscaled` exposes in `Prefs` and `ipn`, minus the ones
//  this engine does not implement.
//
//  Source of the wire-level fields: `tailcfg.MapRequest` and
//  `tailcfg.RegisterRequest` in `tailcfg/tailcfg.go`.
//

import Foundation

/// The settings for one Tailscale connection.
///
/// The struct is `Codable` so that an app can keep it in its own preferences
/// store, and `Hashable` so that a session can tell "the settings changed" from
/// "the settings are the same".
public struct TailscaleConfig: Codable, Hashable, Sendable {

    /// The coordination server to talk to, for example
    /// `https://headscale.example.com` or `https://controlplane.tailscale.com`.
    ///
    /// This is `tailscale up --login-server` on the command line, and
    /// `Prefs.ControlURL` in `tailscaled`. The path is ignored: the control
    /// protocol appends `/key`, `/ts2021`, `/machine/register` and
    /// `/machine/map` to the host.
    public var loginServer: URL

    /// The name this node registers as, which becomes the leftmost label of its
    /// MagicDNS name (`hostname.tailnet.ts.net`).
    ///
    /// Sent as `tailcfg.Hostinfo.Hostname` and used by the coordination server
    /// to name the node. The server may deduplicate it (appending `-1`, `-2`),
    /// and the authoritative name comes back in `MapResponse.Node.Name`.
    public var hostname: String

    /// A pre-authorisation key (`tskey-auth-…`), or `nil` for interactive
    /// registration.
    ///
    /// Sent as `tailcfg.RegisterRequest.Auth.AuthKey`. With a key the server
    /// authorises the node immediately; without one it answers with
    /// `RegisterResponse.AuthURL` and the user has to visit that page, which is
    /// what ``TailscaleState/needsLogin(authURL:)`` surfaces.
    public var authKey: String?

    /// Whether to accept subnet routes advertised by other nodes.
    ///
    /// This is `tailscale up --accept-routes`, and it controls whether
    /// ``TailscalePeerMapper`` adds a peer's `Node.AllowedIPs` (its advertised
    /// routes) to that peer's WireGuard `allowedIPs`, on top of the peer's own
    /// tailnet addresses.
    public var acceptRoutes: Bool

    /// Whether to use the DNS settings from the netmap.
    ///
    /// This is `tailscale up --accept-dns`, and it controls whether
    /// ``TailscalePeerMapper/dnsSettings(netmap:acceptDNS:)`` returns the
    /// server's resolvers and search domains (MagicDNS and split DNS) or
    /// nothing at all.
    public var acceptDNS: Bool

    /// The `StableID` of the peer to route all traffic through, or `nil`.
    ///
    /// This is `tailscale up --exit-node=<ip or name>`. The selection is by
    /// `tailcfg.Node.StableID` rather than by address because addresses are
    /// reassigned when a node is re-registered, and rather than by node key
    /// because the key rotates on expiry. The value is sent to the server as
    /// `tailcfg.Hostinfo.ExitNodeID` as of capability version 122.
    public var exitNodeID: String?

    /// Whether this node offers to be an exit node for the tailnet.
    ///
    /// This is `tailscale up --advertise-exit-node`. It is advertised to the
    /// server as the `0.0.0.0/0` and `::/0` entries of
    /// `tailcfg.Hostinfo.RoutableIPs`; the tailnet admin still has to approve
    /// the advertisement before any peer can use it.
    public var advertiseExitNode: Bool

    /// Whether the node should be deleted automatically when it goes offline.
    ///
    /// Sent as `tailcfg.RegisterRequest.Ephemeral`. Useful for CI runners and
    /// short-lived containers.
    public var ephemeral: Bool

    /// The capability version to advertise, which is the client's way of saying
    /// "I understand every protocol change up to this number".
    ///
    /// See ``TailscaleConfig/defaultCapabilityVersion`` for the value this
    /// engine uses by default and why.
    public var capabilityVersion: Int

    /// An override for the endpoint that serves the netmap, when it differs
    /// from ``loginServer``.
    ///
    /// Rarely needed, and `nil` in almost every deployment: `tailscaled` calls
    /// this `Prefs.ControlURL`, and uses it to register with one server while
    /// fetching the map from another (the "login server" versus "control URL"
    /// split, which exists so that a client can be told to move to a different
    /// control plane without re-authenticating). When `nil`, everything goes to
    /// ``loginServer``.
    public var controlURLOverride: URL?

    /// The capability version this engine advertises by default: **100**.
    ///
    /// Rationale, from the capability-version list in `tailcfg/tailcfg.go`:
    ///
    /// * 68 is the floor for what this engine relies on: it is the version at
    ///   which `MapRequest.Stream` means "read-only, ignore my Hostinfo and
    ///   Endpoints", which is exactly how the session uses streaming.
    /// * 81 added `MapResponse.PacketFilters` (incremental filter updates) and
    ///   93 added stateful firewalling; 100 is comfortably past both, so a
    ///   server will not fall back to pre-81 behaviour for us.
    /// * 111 and 112 are where the protocol starts to *omit* things we would
    ///   otherwise receive: `Node.HomeDERP` replaces the legacy `DERP` string
    ///   field, and `Node.AllowedIPs` may be sent as nil to mean "the same as
    ///   Addresses". Stopping at 100 keeps the server sending the fully
    ///   explicit forms, which makes the netmap easier to reason about. The
    ///   decoder handles both forms anyway, so raising this later is safe.
    /// * Everything above 100 describes features this engine does not
    ///   implement (display messages, taildrive, hardware attestation keys,
    ///   peer relays, funnel ingress). Advertising them would invite the
    ///   server to send data we would have to ignore, and in the case of
    ///   `Hostinfo.IngressEnabled` (113) and `Hostinfo.ExitNodeID` (122) it
    ///   would mean promising to send fields we do not send.
    ///
    /// The default is conservative rather than wrong: the coordination server
    /// only uses the version to decide which optional fields to send, and every
    /// field this engine needs has been stable since well before 100.
    public static let defaultCapabilityVersion = 100

    /// Creates a configuration.
    ///
    /// - Parameters:
    ///   - loginServer: The coordination server.
    ///   - hostname: The name to register as.
    ///   - authKey: A pre-auth key, or `nil` for interactive login.
    ///   - acceptRoutes: Whether to route other nodes' subnet routes.
    ///   - acceptDNS: Whether to use the netmap's DNS settings.
    ///   - exitNodeID: The `StableID` of the exit node, or `nil`.
    ///   - advertiseExitNode: Whether to offer this node as an exit node.
    ///   - ephemeral: Whether the node should expire when it disconnects.
    ///   - capabilityVersion: The capability version to advertise.
    ///   - controlURLOverride: A separate netmap endpoint, or `nil`.
    public init(loginServer: URL,
                hostname: String,
                authKey: String? = nil,
                acceptRoutes: Bool = false,
                acceptDNS: Bool = true,
                exitNodeID: String? = nil,
                advertiseExitNode: Bool = false,
                ephemeral: Bool = false,
                capabilityVersion: Int = TailscaleConfig.defaultCapabilityVersion,
                controlURLOverride: URL? = nil) {
        self.loginServer = loginServer
        self.hostname = hostname
        self.authKey = authKey
        self.acceptRoutes = acceptRoutes
        self.acceptDNS = acceptDNS
        self.exitNodeID = exitNodeID
        self.advertiseExitNode = advertiseExitNode
        self.ephemeral = ephemeral
        self.capabilityVersion = capabilityVersion
        self.controlURLOverride = controlURLOverride
    }

    /// The base URL for netmap requests: ``controlURLOverride`` when set, and
    /// ``loginServer`` otherwise.
    public var controlURL: URL {
        controlURLOverride ?? loginServer
    }

    /// Whether interactive registration will be needed.
    ///
    /// A configuration with a pre-auth key registers without a browser; one
    /// without a key can still be authorised by an admin, so this is a hint for
    /// the UI rather than a promise.
    public var requiresInteractiveLogin: Bool {
        (authKey?.isEmpty ?? true)
    }
}
