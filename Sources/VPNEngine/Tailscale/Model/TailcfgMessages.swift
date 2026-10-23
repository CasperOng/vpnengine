//
//  TailcfgMessages.swift
//  VPNEngine
//
//  The subset of Tailscale's `tailcfg` message types this engine needs, plus
//  the JSON coding rules Go imposes on them.
//
//  Every type here mirrors a type in `tailscale.com/tailcfg`. Property names
//  are kept **exactly as Go spells them** (`IPNVersion`, `DERPMap`,
//  `StableID`, …), because that is also the JSON key: `tailcfg`'s struct tags
//  are mostly empty, so `encoding/json` uses the Go field name. Keeping the
//  names identical means there is no mapping table to get wrong, and a
//  round-trip through this engine is byte-compatible with what tailscaled
//  sends. The engine's own model (``TailscaleNetmap``, ``TailscalePeer``) uses
//  Swift-idiomatic names; only this file speaks Go.
//
//  Decoding is deliberately forgiving, in two directions:
//
//    * **Unknown fields are ignored.** Swift's `Codable` does this for free.
//      It matters: `tailcfg` grows fields on every release, and a client that
//      refused to parse an unknown field would break whenever the server was
//      newer than the app.
//    * **Absent fields get defaults.** Most `tailcfg` fields carry
//      `json:",omitempty"` or `json:",omitzero"`, so a server is free to leave
//      them out. Every type below therefore decodes through
//      `decodeIfPresent` with an explicit default rather than requiring a key.
//
//  ## The envelope
//
//  `tailcfg.Message` — the `{ "RegisterRequest": { … } }` wrapper — **does not
//  exist in the current protocol**. What the source actually says:
//
//    * `tailcfg.RegisterRequest` is documented as "JSON-encoded and sent over
//      the control plane connection to: POST https://<control-plane>/machine/
//      register" (`tailcfg/tailcfg.go`), and the client builds the body with
//      `encode(request)` → `json.Marshal(request)`. No wrapper.
//    * `tailcfg.MapRequest` is documented the same way for
//      `POST /machine/map`, and `readMapResponseMessage` +
//      `mapSession.decodeMsg` (`control/controlclient/direct.go`) read a
//      `uint32` little-endian length followed by one zstd frame of a bare
//      `tailcfg.MapResponse`. No wrapper.
//    * Headscale, the server this engine is most likely to talk to, does
//      `json.NewDecoder(req.Body).Decode(&registerRequest)` and `…(&mapRequest)`
//      directly (`hscontrol/noise.go`), and writes bare `tailcfg.MapResponse`
//      frames (`hscontrol/poll.go`, `writeMapResponse`).
//    * `grep -rn "type Message struct"` over tailscale main, v1.58, v1.32,
//      v1.22, v1.16, v1.8, v1.0 and v0.98, and over headscale main, finds no
//      such envelope type.
//
//  The wire does have a *version tag*, but it lives **inside** the messages
//  (`RegisterRequest.Version`, `MapRequest.Version`, both
//  `tailcfg.CapabilityVersion`) rather than beside them. See
//  ``TailscaleConfig/defaultCapabilityVersion``.
//
//  ``TailscaleControlMessage`` therefore *writes* the bare form — the only
//  form either server implementation parses — and *reads* either the bare form
//  or the one-key envelope, because that costs a few lines and means a
//  future or third-party server that wraps its messages still works.
//
//  ## Framing and compression
//
//  The transport hands this layer *records*, not bytes on the wire. Record
//  framing (the little-endian length prefix) and `MapResponse` zstd
//  compression belong to the transport, not here: see the note on
//  ``TailscaleControlTransport/receiveRecord()``. This file is JSON only.
//

import Foundation

// MARK: - Go's optional bool

extension KeyedDecodingContainer {

    /// Decodes a field that Go models as `opt.Bool` (a tri-state: unset, true,
    /// false).
    ///
    /// `tailcfg` uses `opt.Bool` for fields the server may simply leave out —
    /// `Node.Online`, `NetInfo.WorkingUDP` and friends. Its JSON encoding is a
    /// plain `true`/`false`, but it also accepts the strings `"true"` and
    /// `"false"`, which older serialisers produced.
    ///
    /// - Parameter key: The field to read.
    /// - Throws: A decoding error when the value is neither a bool nor a
    ///   recognisable bool string.
    /// - Returns: `nil` when the field is absent or `null`.
    func decodeTriStateIfPresent(forKey key: Key) throws -> Bool? {
        if let value = try decodeIfPresent(Bool.self, forKey: key) {
            return value
        }
        if let text = try? decodeIfPresent(String.self, forKey: key) {
            switch text {
            case "true": return true
            case "false": return false
            default: return nil
            }
        }
        return nil
    }
}

// MARK: - Raw JSON

/// A JSON value kept as-is.
///
/// `tailcfg` has fields whose values are untyped on purpose: `Node.CapMap` is
/// `map[nodecap.Cap][]RawMessage`, where each `RawMessage` is a *string holding
/// already-encoded JSON* (`tailcfg.RawMessage`). A decoder that insists on a
/// concrete type there would reject perfectly valid capability payloads it does
/// not understand, so this type keeps the bytes.
public enum TailscaleRawJSON: Sendable, Equatable, Codable {

    /// A JSON object, keyed by member name.
    case object([String: TailscaleRawJSON])

    /// A JSON array.
    case array([TailscaleRawJSON])

    /// A JSON string.
    case string(String)

    /// A JSON number.
    case number(Double)

    /// A JSON boolean.
    case boolean(Bool)

    /// JSON `null`.
    case null

    /// Decodes any JSON value.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when the value is not JSON.
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .boolean(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([TailscaleRawJSON].self) {
            self = .array(value)
        } else if let value = try? container.decode([String: TailscaleRawJSON].self) {
            self = .object(value)
        } else {
            throw DecodingError.dataCorruptedError(in: container,
                                                   debugDescription: "not a JSON value")
        }
    }

    /// Encodes the value as it arrived.
    ///
    /// - Parameter encoder: The encoder to write to.
    /// - Throws: A coding error when the value is not JSON.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case let .object(value): try container.encode(value)
        case let .array(value): try container.encode(value)
        case let .string(value): try container.encode(value)
        case let .number(value): try container.encode(value)
        case let .boolean(value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }

    /// The value as a string, when it is one.
    public var stringValue: String? {
        if case let .string(value) = self { return value }
        return nil
    }

    /// The value as a bool, when it is one.
    public var boolValue: Bool? {
        if case let .boolean(value) = self { return value }
        return nil
    }
}

// MARK: - Hostinfo

/// A service a node advertises, in `tailcfg.Hostinfo.Services`.
///
/// The coordination server collects these to build the tailnet-wide services
/// list, which is what makes `tailscale serve` URLs discoverable.
public struct TailscaleService: Sendable, Equatable, Codable {

    /// The service protocol: usually `"tcp"` or `"udp"`, or one of the meta
    /// values `"peerapi4"`, `"peerapi6"`, `"peerapi-dns-proxy"`
    /// (`tailcfg.ServiceProto`).
    public var Proto: String

    /// The port the service listens on.
    public var Port: UInt16

    /// A human readable description, usually the process name.
    public var Description: String

    /// Creates a service entry.
    ///
    /// - Parameters:
    ///   - Proto: The protocol string.
    ///   - Port: The port number.
    ///   - Description: A description, empty when unknown.
    public init(Proto: String, Port: UInt16, Description: String = "") {
        self.Proto = Proto
        self.Port = Port
        self.Description = Description
    }

    /// Decodes a service, tolerating Go's omitted description.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when `Proto` is missing.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.Proto = try container.decodeIfPresent(String.self, forKey: .Proto) ?? ""
        self.Port = try container.decodeIfPresent(UInt16.self, forKey: .Port) ?? 0
        self.Description = try container.decodeIfPresent(String.self, forKey: .Description) ?? ""
    }
}

/// What a node tells the coordination server about itself
/// (`tailcfg.Hostinfo`).
///
/// This is the client's half of the handshake: the server uses it to name the
/// node, to group devices in the admin console, and to decide whether to offer
/// the node subnet routes. The fields this engine does not implement (posture,
/// location, TPM, cloud metadata) are simply absent from the struct, and Go's
/// decoder ignores what it does not need.
public struct TailscaleHostinfo: Sendable, Equatable, Codable {

    /// `tailcfg.Hostinfo.IPNVersion`: the version of the client, in
    /// `version.Long` format (`"1.76.1-t123-abc"`).
    public var IPNVersion: String

    /// `tailcfg.Hostinfo.FrontendLogID`: the logtail ID of the GUI process.
    ///
    /// This engine has no logtail, so it is empty; the field exists so an app
    /// that does log can fill it in.
    public var FrontendLogID: String

    /// `tailcfg.Hostinfo.BackendLogID`: the logtail ID of the daemon process.
    ///
    /// The server treats it as the node's log stream name. Sending a stable
    /// random value is enough; it is not a credential.
    public var BackendLogID: String

    /// `tailcfg.Hostinfo.OS`: the operating system, as a `version.OS` value
    /// (`"macOS"`, `"iOS"`, `"linux"`, `"windows"`).
    public var OS: String

    /// `tailcfg.Hostinfo.OSVersion`: for Apple platforms, a version like
    /// `"15.6.1"`.
    public var OSVersion: String

    /// `tailcfg.Hostinfo.Hostname`: the name the node wants to be known by.
    public var Hostname: String

    /// `tailcfg.Hostinfo.Machine`: the hardware model (`uname -m`, or
    /// `"iPhone12,3"` on mobile).
    public var Machine: String

    /// `tailcfg.Hostinfo.GoArch`: `GOARCH` of the binary.
    ///
    /// Go-typed, and this engine is not Go, but the field is what the server
    /// and `tailscale status` display. Apple silicon is `arm64`, which is also
    /// `GOARCH` on arm64, so the values happen to line up.
    public var GoArch: String

    /// `tailcfg.Hostinfo.GoVersion`: the Go version the client was built with.
    ///
    /// Kept so that the value can be filled in when the app badges itself as a
    /// Go client; otherwise the server only displays it.
    public var GoVersion: String

    /// `tailcfg.Hostinfo.DeviceModel`: the device model string.
    public var DeviceModel: String

    /// `tailcfg.Hostinfo.Package`: the distribution channel (`"appstore"`,
    /// `"choco"`, …). Empty when unknown.
    public var Package: String

    /// `tailcfg.Hostinfo.Env`: a `hostinfo.EnvType` string, empty for
    /// non-container installs.
    public var Env: String

    /// `tailcfg.Hostinfo.RoutableIPs`: the routes this node advertises.
    ///
    /// This is how a subnet router or an exit node announces itself:
    /// `advertiseExitNode` becomes `0.0.0.0/0` plus `::/0` here, and the
    /// tailnet admin still has to approve each route before any peer uses it.
    public var RoutableIPs: [CIDR]

    /// `tailcfg.Hostinfo.RequestTags`: the ACL tags this node asks to claim.
    ///
    /// Authentication is by pre-auth key or by an admin, and the server grants
    /// the tags only if the policy file says the caller may claim them.
    public var RequestTags: [String]

    /// `tailcfg.Hostinfo.ExitNodeID`: the `StableID` of the exit node this node
    /// has chosen, empty when unselected.
    ///
    /// This is the client telling the server its choice, which matters because
    /// the server uses it to decide what to send in `MapResponse` (for example
    /// whether to include the exit node's DNS behaviour). Supported from
    /// capability version 122; earlier versions simply leave it out.
    public var ExitNodeID: String

    /// `tailcfg.Hostinfo.ShieldsUp`: whether the node refuses inbound
    /// connections.
    ///
    /// Tailscale's "shields up" mode. It only affects the server's
    /// bookkeeping and the peer API; WireGuard itself is unaffected.
    public var ShieldsUp: Bool

    /// `tailcfg.Hostinfo.Userspace`: whether the node runs without a TUN
    /// device.
    ///
    /// True means the client does its own IP stack (netstack). This engine
    /// drives a real `WireGuardSession`, so it reports `false`.
    public var Userspace: Bool?

    /// `tailcfg.Hostinfo.App`: disambiguates clients built on `tsnet`
    /// (`"k8s-operator"`, …). Empty here.
    public var App: String

    /// `tailcfg.Hostinfo.Services`: the services this node advertises.
    public var Services: [TailscaleService]

    /// `tailcfg.Hostinfo.NetInfo`: NAT and connectivity self-assessment.
    public var NetInfo: TailscaleNetInfo?

    /// Creates a hostinfo with the fields a fresh client sends.
    ///
    /// - Parameters:
    ///   - hostname: The requested node name.
    ///   - os: The `version.OS` string.
    ///   - ipnVersion: The client version string.
    ///   - backendLogID: A stable per-install identifier for logs.
    ///   - goArch: The `GOARCH` string, `"arm64"` on Apple silicon.
    ///   - routableIPs: Advertised routes.
    ///   - requestTags: Requested ACL tags.
    public init(hostname: String,
                os: String,
                ipnVersion: String,
                backendLogID: String,
                goArch: String = "arm64",
                routableIPs: [CIDR] = [],
                requestTags: [String] = []) {
        self.IPNVersion = ipnVersion
        self.FrontendLogID = ""
        self.BackendLogID = backendLogID
        self.OS = os
        self.OSVersion = ""
        self.Hostname = hostname
        self.Machine = ""
        self.GoArch = goArch
        self.GoVersion = ""
        self.DeviceModel = ""
        self.Package = ""
        self.Env = ""
        self.RoutableIPs = routableIPs
        self.RequestTags = requestTags
        self.ExitNodeID = ""
        self.ShieldsUp = false
        self.Userspace = false
        self.App = ""
        self.Services = []
        self.NetInfo = nil
    }

    /// Decodes hostinfo, defaulting every field Go may omit.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a present field has the wrong type.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.IPNVersion = try container.decodeIfPresent(String.self, forKey: .IPNVersion) ?? ""
        self.FrontendLogID = try container.decodeIfPresent(String.self, forKey: .FrontendLogID) ?? ""
        self.BackendLogID = try container.decodeIfPresent(String.self, forKey: .BackendLogID) ?? ""
        self.OS = try container.decodeIfPresent(String.self, forKey: .OS) ?? ""
        self.OSVersion = try container.decodeIfPresent(String.self, forKey: .OSVersion) ?? ""
        self.Hostname = try container.decodeIfPresent(String.self, forKey: .Hostname) ?? ""
        self.Machine = try container.decodeIfPresent(String.self, forKey: .Machine) ?? ""
        self.GoArch = try container.decodeIfPresent(String.self, forKey: .GoArch) ?? ""
        self.GoVersion = try container.decodeIfPresent(String.self, forKey: .GoVersion) ?? ""
        self.DeviceModel = try container.decodeIfPresent(String.self, forKey: .DeviceModel) ?? ""
        self.Package = try container.decodeIfPresent(String.self, forKey: .Package) ?? ""
        self.Env = try container.decodeIfPresent(String.self, forKey: .Env) ?? ""
        self.RoutableIPs = try container.decodeIfPresent([CIDR].self, forKey: .RoutableIPs) ?? []
        self.RequestTags = try container.decodeIfPresent([String].self, forKey: .RequestTags) ?? []
        self.ExitNodeID = try container.decodeIfPresent(String.self, forKey: .ExitNodeID) ?? ""
        self.ShieldsUp = try container.decodeIfPresent(Bool.self, forKey: .ShieldsUp) ?? false
        self.Userspace = try container.decodeTriStateIfPresent(forKey: .Userspace)
        self.App = try container.decodeIfPresent(String.self, forKey: .App) ?? ""
        self.Services = try container.decodeIfPresent([TailscaleService].self, forKey: .Services) ?? []
        self.NetInfo = try container.decodeIfPresent(TailscaleNetInfo.self, forKey: .NetInfo)
    }

    /// The keys `tailcfg.Hostinfo` uses.
    enum CodingKeys: String, CodingKey {
        case IPNVersion, FrontendLogID, BackendLogID, OS, OSVersion, Hostname, Machine
        case GoArch, GoVersion, DeviceModel, Package, Env, RoutableIPs, RequestTags
        case ExitNodeID, ShieldsUp, Userspace, App, Services, NetInfo
    }
}

/// NAT and connectivity self-assessment (`tailcfg.NetInfo`).
///
/// The client sends this so the coordination server can hand it to peers as a
/// hint while they work out how to reach it. This engine does not run STUN or
/// port mapping yet, so the values it sends are honest zeros/unknowns; the type
/// exists so that a caller with a netcheck implementation can fill them in.
public struct TailscaleNetInfo: Sendable, Equatable, Codable {

    /// `tailcfg.NetInfo.MappingVariesByDestIP`: whether the host's NAT mapping
    /// depends on the destination, which decides whether hole punching can work
    /// at all.
    public var MappingVariesByDestIP: Bool?

    /// `tailcfg.NetInfo.WorkingIPv6`: whether IPv6 reaches the internet.
    public var WorkingIPv6: Bool?

    /// `tailcfg.NetInfo.OSHasIPv6`: whether the OS supports IPv6 at all.
    public var OSHasIPv6: Bool?

    /// `tailcfg.NetInfo.WorkingUDP`: whether outbound UDP works.
    public var WorkingUDP: Bool?

    /// `tailcfg.NetInfo.WorkingICMPv4`: whether ICMPv4 works.
    public var WorkingICMPv4: Bool?

    /// `tailcfg.NetInfo.HavePortMap`: whether a port mapping
    /// (UPnP/NAT-PMP/PCP) is already open.
    public var HavePortMap: Bool

    /// `tailcfg.NetInfo.UPnP`: whether UPnP appears to work.
    public var UPnP: Bool?

    /// `tailcfg.NetInfo.PMP`: whether NAT-PMP appears to work.
    public var PMP: Bool?

    /// `tailcfg.NetInfo.PCP`: whether PCP appears to work.
    public var PCP: Bool?

    /// `tailcfg.NetInfo.PreferredDERP`: the home DERP region, zero when
    /// unknown.
    public var PreferredDERP: Int

    /// `tailcfg.NetInfo.LinkType`: `"wired"`, `"wifi"`, `"mobile"`, or empty.
    public var LinkType: String

    /// `tailcfg.NetInfo.FirewallMode`: Linux firewall detail, empty elsewhere.
    public var FirewallMode: String

    /// Creates a netinfo, defaulting everything to unknown.
    ///
    /// - Parameters:
    ///   - PreferredDERP: The home DERP region, zero when unknown.
    ///   - LinkType: The link type string, empty when unknown.
    public init(PreferredDERP: Int = 0, LinkType: String = "") {
        self.MappingVariesByDestIP = nil
        self.WorkingIPv6 = nil
        self.OSHasIPv6 = nil
        self.WorkingUDP = nil
        self.WorkingICMPv4 = nil
        self.HavePortMap = false
        self.UPnP = nil
        self.PMP = nil
        self.PCP = nil
        self.PreferredDERP = PreferredDERP
        self.LinkType = LinkType
        self.FirewallMode = ""
    }

    /// Decodes netinfo, defaulting every field Go may omit.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a present field has the wrong type.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.MappingVariesByDestIP = try container.decodeTriStateIfPresent(forKey: .MappingVariesByDestIP)
        self.WorkingIPv6 = try container.decodeTriStateIfPresent(forKey: .WorkingIPv6)
        self.OSHasIPv6 = try container.decodeTriStateIfPresent(forKey: .OSHasIPv6)
        self.WorkingUDP = try container.decodeTriStateIfPresent(forKey: .WorkingUDP)
        self.WorkingICMPv4 = try container.decodeTriStateIfPresent(forKey: .WorkingICMPv4)
        self.HavePortMap = try container.decodeIfPresent(Bool.self, forKey: .HavePortMap) ?? false
        self.UPnP = try container.decodeTriStateIfPresent(forKey: .UPnP)
        self.PMP = try container.decodeTriStateIfPresent(forKey: .PMP)
        self.PCP = try container.decodeTriStateIfPresent(forKey: .PCP)
        self.PreferredDERP = try container.decodeIfPresent(Int.self, forKey: .PreferredDERP) ?? 0
        self.LinkType = try container.decodeIfPresent(String.self, forKey: .LinkType) ?? ""
        self.FirewallMode = try container.decodeIfPresent(String.self, forKey: .FirewallMode) ?? ""
    }

    /// The keys `tailcfg.NetInfo` uses. `DERPLatency` is skipped: this engine
    /// has no DERP measurements to record.
    enum CodingKeys: String, CodingKey {
        case MappingVariesByDestIP, WorkingIPv6, OSHasIPv6, WorkingUDP, WorkingICMPv4
        case HavePortMap, UPnP, PMP, PCP, PreferredDERP, LinkType, FirewallMode
    }
}

// MARK: - Registration

/// The pre-shared authorisation in a register request
/// (`tailcfg.RegisterResponseAuth`).
///
/// The Go type sits next to the *response* but is used by the request; the
/// field is `RegisterRequest.Auth.AuthKey`.
public struct TailscaleRegisterAuth: Sendable, Equatable, Codable {

    /// The pre-auth key, `tskey-auth-…`.
    public var AuthKey: String

    /// Creates an auth block.
    ///
    /// - Parameter AuthKey: The pre-auth key.
    public init(AuthKey: String) {
        self.AuthKey = AuthKey
    }
}

/// A node's request to join a tailnet (`tailcfg.RegisterRequest`).
///
/// Sent as the body of `POST /machine/register`. The server answers with a
/// ``TailscaleRegisterResponse``, either authorising the node immediately (when
/// `Auth` carries a pre-auth key) or by handing back an `AuthURL` for the user
/// to visit.
public struct TailscaleRegisterRequest: Sendable, Equatable, Codable {

    /// `tailcfg.RegisterRequest.Version`: the capability version. Sent as
    /// ``TailscaleConfig/capabilityVersion``; the legacy nacl transport used
    /// the value `1`, which the Noise transport never does.
    public var Version: Int

    /// `tailcfg.RegisterRequest.NodeKey`: the node's public key, as
    /// `nodekey:<hex>`.
    public var NodeKey: TailscalePublicKey

    /// `tailcfg.RegisterRequest.OldNodeKey`: the node key being replaced, which
    /// is how a rotation is distinguished from a fresh registration. Zero when
    /// there is no previous key.
    public var OldNodeKey: TailscalePublicKey

    /// `tailcfg.RegisterRequest.NLKey`: the tailnet-lock public key, as
    /// `nlpub:<hex>`.
    ///
    /// This engine does not implement tailnet lock (see ``TailscaleKeys``), so
    /// the zero key is sent — which is exactly what `tailscaled` sends when
    /// lock is not in use. The field has no `omitempty`, so it is always
    /// present on the wire.
    public var NLKey: String

    /// `tailcfg.RegisterRequest.Auth`: the pre-auth key, when there is one.
    public var Auth: TailscaleRegisterAuth?

    /// `tailcfg.RegisterRequest.Expiry`: the requested key expiry.
    ///
    /// The zero time means "use the server's policy". A time in the past is a
    /// request to expire the key now, which is how logout is implemented.
    public var Expiry: Date

    /// `tailcfg.RegisterRequest.Followup`: the `AuthURL` from a previous
    /// response.
    ///
    /// The server holds the response until that URL has been visited, which
    /// turns registration polling into a long poll. Empty on the first attempt.
    public var Followup: String

    /// `tailcfg.RegisterRequest.Hostinfo`.
    public var Hostinfo: TailscaleHostinfo?

    /// `tailcfg.RegisterRequest.Ephemeral`: whether the node should be deleted
    /// automatically once it stops being active.
    public var Ephemeral: Bool

    /// Creates a register request.
    ///
    /// - Parameters:
    ///   - Version: The capability version.
    ///   - NodeKey: The node's public key.
    ///   - OldNodeKey: The key being replaced, or `nil`.
    ///   - AuthKey: The pre-auth key, or `nil`.
    ///   - Expiry: The requested expiry, or `nil` for the server's policy.
    ///   - Followup: An auth URL from a previous response, or `nil`.
    ///   - Hostinfo: The client's hostinfo.
    ///   - Ephemeral: Whether the node is ephemeral.
    ///   - NLKey: The tailnet-lock key text; defaults to the zero key.
    public init(Version: Int,
                NodeKey: TailscalePublicKey,
                OldNodeKey: TailscalePublicKey? = nil,
                AuthKey: String? = nil,
                Expiry: Date? = nil,
                Followup: String? = nil,
                Hostinfo: TailscaleHostinfo? = nil,
                Ephemeral: Bool = false,
                NLKey: String = TailscaleRegisterRequest.zeroNetworkLockKey) {
        self.Version = Version
        self.NodeKey = NodeKey
        self.OldNodeKey = OldNodeKey ?? TailscalePublicKey(role: .node, rawValue: Data(repeating: 0, count: 32))!
        self.NLKey = NLKey
        self.Auth = AuthKey.map { TailscaleRegisterAuth(AuthKey: $0) }
        self.Expiry = Expiry ?? TailcfgCoding.goZeroTime
        self.Followup = Followup ?? ""
        self.Hostinfo = Hostinfo
        self.Ephemeral = Ephemeral
    }

    /// The zero tailnet-lock public key as text: `nlpub:` followed by 64 zeros.
    public static let zeroNetworkLockKey = "nlpub:" + String(repeating: "0", count: 64)

    /// Decodes a register request, defaulting the fields Go omits.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a required field is missing or
    ///   malformed.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.Version = try container.decodeIfPresent(Int.self, forKey: .Version) ?? 0
        guard let nodeKey = try container.decodeIfPresent(TailscalePublicKey.self, forKey: .NodeKey) else {
            throw DecodingError.dataCorruptedError(forKey: .NodeKey,
                                                   in: container,
                                                   debugDescription: "RegisterRequest.NodeKey is required")
        }
        self.NodeKey = nodeKey
        self.OldNodeKey = try container.decodeIfPresent(TailscalePublicKey.self, forKey: .OldNodeKey)
            ?? TailscalePublicKey(role: .node, rawValue: Data(repeating: 0, count: 32))!
        self.NLKey = try container.decodeIfPresent(String.self, forKey: .NLKey)
            ?? TailscaleRegisterRequest.zeroNetworkLockKey
        self.Auth = try container.decodeIfPresent(TailscaleRegisterAuth.self, forKey: .Auth)
        self.Expiry = try container.decodeIfPresent(Date.self, forKey: .Expiry) ?? TailcfgCoding.goZeroTime
        self.Followup = try container.decodeIfPresent(String.self, forKey: .Followup) ?? ""
        self.Hostinfo = try container.decodeIfPresent(TailscaleHostinfo.self, forKey: .Hostinfo)
        self.Ephemeral = try container.decodeIfPresent(Bool.self, forKey: .Ephemeral) ?? false
    }

    /// The keys `tailcfg.RegisterRequest` uses that this engine models.
    enum CodingKeys: String, CodingKey {
        case Version, NodeKey, OldNodeKey, NLKey, Auth, Expiry, Followup, Hostinfo, Ephemeral
    }
}

/// The server's answer to a register request
/// (`tailcfg.RegisterResponse`).
public struct TailscaleRegisterResponse: Sendable, Equatable, Codable {

    /// `tailcfg.RegisterResponse.User`: the user the node belongs to.
    ///
    /// Absent (zero value) until the node is authorised.
    public var User: TailscaleUser

    /// `tailcfg.RegisterResponse.Login`: the identity provider login that
    /// authorised the node.
    public var Login: TailscaleLogin

    /// `tailcfg.RegisterResponse.NodeKeyExpired`: whether the node key must be
    /// replaced.
    ///
    /// The server says this when the key it knows about has passed its expiry,
    /// typically because the node was offline for longer than the key lifetime.
    /// The remedy is to generate a new node key, keep the machine key, and
    /// register again with `OldNodeKey` set — see
    /// ``TailscaleSession/rotateNodeKeyAndReregister()``.
    public var NodeKeyExpired: Bool

    /// `tailcfg.RegisterResponse.MachineAuthorized`: whether the machine may
    /// connect.
    ///
    /// `false` with no `AuthURL` means an admin has to approve the device, so
    /// the client polls. `false` *with* an `AuthURL` means the user has to visit
    /// the URL first.
    public var MachineAuthorized: Bool

    /// `tailcfg.RegisterResponse.AuthURL`: the interactive authorisation URL,
    /// empty when none is needed.
    public var AuthURL: String

    /// `tailcfg.RegisterResponse.Error`: a fatal registration error, empty when
    /// there is none.
    ///
    /// When set, every other field is meaningless.
    public var Error: String

    /// Creates a register response.
    ///
    /// - Parameters:
    ///   - User: The owning user.
    ///   - Login: The authorising login.
    ///   - NodeKeyExpired: Whether the node key must be rotated.
    ///   - MachineAuthorized: Whether the machine may connect.
    ///   - AuthURL: The interactive login URL, or empty.
    ///   - Error: A fatal error, or empty.
    public init(User: TailscaleUser = TailscaleUser(),
                Login: TailscaleLogin = TailscaleLogin(),
                NodeKeyExpired: Bool = false,
                MachineAuthorized: Bool = false,
                AuthURL: String = "",
                Error: String = "") {
        self.User = User
        self.Login = Login
        self.NodeKeyExpired = NodeKeyExpired
        self.MachineAuthorized = MachineAuthorized
        self.AuthURL = AuthURL
        self.Error = Error
    }

    /// Decodes a register response, defaulting the fields Go omits.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a present field has the wrong type.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.User = try container.decodeIfPresent(TailscaleUser.self, forKey: .User) ?? TailscaleUser()
        self.Login = try container.decodeIfPresent(TailscaleLogin.self, forKey: .Login) ?? TailscaleLogin()
        self.NodeKeyExpired = try container.decodeIfPresent(Bool.self, forKey: .NodeKeyExpired) ?? false
        self.MachineAuthorized = try container.decodeIfPresent(Bool.self, forKey: .MachineAuthorized) ?? false
        self.AuthURL = try container.decodeIfPresent(String.self, forKey: .AuthURL) ?? ""
        self.Error = try container.decodeIfPresent(String.self, forKey: .Error) ?? ""
    }

    /// The keys `tailcfg.RegisterResponse` uses that this engine models.
    enum CodingKeys: String, CodingKey {
        case User, Login, NodeKeyExpired, MachineAuthorized, AuthURL, Error
    }

    /// The `AuthURL` as a URL, when it is a usable one.
    public var authURLValue: URL? {
        guard !AuthURL.isEmpty else { return nil }
        return URL(string: AuthURL)
    }
}

// MARK: - Users

/// A tailnet user (`tailcfg.User`).
public struct TailscaleUser: Sendable, Equatable, Codable {

    /// `tailcfg.User.ID`, a numeric user ID.
    public var ID: Int64

    /// `tailcfg.User.DisplayName`: overrides the login name when non-empty.
    public var DisplayName: String

    /// `tailcfg.User.ProfilePicURL`.
    public var ProfilePicURL: String

    /// `tailcfg.User.Created`.
    public var Created: Date?

    /// Creates a user.
    ///
    /// - Parameters:
    ///   - ID: The numeric ID.
    ///   - DisplayName: The display name.
    ///   - ProfilePicURL: The avatar URL.
    ///   - Created: The creation date.
    public init(ID: Int64 = 0,
                DisplayName: String = "",
                ProfilePicURL: String = "",
                Created: Date? = nil) {
        self.ID = ID
        self.DisplayName = DisplayName
        self.ProfilePicURL = ProfilePicURL
        self.Created = Created
    }

    /// Decodes a user, defaulting the fields Go omits.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a present field has the wrong type.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.ID = try container.decodeIfPresent(Int64.self, forKey: .ID) ?? 0
        self.DisplayName = try container.decodeIfPresent(String.self, forKey: .DisplayName) ?? ""
        self.ProfilePicURL = try container.decodeIfPresent(String.self, forKey: .ProfilePicURL) ?? ""
        self.Created = try container.decodeIfPresent(Date.self, forKey: .Created)
    }

    /// The keys `tailcfg.User` uses.
    enum CodingKeys: String, CodingKey {
        case ID, DisplayName, ProfilePicURL, Created
    }
}

/// An identity provider login (`tailcfg.Login`).
public struct TailscaleLogin: Sendable, Equatable, Codable {

    /// `tailcfg.Login.ID`.
    public var ID: Int64

    /// `tailcfg.Login.Provider`: `"google"`, `"github"`, `"okta_…"`, `"headscale"`.
    public var Provider: String

    /// `tailcfg.Login.LoginName`: an email address, or an email-shaped string.
    public var LoginName: String

    /// `tailcfg.Login.DisplayName`.
    public var DisplayName: String

    /// `tailcfg.Login.ProfilePicURL`.
    public var ProfilePicURL: String

    /// Creates a login.
    ///
    /// - Parameters:
    ///   - ID: The numeric ID.
    ///   - Provider: The provider name.
    ///   - LoginName: The login name.
    ///   - DisplayName: The display name.
    ///   - ProfilePicURL: The avatar URL.
    public init(ID: Int64 = 0,
                Provider: String = "",
                LoginName: String = "",
                DisplayName: String = "",
                ProfilePicURL: String = "") {
        self.ID = ID
        self.Provider = Provider
        self.LoginName = LoginName
        self.DisplayName = DisplayName
        self.ProfilePicURL = ProfilePicURL
    }

    /// Decodes a login, defaulting the fields Go omits.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a present field has the wrong type.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.ID = try container.decodeIfPresent(Int64.self, forKey: .ID) ?? 0
        self.Provider = try container.decodeIfPresent(String.self, forKey: .Provider) ?? ""
        self.LoginName = try container.decodeIfPresent(String.self, forKey: .LoginName) ?? ""
        self.DisplayName = try container.decodeIfPresent(String.self, forKey: .DisplayName) ?? ""
        self.ProfilePicURL = try container.decodeIfPresent(String.self, forKey: .ProfilePicURL) ?? ""
    }

    /// The keys `tailcfg.Login` uses.
    enum CodingKeys: String, CodingKey {
        case ID, Provider, LoginName, DisplayName, ProfilePicURL
    }
}

/// Display-friendly data about a user (`tailcfg.UserProfile`).
public struct TailscaleUserProfile: Sendable, Equatable, Codable {

    /// `tailcfg.UserProfile.ID`.
    public var ID: Int64

    /// `tailcfg.UserProfile.LoginName`: for display, without the provider.
    public var LoginName: String

    /// `tailcfg.UserProfile.DisplayName`.
    public var DisplayName: String

    /// `tailcfg.UserProfile.ProfilePicURL`.
    public var ProfilePicURL: String

    /// `tailcfg.UserProfile.Groups`: the policy-file groups this user is in.
    public var Groups: [String]

    /// Creates a user profile.
    ///
    /// - Parameters:
    ///   - ID: The user ID.
    ///   - LoginName: The login name.
    ///   - DisplayName: The display name.
    ///   - ProfilePicURL: The avatar URL.
    ///   - Groups: The groups the user belongs to.
    public init(ID: Int64 = 0,
                LoginName: String = "",
                DisplayName: String = "",
                ProfilePicURL: String = "",
                Groups: [String] = []) {
        self.ID = ID
        self.LoginName = LoginName
        self.DisplayName = DisplayName
        self.ProfilePicURL = ProfilePicURL
        self.Groups = Groups
    }

    /// Decodes a profile, defaulting the fields Go omits.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a present field has the wrong type.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.ID = try container.decodeIfPresent(Int64.self, forKey: .ID) ?? 0
        self.LoginName = try container.decodeIfPresent(String.self, forKey: .LoginName) ?? ""
        self.DisplayName = try container.decodeIfPresent(String.self, forKey: .DisplayName) ?? ""
        self.ProfilePicURL = try container.decodeIfPresent(String.self, forKey: .ProfilePicURL) ?? ""
        self.Groups = try container.decodeIfPresent([String].self, forKey: .Groups) ?? []
    }

    /// The keys `tailcfg.UserProfile` uses.
    enum CodingKeys: String, CodingKey {
        case ID, LoginName, DisplayName, ProfilePicURL, Groups
    }
}

// MARK: - Map request

/// The client's half of the netmap stream (`tailcfg.MapRequest`).
///
/// Sent as the body of `POST /machine/map`. With `Stream` set the server keeps
/// the response open and pushes incremental ``TailscaleMapResponse`` frames,
/// which is how a node learns about peer changes without polling.
public struct TailscaleMapRequest: Sendable, Equatable, Codable {

    /// `tailcfg.MapRequest.Version`: the capability version.
    public var Version: Int

    /// `tailcfg.MapRequest.Compress`: `"zstd"` or empty.
    ///
    /// This engine sends empty, which asks for uncompressed frames. Headscale
    /// honours that (`hscontrol/poll.go`: `if compress == util.ZstdCompression`
    /// → compress), so a Headscale deployment needs no zstd decoder at all.
    /// The tailscale-hosted control plane compresses unconditionally, so the
    /// transport has to be able to unwrap a zstd frame in that case; see
    /// ``TailscaleControlTransport``.
    public var Compress: String

    /// `tailcfg.MapRequest.KeepAlive`: whether the server should send keepalive
    /// frames.
    ///
    /// Keepalives are one of the few things that keep a NAT mapping or a
    /// watchful middlebox from dropping a long-poll that carries no traffic.
    public var KeepAlive: Bool

    /// `tailcfg.MapRequest.NodeKey`: the node's public key.
    public var NodeKey: TailscalePublicKey

    /// `tailcfg.MapRequest.DiscoKey`: the disco public key, as `discokey:<hex>`.
    public var DiscoKey: TailscalePublicKey

    /// `tailcfg.MapRequest.Stream`: whether the client wants a stream of
    /// responses rather than exactly one.
    ///
    /// As of capability version 68 this also *demotes* the request: with
    /// `Stream` true the server ignores `Hostinfo` and `Endpoints`, and the
    /// client is expected to update those on a separate request. This engine
    /// therefore sends `Hostinfo` here for older servers and does not rely on
    /// it being read.
    public var Stream: Bool

    /// `tailcfg.MapRequest.Hostinfo`.
    public var Hostinfo: TailscaleHostinfo?

    /// `tailcfg.MapRequest.Endpoints`: the node's own UDP `ip:port` endpoints,
    /// for peers to try.
    ///
    /// This engine has no disco/STUN implementation, so it always sends an
    /// empty list: it cannot discover its own endpoints and must not claim
    /// addresses it has not verified. The consequence is that peers on the same
    /// LAN can only reach this node when it initiates.
    public var Endpoints: [String]

    /// `tailcfg.MapRequest.OmitPeers`: whether the client is happy for the
    /// server to leave `Peers` out of the response.
    ///
    /// Always `false` here: the netmap *is* what this client needs.
    public var OmitPeers: Bool

    /// `tailcfg.MapRequest.ReadOnly`: deprecated in the protocol (always false
    /// as of capability version 68) and always `false` here.
    public var ReadOnly: Bool

    /// Creates a map request.
    ///
    /// - Parameters:
    ///   - Version: The capability version.
    ///   - NodeKey: The node's public key.
    ///   - DiscoKey: The disco public key.
    ///   - Stream: Whether to ask for a stream.
    ///   - Hostinfo: The client's hostinfo.
    ///   - Endpoints: The node's own endpoints, normally empty.
    ///   - KeepAlive: Whether to ask for keepalives.
    ///   - Compress: The requested compression, normally empty.
    ///   - OmitPeers: Whether peers may be omitted.
    public init(Version: Int,
                NodeKey: TailscalePublicKey,
                DiscoKey: TailscalePublicKey,
                Stream: Bool,
                Hostinfo: TailscaleHostinfo? = nil,
                Endpoints: [String] = [],
                KeepAlive: Bool = true,
                Compress: String = "",
                OmitPeers: Bool = false) {
        self.Version = Version
        self.Compress = Compress
        self.KeepAlive = KeepAlive
        self.NodeKey = NodeKey
        self.DiscoKey = DiscoKey
        self.Stream = Stream
        self.Hostinfo = Hostinfo
        self.Endpoints = Endpoints
        self.OmitPeers = OmitPeers
        self.ReadOnly = false
    }

    /// Decodes a map request, defaulting the fields Go omits.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a required field is missing.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.Version = try container.decodeIfPresent(Int.self, forKey: .Version) ?? 0
        self.Compress = try container.decodeIfPresent(String.self, forKey: .Compress) ?? ""
        self.KeepAlive = try container.decodeIfPresent(Bool.self, forKey: .KeepAlive) ?? false
        guard let nodeKey = try container.decodeIfPresent(TailscalePublicKey.self, forKey: .NodeKey) else {
            throw DecodingError.dataCorruptedError(forKey: .NodeKey,
                                                   in: container,
                                                   debugDescription: "MapRequest.NodeKey is required")
        }
        self.NodeKey = nodeKey
        self.DiscoKey = try container.decodeIfPresent(TailscalePublicKey.self, forKey: .DiscoKey)
            ?? TailscalePublicKey(role: .disco, rawValue: Data(repeating: 0, count: 32))!
        self.Stream = try container.decodeIfPresent(Bool.self, forKey: .Stream) ?? false
        self.Hostinfo = try container.decodeIfPresent(TailscaleHostinfo.self, forKey: .Hostinfo)
        self.Endpoints = try container.decodeIfPresent([String].self, forKey: .Endpoints) ?? []
        self.OmitPeers = try container.decodeIfPresent(Bool.self, forKey: .OmitPeers) ?? false
        self.ReadOnly = try container.decodeIfPresent(Bool.self, forKey: .ReadOnly) ?? false
    }

    /// The keys `tailcfg.MapRequest` uses that this engine models.
    enum CodingKeys: String, CodingKey {
        case Version, Compress, KeepAlive, NodeKey, DiscoKey, Stream, Hostinfo
        case Endpoints, OmitPeers, ReadOnly
    }
}

// MARK: - Map response

/// One frame of the netmap stream (`tailcfg.MapResponse`).
///
/// Most fields are *optional*, and the distinction between "absent" and "empty"
/// is load-bearing:
///
///   * `Peers` absent means "unchanged"; `Peers` present (even empty) means
///     "this is the complete peer list now".
///   * `PeersChanged` upserts and `PeersRemoved` deletes, and both are ignored
///     when `Peers` is present. `tailcfg` says so explicitly: "If Peers is
///     non-empty, PeersChanged and PeersRemoved should be ignored (and should be
///     empty)."
///   * `DNSConfig`, `Domain` and `DERPMap` absent mean "no change from the last
///     value seen in this stream", so they can only be applied by a netmap that
///     remembers them (``TailscaleNetmap``).
public struct TailscaleMapResponse: Sendable, Equatable, Codable {

    /// `tailcfg.MapResponse.KeepAlive`: an empty frame that exists only to
    /// prove the stream is alive.
    ///
    /// When true, every other field except `PingRequest`, `ControlTime` and
    /// `PopBrowserURL` is to be ignored.
    public var KeepAlive: Bool

    /// `tailcfg.MapResponse.Node`: this node's own entry, or `nil` for "no
    /// change".
    public var Node: TailscaleNode?

    /// `tailcfg.MapResponse.Peers`: the **complete** peer list, or `nil` when
    /// the frame carries deltas instead.
    public var Peers: [TailscaleNode]?

    /// `tailcfg.MapResponse.PeersChanged`: peers to add or replace, keyed by
    /// `Node.ID`.
    public var PeersChanged: [TailscaleNode]?

    /// `tailcfg.MapResponse.PeersRemoved`: IDs of peers that are gone.
    public var PeersRemoved: [Int64]?

    /// `tailcfg.MapResponse.PeersChangedPatch`: lightweight field-level updates
    /// to peers that are already known.
    ///
    /// Applied *after* the fields above, which is what `tailcfg` documents
    /// ("These are applied after Peers* above"). Headscale relies on this form
    /// for endpoint and online-status changes
    /// (`hscontrol/mapper/builder.go`, `WithPeerChangedPatch`), so ignoring it
    /// would leave a netmap permanently stale.
    public var PeersChangedPatch: [TailscalePeerChange]?

    /// `tailcfg.MapResponse.OnlineChange`: peers whose online status changed.
    public var OnlineChange: [String: Bool]?

    /// `tailcfg.MapResponse.PeerSeenChange`: peers whose last-seen time needs
    /// updating; `true` means "just now", `false` means "gone".
    public var PeerSeenChange: [String: Bool]?

    /// `tailcfg.MapResponse.DNSConfig`: DNS settings, or `nil` for "no change".
    public var DNSConfig: TailscaleDNSConfig?

    /// `tailcfg.MapResponse.Domain`: the tailnet's MagicDNS domain, for example
    /// `"tailnet.ts.net"`. Empty means unchanged.
    public var Domain: String?

    /// `tailcfg.MapResponse.PacketFilter`: the full packet filter, or `nil` for
    /// "no change".
    ///
    /// A non-nil *empty* list means "block everything", which `tailcfg` calls
    /// out as a distinction `omitempty` cannot express.
    public var PacketFilter: [TailscaleFilterRule]?

    /// `tailcfg.MapResponse.PacketFilters`: incremental filter updates, keyed
    /// by a server-assigned name.
    ///
    /// `nil` value entries delete that key's rules; the special key `"*"` with
    /// a `nil` value clears everything including the implicit base filter.
    public var PacketFilters: [String: [TailscaleFilterRule]?]?

    /// `tailcfg.MapResponse.DERPMap`: the relay map, or `nil` for "no change".
    public var DERPMap: TailscaleDERPMap?

    /// `tailcfg.MapResponse.UserProfiles`: new or updated profiles only.
    public var UserProfiles: [TailscaleUserProfile]?

    /// `tailcfg.MapResponse.ControlTime`: the server's clock, for skew
    /// detection and for stamping last-seen times.
    public var ControlTime: Date?

    /// Not a `tailcfg.MapResponse` field; see the doc comment on the property.
    ///
    /// `tailcfg.MapResponse` has **no** `NetInfo` member — a node's netinfo
    /// travels inside its `Hostinfo` (`Node.Hostinfo.NetInfo`). It is decoded
    /// here anyway because harnesses and older servers have been seen to put it
    /// at the top level, and ignoring the field would be worse than reading it.
    public var NetInfo: TailscaleNetInfo?

    /// Creates a map response.
    ///
    /// - Parameters:
    ///   - KeepAlive: Whether this is a keepalive frame.
    ///   - Node: The self node, or `nil`.
    ///   - Peers: The complete peer list, or `nil`.
    ///   - PeersChanged: Peers to upsert, or `nil`.
    ///   - PeersRemoved: Peers to remove, or `nil`.
    ///   - DNSConfig: The DNS settings, or `nil`.
    ///   - Domain: The MagicDNS domain, or `nil`.
    ///   - PacketFilter: The packet filter, or `nil`.
    ///   - DERPMap: The relay map, or `nil`.
    ///   - UserProfiles: Updated user profiles, or `nil`.
    ///   - ControlTime: The server's time, or `nil`.
    public init(KeepAlive: Bool = false,
                Node: TailscaleNode? = nil,
                Peers: [TailscaleNode]? = nil,
                PeersChanged: [TailscaleNode]? = nil,
                PeersRemoved: [Int64]? = nil,
                DNSConfig: TailscaleDNSConfig? = nil,
                Domain: String? = nil,
                PacketFilter: [TailscaleFilterRule]? = nil,
                DERPMap: TailscaleDERPMap? = nil,
                UserProfiles: [TailscaleUserProfile]? = nil,
                ControlTime: Date? = nil) {
        self.KeepAlive = KeepAlive
        self.Node = Node
        self.Peers = Peers
        self.PeersChanged = PeersChanged
        self.PeersRemoved = PeersRemoved
        self.PeersChangedPatch = nil
        self.OnlineChange = nil
        self.PeerSeenChange = nil
        self.DNSConfig = DNSConfig
        self.Domain = Domain
        self.PacketFilter = PacketFilter
        self.PacketFilters = nil
        self.DERPMap = DERPMap
        self.UserProfiles = UserProfiles
        self.ControlTime = ControlTime
        self.NetInfo = nil
    }

    /// Decodes a map response, defaulting the fields Go omits.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a present field has the wrong type.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.KeepAlive = try container.decodeIfPresent(Bool.self, forKey: .KeepAlive) ?? false
        self.Node = try container.decodeIfPresent(TailscaleNode.self, forKey: .Node)
        self.Peers = try container.decodeIfPresent([TailscaleNode].self, forKey: .Peers)
        self.PeersChanged = try container.decodeIfPresent([TailscaleNode].self, forKey: .PeersChanged)
        self.PeersRemoved = try container.decodeIfPresent([Int64].self, forKey: .PeersRemoved)
        self.PeersChangedPatch = try container.decodeIfPresent([TailscalePeerChange].self, forKey: .PeersChangedPatch)
        self.OnlineChange = try container.decodeStringKeyedBoolsIfPresent(forKey: .OnlineChange)
        self.PeerSeenChange = try container.decodeStringKeyedBoolsIfPresent(forKey: .PeerSeenChange)
        self.DNSConfig = try container.decodeIfPresent(TailscaleDNSConfig.self, forKey: .DNSConfig)
        self.Domain = try container.decodeIfPresent(String.self, forKey: .Domain)
        self.PacketFilter = try container.decodeIfPresent([TailscaleFilterRule].self, forKey: .PacketFilter)
        self.PacketFilters = try container.decodeIfPresent([String: [TailscaleFilterRule]?].self, forKey: .PacketFilters)
        self.DERPMap = try container.decodeIfPresent(TailscaleDERPMap.self, forKey: .DERPMap)
        self.UserProfiles = try container.decodeIfPresent([TailscaleUserProfile].self, forKey: .UserProfiles)
        self.ControlTime = try container.decodeIfPresent(Date.self, forKey: .ControlTime)
        self.NetInfo = try container.decodeIfPresent(TailscaleNetInfo.self, forKey: .NetInfo)
    }

    /// The keys `tailcfg.MapResponse` uses that this engine models.
    enum CodingKeys: String, CodingKey {
        case KeepAlive, Node, Peers, PeersChanged, PeersRemoved, PeersChangedPatch
        case OnlineChange, PeerSeenChange, DNSConfig, Domain, PacketFilter, PacketFilters
        case DERPMap, UserProfiles, ControlTime, NetInfo
    }
}

extension KeyedDecodingContainer {

    /// Decodes a JSON object whose keys are numeric strings, as Go writes
    /// `map[tailcfg.NodeID]bool`.
    ///
    /// - Parameter key: The field to read.
    /// - Throws: A decoding error when the value is not such an object.
    /// - Returns: The map with numeric keys rendered back to strings, or `nil`
    ///   when absent.
    func decodeStringKeyedBoolsIfPresent(forKey key: Key) throws -> [String: Bool]? {
        try decodeIfPresent([String: Bool].self, forKey: key)
    }
}

/// This node or a peer (`tailcfg.Node`).
///
/// Only the fields this engine reads are modelled; `tailcfg.Node` is one of the
/// largest structs in the protocol and grows constantly. Everything else is
/// ignored on the way in, which is safe because nothing here depends on a field
/// that is not present.
public struct TailscaleNode: Sendable, Equatable, Codable {

    /// `tailcfg.Node.ID`: the server's numeric node ID.
    ///
    /// This ID is not stable across a re-registration; `StableID` is.
    public var ID: Int64

    /// `tailcfg.Node.StableID`: the ID that survives re-registration.
    ///
    /// This is what an exit-node selection stores
    /// (``TailscaleConfig/exitNodeID``), because it keeps pointing at the same
    /// device after a node-key rotation.
    public var StableID: String

    /// `tailcfg.Node.Name`: the node's FQDN, **with** a trailing dot, for
    /// example `"host.tailnet.ts.net."`. It is also the MagicDNS name.
    public var Name: String

    /// `tailcfg.Node.User`: the owning user's ID.
    public var User: Int64

    /// `tailcfg.Node.Key`: the node's public key, as `nodekey:<hex>`.
    ///
    /// This is also the WireGuard public key.
    public var Key: TailscalePublicKey

    /// `tailcfg.Node.KeyExpiry`: when the node key expires. Absent means the
    /// key never expires.
    public var KeyExpiry: Date?

    /// `tailcfg.Node.Machine`: the machine key, as `mkey:<hex>`.
    public var Machine: TailscalePublicKey?

    /// `tailcfg.Node.DiscoKey`: the disco key, as `discokey:<hex>`.
    public var DiscoKey: TailscalePublicKey?

    /// `tailcfg.Node.Addresses`: the node's own tailnet addresses, normally one
    /// `100.x.y.z/32` and one `fd7a:115c:a1e0::/128`.
    public var Addresses: [CIDR]

    /// `tailcfg.Node.AllowedIPs`: the ranges this node will route.
    ///
    /// As of capability version 112 this may be **absent**, which means "the
    /// same as `Addresses`" (`tailcfg`: "As of CapabilityVersion 112, this may
    /// be nil (null or undefined) on the wire to mean the same as Addresses").
    /// Older servers always fill it in. ``TailscalePeer`` resolves the
    /// ambiguity once, on the way in.
    public var AllowedIPs: [CIDR]?

    /// `tailcfg.Node.Endpoints`: the node's UDP `ip:port` endpoints.
    public var Endpoints: [String]

    /// `tailcfg.Node.HomeDERP`: the node's home DERP region, zero when unknown.
    ///
    /// The pre-111 wire form of the same thing is a string in the `DERP` field
    /// (`"127.3.3.40:<region>"`), which is decoded as `LegacyDERP` and turned
    /// into this value.
    public var HomeDERP: Int

    /// `tailcfg.Node.Hostinfo`: what the node told the server about itself.
    public var Hostinfo: TailscaleHostinfo?

    /// `tailcfg.Node.Created`: when the node first registered.
    public var Created: Date?

    /// `tailcfg.Node.Cap`: the node's capability version, zero when the server
    /// did not send it.
    public var Cap: Int

    /// `tailcfg.Node.Tags`: the ACL tags applied to the node.
    public var Tags: [String]

    /// `tailcfg.Node.PrimaryRoutes`: the advertised routes this node is
    /// currently the primary router for.
    public var PrimaryRoutes: [CIDR]

    /// `tailcfg.Node.LastSeen`: the last time the node was online, or `nil`
    /// when unknown or not permitted.
    public var LastSeen: Date?

    /// `tailcfg.Node.Online`: whether the node is connected to the control
    /// server; `nil` means unknown.
    public var Online: Bool?

    /// `tailcfg.Node.Expired`: whether the node's key has expired.
    ///
    /// The client may only ever set this from `false` to `true`, and it is
    /// normally computed locally from `KeyExpiry` to avoid clock skew; see
    /// ``TailscalePeer/isExpired``.
    public var Expired: Bool

    /// `tailcfg.Node.Capabilities`: the deprecated flat capability list.
    public var Capabilities: [String]

    /// `tailcfg.Node.CapMap`: capabilities with their JSON payloads.
    ///
    /// Kept as raw JSON: the payload types are defined by whichever feature
    /// uses them, and a decoder that insisted on a concrete shape would reject
    /// capabilities it does not know about.
    public var CapMap: [String: [TailscaleRawJSON]]

    /// The legacy `DERP` string field, kept separately so that it never
    /// overwrites `HomeDERP` on encode.
    public var LegacyDERP: String?

    /// Creates a node.
    ///
    /// - Parameters:
    ///   - ID: The numeric node ID.
    ///   - StableID: The stable ID.
    ///   - Name: The FQDN, with trailing dot.
    ///   - Key: The node public key.
    ///   - Addresses: The tailnet addresses.
    ///   - AllowedIPs: The routed ranges, or `nil` for "same as addresses".
    ///   - Endpoints: The peer's endpoints.
    ///   - Hostname: The short hostname, used for `Hostinfo`.
    public init(ID: Int64,
                StableID: String,
                Name: String,
                Key: TailscalePublicKey,
                Addresses: [CIDR],
                AllowedIPs: [CIDR]? = nil,
                Endpoints: [String] = [],
                Hostname: String? = nil) {
        self.ID = ID
        self.StableID = StableID
        self.Name = Name
        self.User = 0
        self.Key = Key
        self.KeyExpiry = nil
        self.Machine = nil
        self.DiscoKey = nil
        self.Addresses = Addresses
        self.AllowedIPs = AllowedIPs
        self.Endpoints = Endpoints
        self.HomeDERP = 0
        self.Hostinfo = Hostname.map { TailscaleHostinfo(hostname: $0, os: "", ipnVersion: "", backendLogID: "") }
        self.Created = nil
        self.Cap = 0
        self.Tags = []
        self.PrimaryRoutes = []
        self.LastSeen = nil
        self.Online = nil
        self.Expired = false
        self.Capabilities = []
        self.CapMap = [:]
        self.LegacyDERP = nil
    }

    /// Decodes a node, defaulting the fields Go omits.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a required field is missing or a present
    ///   field has the wrong type.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.ID = try container.decodeIfPresent(Int64.self, forKey: .ID) ?? 0
        self.StableID = try container.decodeIfPresent(String.self, forKey: .StableID) ?? ""
        self.Name = try container.decodeIfPresent(String.self, forKey: .Name) ?? ""
        self.User = try container.decodeIfPresent(Int64.self, forKey: .User) ?? 0
        guard let key = try container.decodeIfPresent(TailscalePublicKey.self, forKey: .Key) else {
            throw DecodingError.dataCorruptedError(forKey: .Key,
                                                   in: container,
                                                   debugDescription: "Node.Key is required")
        }
        self.Key = key
        self.KeyExpiry = try container.decodeIfPresent(Date.self, forKey: .KeyExpiry)
        self.Machine = try container.decodeIfPresent(TailscalePublicKey.self, forKey: .Machine)
        self.DiscoKey = try container.decodeIfPresent(TailscalePublicKey.self, forKey: .DiscoKey)
        self.Addresses = try container.decodeIfPresent([CIDR].self, forKey: .Addresses) ?? []
        self.AllowedIPs = try container.decodeIfPresent([CIDR].self, forKey: .AllowedIPs)
        self.Endpoints = try container.decodeIfPresent([String].self, forKey: .Endpoints) ?? []
        self.LegacyDERP = try container.decodeIfPresent(String.self, forKey: .DERP)
        self.HomeDERP = try container.decodeIfPresent(Int.self, forKey: .HomeDERP)
            ?? TailscaleNode.regionID(fromLegacyDERP: self.LegacyDERP)
        self.Hostinfo = try container.decodeIfPresent(TailscaleHostinfo.self, forKey: .Hostinfo)
        self.Created = try container.decodeIfPresent(Date.self, forKey: .Created)
        self.Cap = try container.decodeIfPresent(Int.self, forKey: .Cap) ?? 0
        self.Tags = try container.decodeIfPresent([String].self, forKey: .Tags) ?? []
        self.PrimaryRoutes = try container.decodeIfPresent([CIDR].self, forKey: .PrimaryRoutes) ?? []
        self.LastSeen = try container.decodeIfPresent(Date.self, forKey: .LastSeen)
        self.Online = try container.decodeTriStateIfPresent(forKey: .Online)
        self.Expired = try container.decodeIfPresent(Bool.self, forKey: .Expired) ?? false
        self.Capabilities = try container.decodeIfPresent([String].self, forKey: .Capabilities) ?? []
        self.CapMap = try container.decodeIfPresent([String: [TailscaleRawJSON]].self, forKey: .CapMap) ?? [:]
    }

    /// Writes a node, including the legacy `DERP` field only when it was read.
    ///
    /// - Parameter encoder: The encoder to write to.
    /// - Throws: A coding error when a field cannot be encoded.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(ID, forKey: .ID)
        try container.encode(StableID, forKey: .StableID)
        try container.encode(Name, forKey: .Name)
        try container.encode(User, forKey: .User)
        try container.encode(Key, forKey: .Key)
        try container.encodeIfPresent(KeyExpiry, forKey: .KeyExpiry)
        try container.encodeIfPresent(Machine, forKey: .Machine)
        try container.encodeIfPresent(DiscoKey, forKey: .DiscoKey)
        try container.encode(Addresses, forKey: .Addresses)
        try container.encodeIfPresent(AllowedIPs, forKey: .AllowedIPs)
        try container.encode(Endpoints, forKey: .Endpoints)
        try container.encodeIfPresent(LegacyDERP, forKey: .DERP)
        try container.encode(HomeDERP, forKey: .HomeDERP)
        try container.encodeIfPresent(Hostinfo, forKey: .Hostinfo)
        try container.encodeIfPresent(Created, forKey: .Created)
        try container.encode(Cap, forKey: .Cap)
        try container.encode(Tags, forKey: .Tags)
        try container.encode(PrimaryRoutes, forKey: .PrimaryRoutes)
        try container.encodeIfPresent(LastSeen, forKey: .LastSeen)
        try container.encodeIfPresent(Online, forKey: .Online)
        try container.encode(Expired, forKey: .Expired)
        try container.encode(Capabilities, forKey: .Capabilities)
        try container.encode(CapMap, forKey: .CapMap)
    }

    /// The keys `tailcfg.Node` uses that this engine models.
    enum CodingKeys: String, CodingKey {
        case ID, StableID, Name, User, Key, KeyExpiry, Machine, DiscoKey
        case Addresses, AllowedIPs, Endpoints, HomeDERP
        case DERP
        case Hostinfo, Created, Cap, Tags, PrimaryRoutes, LastSeen, Online
        case Expired, Capabilities, CapMap
    }

    /// Extracts the region ID from the legacy `"127.3.3.40:<region>"` form.
    ///
    /// `tailcfg.DerpMagicIP` is the sentinel address the legacy field uses;
    /// the port is the region ID. Anything else is treated as "unknown", which
    /// is what zero means.
    ///
    /// - Parameter text: The legacy `DERP` field, when present.
    /// - Returns: The region ID, or zero.
    static func regionID(fromLegacyDERP text: String?) -> Int {
        guard let text else { return 0 }
        let parts = text.split(separator: ":")
        guard parts.count == 2, parts[0] == "127.3.3.40", let region = Int(parts[1]) else { return 0 }
        return region
    }
}

// MARK: - Peer deltas

/// A field-level update to a known peer (`tailcfg.PeerChange`).
///
/// `nil` (absent) means "unchanged" for every field, which is why they are all
/// optional. A patch for an unknown `NodeID` is ignored.
public struct TailscalePeerChange: Sendable, Equatable, Codable {

    /// `tailcfg.PeerChange.NodeID`: the node being patched, by numeric ID.
    public var NodeID: Int64

    /// `tailcfg.PeerChange.DERPRegion`: a new home DERP region, zero for "no
    /// change".
    public var DERPRegion: Int

    /// `tailcfg.PeerChange.Cap`: a new capability version, zero for "no
    /// change".
    public var Cap: Int

    /// `tailcfg.PeerChange.CapMap`: a new capability map, absent for "no
    /// change".
    public var CapMap: [String: [TailscaleRawJSON]]?

    /// `tailcfg.PeerChange.Endpoints`: new endpoints, absent for "no change".
    public var Endpoints: [String]?

    /// `tailcfg.PeerChange.Key`: a new node key, absent for "no change".
    public var Key: TailscalePublicKey?

    /// `tailcfg.PeerChange.DiscoKey`: a new disco key, absent for "no change".
    public var DiscoKey: TailscalePublicKey?

    /// `tailcfg.PeerChange.Online`: a new online status, absent for "no
    /// change".
    public var Online: Bool?

    /// `tailcfg.PeerChange.LastSeen`: a new last-seen time, absent for "no
    /// change".
    public var LastSeen: Date?

    /// `tailcfg.PeerChange.KeyExpiry`: a new key expiry, absent for "no
    /// change".
    public var KeyExpiry: Date?

    /// Creates a peer patch.
    ///
    /// - Parameters:
    ///   - NodeID: The node to patch.
    ///   - DERPRegion: The new home DERP region.
    ///   - Endpoints: The new endpoints.
    ///   - Online: The new online status.
    ///   - KeyExpiry: The new key expiry.
    public init(NodeID: Int64,
                DERPRegion: Int = 0,
                Endpoints: [String]? = nil,
                Online: Bool? = nil,
                KeyExpiry: Date? = nil) {
        self.NodeID = NodeID
        self.DERPRegion = DERPRegion
        self.Cap = 0
        self.CapMap = nil
        self.Endpoints = Endpoints
        self.Key = nil
        self.DiscoKey = nil
        self.Online = Online
        self.LastSeen = nil
        self.KeyExpiry = KeyExpiry
    }

    /// Decodes a peer patch, defaulting the fields Go omits.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a present field has the wrong type.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.NodeID = try container.decodeIfPresent(Int64.self, forKey: .NodeID) ?? 0
        self.DERPRegion = try container.decodeIfPresent(Int.self, forKey: .DERPRegion) ?? 0
        self.Cap = try container.decodeIfPresent(Int.self, forKey: .Cap) ?? 0
        self.CapMap = try container.decodeIfPresent([String: [TailscaleRawJSON]].self, forKey: .CapMap)
        self.Endpoints = try container.decodeIfPresent([String].self, forKey: .Endpoints)
        self.Key = try container.decodeIfPresent(TailscalePublicKey.self, forKey: .Key)
        self.DiscoKey = try container.decodeIfPresent(TailscalePublicKey.self, forKey: .DiscoKey)
        self.Online = try container.decodeTriStateIfPresent(forKey: .Online)
        self.LastSeen = try container.decodeIfPresent(Date.self, forKey: .LastSeen)
        self.KeyExpiry = try container.decodeIfPresent(Date.self, forKey: .KeyExpiry)
    }

    /// The keys `tailcfg.PeerChange` uses that this engine models.
    enum CodingKeys: String, CodingKey {
        case NodeID, DERPRegion, Cap, CapMap, Endpoints, Key, DiscoKey, Online, LastSeen, KeyExpiry
    }
}

// MARK: - Packet filter

/// A port range in a filter rule (`tailcfg.PortRange`).
public struct TailscalePortRange: Sendable, Equatable, Codable {

    /// `tailcfg.PortRange.First`: the low port, inclusive.
    public var First: UInt16

    /// `tailcfg.PortRange.Last`: the high port, inclusive.
    public var Last: UInt16

    /// Creates a port range.
    ///
    /// - Parameters:
    ///   - First: The low port.
    ///   - Last: The high port.
    public init(First: UInt16, Last: UInt16) {
        self.First = First
        self.Last = Last
    }

    /// Decodes a port range, defaulting missing bounds to the whole range.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a present field has the wrong type.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.First = try container.decodeIfPresent(UInt16.self, forKey: .First) ?? 0
        self.Last = try container.decodeIfPresent(UInt16.self, forKey: .Last) ?? 65535
    }

    /// The keys `tailcfg.PortRange` uses.
    enum CodingKeys: String, CodingKey {
        case First, Last
    }

    /// Whether this range spans every port.
    public var isEverything: Bool { First == 0 && Last == 65535 }
}

/// A destination in a filter rule (`tailcfg.NetPortRange`).
///
/// `IP` is a **string** in `tailcfg`, not a parsed prefix, because it also
/// accepts `"*"` and `"first-last"` ranges; that is why this type keeps it as
/// text rather than as a ``CIDR``.
public struct TailscaleNetPortRange: Sendable, Equatable, Codable {

    /// `tailcfg.NetPortRange.IP`: an IP, a CIDR, an inclusive `first-last`
    /// range, or `"*"` for everything.
    public var IP: String

    /// `tailcfg.NetPortRange.Bits`: a deprecated way of turning `IP` into a
    /// CIDR.
    public var Bits: Int?

    /// `tailcfg.NetPortRange.Ports`: the ports that are reachable.
    public var Ports: TailscalePortRange

    /// Creates a destination.
    ///
    /// - Parameters:
    ///   - IP: The destination text.
    ///   - Ports: The reachable ports.
    ///   - Bits: The deprecated CIDR length, when present.
    public init(IP: String, Ports: TailscalePortRange = TailscalePortRange(First: 0, Last: 65535), Bits: Int? = nil) {
        self.IP = IP
        self.Ports = Ports
        self.Bits = Bits
    }

    /// Decodes a destination, defaulting the fields Go omits.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a present field has the wrong type.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.IP = try container.decodeIfPresent(String.self, forKey: .IP) ?? ""
        self.Bits = try container.decodeIfPresent(Int.self, forKey: .Bits)
        self.Ports = try container.decodeIfPresent(TailscalePortRange.self, forKey: .Ports)
            ?? TailscalePortRange(First: 0, Last: 65535)
    }

    /// The keys `tailcfg.NetPortRange` uses.
    enum CodingKeys: String, CodingKey {
        case IP, Bits, Ports
    }

    /// Whether this destination is "anything, any port".
    public var isEverything: Bool { IP == "*" && Ports.isEverything }
}

/// One packet filter rule (`tailcfg.FilterRule`).
///
/// This engine does not enforce the filter — the tunnel is a plain WireGuard
/// device, and enforcing a stateful filter is a separate job — but it does look
/// at the rules to answer one question: has the tailnet policy handed this node
/// a blanket allow (``TailscaleNetmap/packetFilterAllowsAll``)? That answer is
/// what tells an app whether it may show "your traffic is unrestricted".
public struct TailscaleFilterRule: Sendable, Equatable, Codable {

    /// `tailcfg.FilterRule.SrcIPs`: the source matchers, where `"*"` means
    /// everything.
    public var SrcIPs: [String]

    /// `tailcfg.FilterRule.SrcBits`: the deprecated CIDR lengths.
    public var SrcBits: [Int]?

    /// `tailcfg.FilterRule.DstPorts`: the destinations.
    public var DstPorts: [TailscaleNetPortRange]?

    /// `tailcfg.FilterRule.IPProto`: the IP protocol numbers to match; absent
    /// means TCP, UDP and ICMP.
    public var IPProto: [Int]?

    /// Creates a rule.
    ///
    /// - Parameters:
    ///   - SrcIPs: The source matchers.
    ///   - DstPorts: The destinations.
    ///   - IPProto: The protocol numbers, or `nil` for the default set.
    public init(SrcIPs: [String], DstPorts: [TailscaleNetPortRange]? = nil, IPProto: [Int]? = nil) {
        self.SrcIPs = SrcIPs
        self.SrcBits = nil
        self.DstPorts = DstPorts
        self.IPProto = IPProto
    }

    /// Decodes a rule, defaulting the fields Go omits.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a present field has the wrong type.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.SrcIPs = try container.decodeIfPresent([String].self, forKey: .SrcIPs) ?? []
        self.SrcBits = try container.decodeIfPresent([Int].self, forKey: .SrcBits)
        self.DstPorts = try container.decodeIfPresent([TailscaleNetPortRange].self, forKey: .DstPorts)
        self.IPProto = try container.decodeIfPresent([Int].self, forKey: .IPProto)
    }

    /// The keys `tailcfg.FilterRule` uses that this engine models.
    enum CodingKeys: String, CodingKey {
        case SrcIPs, SrcBits, DstPorts, IPProto
    }

    /// Whether this rule is a blanket "from anywhere, to anywhere, on any
    /// port".
    ///
    /// The source must contain `"*"` with no narrowing `SrcBits`, and at least
    /// one destination must be `"*"` on every port. Protocol restrictions are
    /// ignored, because a rule that allows every protocol on every port is only
    /// more permissive than one that does not name protocols.
    public var allowsEverything: Bool {
        guard SrcIPs.contains("*") else { return false }
        if let SrcBits, !SrcBits.isEmpty, SrcBits.contains(where: { $0 != 0 }) { return false }
        guard let DstPorts else { return false }
        return DstPorts.contains(where: \.isEverything)
    }
}

// MARK: - DNS

/// One DNS resolver (`dnstype.Resolver`).
public struct TailscaleDNSResolver: Sendable, Equatable, Codable {

    /// `dnstype.Resolver.Addr`: an IP, an `IP:port`, an `https://` DNS-over-
    /// HTTPS URL, or an `http://node:port` URL for an exit node's DNS proxy.
    public var Addr: String

    /// `dnstype.Resolver.BootstrapResolution`: how to resolve a DoH hostname
    /// before the tunnel is up.
    public var BootstrapResolution: [String]

    /// `dnstype.Resolver.UseWithExitNode`: whether to keep using this resolver
    /// even when an exit node is selected.
    public var UseWithExitNode: Bool

    /// Creates a resolver.
    ///
    /// - Parameters:
    ///   - Addr: The resolver address or URL.
    ///   - BootstrapResolution: Bootstrap addresses for a DoH resolver.
    ///   - UseWithExitNode: Whether the resolver survives exit-node selection.
    public init(Addr: String, BootstrapResolution: [String] = [], UseWithExitNode: Bool = false) {
        self.Addr = Addr
        self.BootstrapResolution = BootstrapResolution
        self.UseWithExitNode = UseWithExitNode
    }

    /// Decodes a resolver, defaulting the fields Go omits.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a present field has the wrong type.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.Addr = try container.decodeIfPresent(String.self, forKey: .Addr) ?? ""
        self.BootstrapResolution = try container.decodeIfPresent([String].self, forKey: .BootstrapResolution) ?? []
        self.UseWithExitNode = try container.decodeIfPresent(Bool.self, forKey: .UseWithExitNode) ?? false
    }

    /// The keys `dnstype.Resolver` uses.
    enum CodingKeys: String, CodingKey {
        case Addr, BootstrapResolution, UseWithExitNode
    }
}

/// An extra DNS record (`tailcfg.DNSRecord`).
public struct TailscaleDNSRecord: Sendable, Equatable, Codable {

    /// `tailcfg.DNSRecord.Name`: the FQDN, trailing dot optional.
    public var Name: String

    /// `tailcfg.DNSRecord.Type`: the record type; empty means A or AAAA
    /// depending on `Value`.
    public var RecordType: String

    /// `tailcfg.DNSRecord.Value`: the IP address as text.
    public var Value: String

    /// Creates a record.
    ///
    /// - Parameters:
    ///   - Name: The record name.
    ///   - Type: The record type, or empty.
    ///   - Value: The record value.
    public init(Name: String, RecordType: String = "", Value: String = "") {
        self.Name = Name
        self.RecordType = RecordType
        self.Value = Value
    }

    /// Decodes a record, defaulting the fields Go omits.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a present field has the wrong type.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.Name = try container.decodeIfPresent(String.self, forKey: .Name) ?? ""
        self.RecordType = try container.decodeIfPresent(String.self, forKey: .RecordType) ?? ""
        self.Value = try container.decodeIfPresent(String.self, forKey: .Value) ?? ""
    }

    /// The keys `tailcfg.DNSRecord` uses.
    enum CodingKeys: String, CodingKey {
        case Name
        // `Type` cannot be a Swift member name at all (it collides with the
        // `foo.Type` metatype expression), so the case is named for the property and
        // mapped back to the wire key with a raw value.
        case RecordType = "Type"
        case Value
    }
}

/// The tailnet's DNS settings (`tailcfg.DNSConfig`).
public struct TailscaleDNSConfig: Sendable, Equatable, Codable {

    /// `tailcfg.DNSConfig.Resolvers`: the global resolvers, in preference
    /// order.
    public var Resolvers: [TailscaleDNSResolver]

    /// `tailcfg.DNSConfig.Routes`: split-DNS suffixes and the resolvers that
    /// answer for them.
    ///
    /// The keys are fully-qualified suffixes (a trailing dot is optional, a
    /// leading dot is not). An empty resolver list for a suffix means "let
    /// Tailscale's built-in resolver (100.100.100.100) handle it", which is how
    /// MagicDNS coexists with a corporate split-DNS zone.
    public var Routes: [String: [TailscaleDNSResolver]]

    /// `tailcfg.DNSConfig.FallbackResolvers`: resolvers for configurations that
    /// cannot work without an explicit default.
    public var FallbackResolvers: [TailscaleDNSResolver]

    /// `tailcfg.DNSConfig.Domains`: the search domains, without trailing dots.
    public var Domains: [String]

    /// `tailcfg.DNSConfig.Proxied`: whether MagicDNS is on.
    ///
    /// The name is a legacy from when it meant "proxy requests"; as of
    /// `tailcfg`'s own comment it now just means "resolve the netmap's
    /// hostnames automatically".
    public var Proxied: Bool

    /// `tailcfg.DNSConfig.Nameservers`: the deprecated plain-address resolver
    /// list, used only by capability versions 9 to 13.
    public var Nameservers: [String]

    /// `tailcfg.DNSConfig.CertDomains`: the domains the control plane will
    /// issue TLS certificates for.
    public var CertDomains: [String]

    /// `tailcfg.DNSConfig.ExtraRecords`: extra records added to MagicDNS.
    public var ExtraRecords: [TailscaleDNSRecord]

    /// `tailcfg.DNSConfig.ExitNodeFilteredSet`: the suffixes an exit node's DNS
    /// proxy must not answer.
    public var ExitNodeFilteredSet: [String]

    /// Creates a DNS configuration.
    ///
    /// - Parameters:
    ///   - Resolvers: The global resolvers.
    ///   - Routes: The split-DNS routes.
    ///   - Domains: The search domains.
    ///   - Proxied: Whether MagicDNS is on.
    ///   - Nameservers: The deprecated resolver list.
    ///   - CertDomains: The certificate domains.
    ///   - ExtraRecords: The extra records.
    ///   - FallbackResolvers: The fallback resolvers.
    ///   - ExitNodeFilteredSet: The suffixes an exit node must not answer.
    public init(Resolvers: [TailscaleDNSResolver] = [],
                Routes: [String: [TailscaleDNSResolver]] = [:],
                Domains: [String] = [],
                Proxied: Bool = false,
                Nameservers: [String] = [],
                CertDomains: [String] = [],
                ExtraRecords: [TailscaleDNSRecord] = [],
                FallbackResolvers: [TailscaleDNSResolver] = [],
                ExitNodeFilteredSet: [String] = []) {
        self.Resolvers = Resolvers
        self.Routes = Routes
        self.FallbackResolvers = FallbackResolvers
        self.Domains = Domains
        self.Proxied = Proxied
        self.Nameservers = Nameservers
        self.CertDomains = CertDomains
        self.ExtraRecords = ExtraRecords
        self.ExitNodeFilteredSet = ExitNodeFilteredSet
    }

    /// Decodes a DNS configuration, defaulting the fields Go omits.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a present field has the wrong type.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.Resolvers = try container.decodeIfPresent([TailscaleDNSResolver].self, forKey: .Resolvers) ?? []
        self.Routes = try container.decodeIfPresent([String: [TailscaleDNSResolver]].self, forKey: .Routes) ?? [:]
        self.FallbackResolvers = try container.decodeIfPresent([TailscaleDNSResolver].self, forKey: .FallbackResolvers) ?? []
        self.Domains = try container.decodeIfPresent([String].self, forKey: .Domains) ?? []
        self.Proxied = try container.decodeIfPresent(Bool.self, forKey: .Proxied) ?? false
        self.Nameservers = try container.decodeIfPresent([String].self, forKey: .Nameservers) ?? []
        self.CertDomains = try container.decodeIfPresent([String].self, forKey: .CertDomains) ?? []
        self.ExtraRecords = try container.decodeIfPresent([TailscaleDNSRecord].self, forKey: .ExtraRecords) ?? []
        self.ExitNodeFilteredSet = try container.decodeIfPresent([String].self, forKey: .ExitNodeFilteredSet) ?? []
    }

    /// The keys `tailcfg.DNSConfig` uses that this engine models.
    enum CodingKeys: String, CodingKey {
        case Resolvers, Routes, FallbackResolvers, Domains, Proxied, Nameservers
        case CertDomains, ExtraRecords, ExitNodeFilteredSet
    }

    /// The resolver addresses that can be handed to a tunnel interface.
    ///
    /// Only classic `IP` and `IP:port` resolvers are returned: a DoH URL is not
    /// something a system resolver library accepts, and DNS-over-HTTPS inside
    /// the tunnel needs an HTTP client this engine does not have. The order is
    /// the server's preference order.
    public var plainResolverAddresses: [String] {
        Resolvers.map(\.Addr).filter { TailscaleDNSConfig.isPlainResolver($0) }
    }

    /// Whether an address is a plain `IP` or `IP:port` resolver rather than a
    /// URL.
    ///
    /// - Parameter address: The resolver address text.
    /// - Returns: `true` for anything without a URL scheme.
    public static func isPlainResolver(_ address: String) -> Bool {
        !address.contains("://")
    }
}

// MARK: - DERP

/// A relay node (`tailcfg.DERPNode`).
///
/// Decoded for completeness even though this engine does not use DERP yet: a
/// client that ignored the map would have to re-learn it when it does.
public struct TailscaleDERPNode: Sendable, Equatable, Codable {

    /// `tailcfg.DERPNode.Name`: the node's unique name within the map
    /// (`"1b"`), which is not a hostname.
    public var Name: String

    /// `tailcfg.DERPNode.RegionID`.
    public var RegionID: Int

    /// `tailcfg.DERPNode.HostName`: the name to dial.
    public var HostName: String

    /// `tailcfg.DERPNode.CertName`: the expected TLS name, empty to use
    /// `HostName`. `"sha256-raw:<hex>"` means a pinned self-signed certificate.
    public var CertName: String

    /// `tailcfg.DERPNode.IPv4`: a forced IPv4 address, or `"none"`.
    public var IPv4: String

    /// `tailcfg.DERPNode.IPv6`: a forced IPv6 address, or `"none"`.
    public var IPv6: String

    /// `tailcfg.DERPNode.STUNPort`: the STUN port, zero for the default.
    public var STUNPort: Int

    /// `tailcfg.DERPNode.STUNOnly`: whether the node offers STUN but no relaying.
    public var STUNOnly: Bool

    /// `tailcfg.DERPNode.STUNTestIP`: a STUN address override for testing.
    public var STUNTestIP: String

    /// `tailcfg.DERPNode.DERPPort`: the relay port, zero for 443.
    public var DERPPort: Int

    /// `tailcfg.DERPNode.InsecureForTests`: whether to skip TLS verification.
    public var InsecureForTests: Bool

    /// `tailcfg.DERPNode.CanPort80`: whether the node also listens on port 80.
    public var CanPort80: Bool

    /// Decodes a node, defaulting the fields Go omits.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a present field has the wrong type.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.Name = try container.decodeIfPresent(String.self, forKey: .Name) ?? ""
        self.RegionID = try container.decodeIfPresent(Int.self, forKey: .RegionID) ?? 0
        self.HostName = try container.decodeIfPresent(String.self, forKey: .HostName) ?? ""
        self.CertName = try container.decodeIfPresent(String.self, forKey: .CertName) ?? ""
        self.IPv4 = try container.decodeIfPresent(String.self, forKey: .IPv4) ?? ""
        self.IPv6 = try container.decodeIfPresent(String.self, forKey: .IPv6) ?? ""
        self.STUNPort = try container.decodeIfPresent(Int.self, forKey: .STUNPort) ?? 0
        self.STUNOnly = try container.decodeIfPresent(Bool.self, forKey: .STUNOnly) ?? false
        self.STUNTestIP = try container.decodeIfPresent(String.self, forKey: .STUNTestIP) ?? ""
        self.DERPPort = try container.decodeIfPresent(Int.self, forKey: .DERPPort) ?? 0
        self.InsecureForTests = try container.decodeIfPresent(Bool.self, forKey: .InsecureForTests) ?? false
        self.CanPort80 = try container.decodeIfPresent(Bool.self, forKey: .CanPort80) ?? false
    }

    /// The keys `tailcfg.DERPNode` uses that this engine models.
    enum CodingKeys: String, CodingKey {
        case Name, RegionID, HostName, CertName, IPv4, IPv6, STUNPort, STUNOnly
        case STUNTestIP, DERPPort, InsecureForTests, CanPort80
    }
}

/// One relay region (`tailcfg.DERPRegion`).
public struct TailscaleDERPRegion: Sendable, Equatable, Codable {

    /// `tailcfg.DERPRegion.RegionID`: non-zero and small enough to fit in a
    /// JavaScript number. 900–999 are reserved for self-hosted regions.
    public var RegionID: Int

    /// `tailcfg.DERPRegion.RegionCode`: a short code such as `"nyc"`.
    public var RegionCode: String

    /// `tailcfg.DERPRegion.RegionName`: a long name such as
    /// `"New York City"`.
    public var RegionName: String

    /// `tailcfg.DERPRegion.Latitude`.
    public var Latitude: Double

    /// `tailcfg.DERPRegion.Longitude`.
    public var Longitude: Double

    /// `tailcfg.DERPRegion.Avoid`: whether to migrate away from this region.
    /// Deprecated in the protocol in favour of ``NoMeasureNoHome``.
    public var Avoid: Bool

    /// `tailcfg.DERPRegion.NoMeasureNoHome`: whether to skip latency
    /// measurement and home selection for this region.
    public var NoMeasureNoHome: Bool

    /// `tailcfg.DERPRegion.Nodes`: the relay nodes in this region.
    public var Nodes: [TailscaleDERPNode]

    /// Creates a region.
    ///
    /// - Parameters:
    ///   - RegionID: The region ID.
    ///   - RegionCode: The short code.
    ///   - RegionName: The long name.
    ///   - Nodes: The nodes in the region.
    public init(RegionID: Int,
                RegionCode: String = "",
                RegionName: String = "",
                Nodes: [TailscaleDERPNode] = []) {
        self.RegionID = RegionID
        self.RegionCode = RegionCode
        self.RegionName = RegionName
        self.Latitude = 0
        self.Longitude = 0
        self.Avoid = false
        self.NoMeasureNoHome = false
        self.Nodes = Nodes
    }

    /// Decodes a region, defaulting the fields Go omits.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a present field has the wrong type.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.RegionID = try container.decodeIfPresent(Int.self, forKey: .RegionID) ?? 0
        self.RegionCode = try container.decodeIfPresent(String.self, forKey: .RegionCode) ?? ""
        self.RegionName = try container.decodeIfPresent(String.self, forKey: .RegionName) ?? ""
        self.Latitude = try container.decodeIfPresent(Double.self, forKey: .Latitude) ?? 0
        self.Longitude = try container.decodeIfPresent(Double.self, forKey: .Longitude) ?? 0
        self.Avoid = try container.decodeIfPresent(Bool.self, forKey: .Avoid) ?? false
        self.NoMeasureNoHome = try container.decodeIfPresent(Bool.self, forKey: .NoMeasureNoHome) ?? false
        self.Nodes = try container.decodeIfPresent([TailscaleDERPNode].self, forKey: .Nodes) ?? []
    }

    /// The keys `tailcfg.DERPRegion` uses that this engine models.
    enum CodingKeys: String, CodingKey {
        case RegionID, RegionCode, RegionName, Latitude, Longitude, Avoid, NoMeasureNoHome, Nodes
    }
}

/// The relay map (`tailcfg.DERPMap`).
///
/// Decoded and kept so that a later DERP implementation has the data it needs,
/// and so that a caller can show the user which regions exist.
public struct TailscaleDERPMap: Sendable, Equatable, Codable {

    /// `tailcfg.DERPMap.Regions`: the regions, keyed by region ID.
    ///
    /// Go encodes a `map[DERPRegionID]*DERPRegion` with the IDs as decimal
    /// strings, so the JSON keys here are strings too.
    public var Regions: [Int: TailscaleDERPRegion]

    /// `tailcfg.DERPMap.OmitDefaultRegions`: whether to ignore Tailscale's
    /// built-in regions and use only the ones listed here.
    public var OmitDefaultRegions: Bool

    /// Creates a relay map.
    ///
    /// - Parameters:
    ///   - Regions: The regions.
    ///   - OmitDefaultRegions: Whether the built-in regions are suppressed.
    public init(Regions: [Int: TailscaleDERPRegion] = [:], OmitDefaultRegions: Bool = false) {
        self.Regions = Regions
        self.OmitDefaultRegions = OmitDefaultRegions
    }

    /// Decodes a relay map, converting Go's string keys back to integers.
    ///
    /// Go types this as `map[DERPRegionID]*DERPRegion`, so a region may also be
    /// `null`, which means "forget this region". That case is skipped rather
    /// than modelled: nothing in this engine reads regions yet, and dropping a
    /// region it does not use cannot affect a connection.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a key is not an integer or a region is
    ///   malformed.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.OmitDefaultRegions = try container.decodeIfPresent(Bool.self, forKey: .omitDefaultRegions) ?? false
        self.Regions = [:]
        if let raw = try container.decodeIfPresent([String: TailscaleDERPRegion?].self, forKey: .Regions) {
            for (key, region) in raw {
                guard let region else { continue }
                guard let id = Int(key) else {
                    throw DecodingError.dataCorruptedError(forKey: .Regions,
                                                           in: container,
                                                           debugDescription: "\"\(key)\" is not a DERP region ID")
                }
                self.Regions[id] = region
            }
        }
    }

    /// Writes the region IDs as decimal string keys.
    ///
    /// - Parameter encoder: The encoder to write to.
    /// - Throws: A coding error when the map cannot be encoded.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(OmitDefaultRegions, forKey: .omitDefaultRegions)
        var raw: [String: TailscaleDERPRegion] = [:]
        for (id, region) in Regions {
            raw[String(id)] = region
        }
        try container.encode(raw, forKey: .Regions)
    }

    /// The keys `tailcfg.DERPMap` uses that this engine models.
    enum CodingKeys: String, CodingKey {
        case Regions
        case omitDefaultRegions
    }

    /// The region with a given ID, when present.
    ///
    /// - Parameter id: The region ID.
    /// - Returns: The region, or `nil`.
    public func region(id: Int) -> TailscaleDERPRegion? { Regions[id] }
}

// MARK: - The envelope

/// A control-protocol message, in either direction.
///
/// See the file header for what the wire actually looks like and why this type
/// writes the bare form and reads two. In short:
///
///   * encoding produces exactly what `tailscaled` produces — the bare message
///     (`json.Marshal(request)` of a `RegisterRequest` or `MapRequest`);
///   * decoding accepts that, and also the one-key `{"MapResponse": {…}}`
///     envelope form, which the protocol never sent but which costs nothing to
///     tolerate.
public enum TailscaleControlMessage: Sendable, Equatable {

    /// A `POST /machine/register` body.
    case registerRequest(TailscaleRegisterRequest)

    /// A `POST /machine/register` response.
    case registerResponse(TailscaleRegisterResponse)

    /// A `POST /machine/map` body.
    case mapRequest(TailscaleMapRequest)

    /// One frame of the `POST /machine/map` response stream.
    case mapResponse(TailscaleMapResponse)

    /// The name of the message, as Go's `encoding/json` would use if a
    /// well-meaning server wrapped it in an envelope.
    public var kind: String {
        switch self {
        case .registerRequest: return "RegisterRequest"
        case .registerResponse: return "RegisterResponse"
        case .mapRequest: return "MapRequest"
        case .mapResponse: return "MapResponse"
        }
    }

    /// The message kinds that can appear in the envelope form, in probe order.
    static let envelopeKeys = ["RegisterRequest", "RegisterResponse", "MapRequest", "MapResponse"]

    /// Encodes the message.
    ///
    /// - Throws: When the message cannot be encoded as JSON.
    /// - Returns: The bytes to hand to ``TailscaleControlTransport``.
    public func encoded() throws -> Data {
        let encoder = TailcfgCoding.encoder()
        switch self {
        case let .registerRequest(request): return try encoder.encode(request)
        case let .registerResponse(response): return try encoder.encode(response)
        case let .mapRequest(request): return try encoder.encode(request)
        case let .mapResponse(response): return try encoder.encode(response)
        }
    }

    /// Decodes a record, accepting a bare message or a one-key envelope.
    ///
    /// The four message types are tried in turn, and the first that parses
    /// wins. That is unambiguous in practice: the types share almost no
    /// required fields, so a `MapResponse` cannot parse as a `RegisterRequest`.
    ///
    /// - Parameter record: One record from the transport.
    /// - Throws: ``TailscaleControlError/malformedRecord(_:)`` when no message
    ///   type matches.
    /// - Returns: The decoded message.
    public init(decoding record: Data) throws {
        let inner = try TailscaleControlMessage.unwrapEnvelope(record)
        let decoder = TailcfgCoding.decoder()
        for key in TailscaleControlMessage.envelopeKeys {
            switch key {
            case "RegisterResponse":
                if let value = try? decoder.decode(TailscaleRegisterResponse.self, from: inner) {
                    self = .registerResponse(value)
                    return
                }
            case "MapResponse":
                if let value = try? decoder.decode(TailscaleMapResponse.self, from: inner) {
                    self = .mapResponse(value)
                    return
                }
            case "RegisterRequest":
                if let value = try? decoder.decode(TailscaleRegisterRequest.self, from: inner) {
                    self = .registerRequest(value)
                    return
                }
            case "MapRequest":
                if let value = try? decoder.decode(TailscaleMapRequest.self, from: inner) {
                    self = .mapRequest(value)
                    return
                }
            default:
                continue
            }
        }
        throw TailscaleControlError.malformedRecord(String(decoding: record.prefix(200), as: UTF8.self))
    }

    /// Strips a one-key envelope, when one is present.
    ///
    /// - Parameter record: The record as it arrived.
    /// - Throws: When the record is not JSON at all.
    /// - Returns: The bytes of the message itself.
    static func unwrapEnvelope(_ record: Data) throws -> Data {
        guard let object = try? JSONSerialization.jsonObject(with: record),
              let dictionary = object as? [String: Any] else {
            // Not a JSON object: hand it back and let the message decoders
            // produce the error, which will be more specific.
            return record
        }
        for key in TailscaleControlMessage.envelopeKeys where dictionary[key] != nil {
            guard let inner = dictionary[key],
                  let data = try? JSONSerialization.data(withJSONObject: inner) else {
                throw TailscaleControlError.malformedEnvelope(key)
            }
            return data
        }
        return record
    }
}

// MARK: - Coding

/// JSON coding tuned to match Go's `encoding/json` (`TailcfgCoding`).
///
/// The one real difference between Go and Foundation here is time. Go's
/// `time.Time` marshals as RFC 3339 **with up to nine fractional digits**
/// (`time.RFC3339Nano`, which trims trailing zeros), and it can print the zero
/// time as `"0001-01-01T00:00:00Z"`. Foundation's
/// `JSONDecoder.DateDecodingStrategy.iso8601` uses an `ISO8601DateFormatter`
/// with `.withInternetDateTime` only, so it *rejects* every timestamp that has
/// a fractional part — which is every timestamp `tailscaled` sends. A decoder
/// with the default settings therefore fails on the first `MapResponse`, which
/// is exactly the bug this type exists to prevent.
///
/// Neither a nine-digit fraction nor year 1 survives `DateFormatter`, so
/// ``goTime(_:)`` parses the seconds with a formatter and adds the fraction
/// itself. Truncating to three digits and hoping would also have "worked", but
/// silently losing precision the server chose to send is the kind of thing that
/// turns into a heisenbug later.
public enum TailcfgCoding {

    /// Go's zero `time.Time`: `January 1, year 1, 00:00:00 UTC`.
    ///
    /// `tailcfg` uses it as "unset" for the fields that carry no `omitempty` —
    /// notably `RegisterRequest.Expiry`, which is always on the wire.
    public static let goZeroTime = Date(timeIntervalSince1970: -62_135_596_800)

    /// The literal Go prints for the zero time.
    public static let goZeroTimeText = "0001-01-01T00:00:00Z"

    /// A decoder that reads Go's JSON.
    ///
    /// - Returns: A decoder with Go-compatible date handling.
    public static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let text = try container.decode(String.self)
            guard let date = goTime(text) else {
                throw DecodingError.dataCorruptedError(in: container,
                                                       debugDescription: "\"\(text)\" is not an RFC 3339 timestamp")
            }
            return date
        }
        return decoder
    }

    /// An encoder that writes Go's JSON.
    ///
    /// - Returns: An encoder that writes RFC 3339 timestamps with milliseconds.
    public static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .custom { date, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(encodeGoTime(date))
        }
        return encoder
    }

    /// Parses an RFC 3339 timestamp the way Go writes it.
    ///
    /// Accepts a fraction of any length from one to nine digits, with or
    /// without a timezone offset, and the zero-time literal.
    ///
    /// - Parameter text: The timestamp text.
    /// - Returns: The date, or `nil` when the text is not a timestamp.
    public static func goTime(_ text: String) -> Date? {
        if text == goZeroTimeText { return goZeroTime }

        var secondsText = text
        var fraction = 0.0
        if let dot = text.firstIndex(of: ".") {
            let afterDot = text.index(after: dot)
            var end = afterDot
            while end < text.endIndex, text[end].isASCII, text[end].isNumber {
                end = text.index(after: end)
            }
            let digits = text[afterDot ..< end]
            guard !digits.isEmpty, digits.count <= 9, let value = Double(digits) else { return nil }
            fraction = value / pow(10, Double(digits.count))
            secondsText = String(text[text.startIndex ..< dot]) + String(text[end...])
        }

        guard let base = plainRFC3339(secondsText) else { return nil }
        return base.addingTimeInterval(fraction)
    }

    /// Formats a date the way Go's `time.Time.MarshalJSON` does.
    ///
    /// - Parameter date: The date to format.
    /// - Returns: An RFC 3339 timestamp with millisecond precision and a `Z`
    ///   offset.
    public static func encodeGoTime(_ date: Date) -> String {
        if date == goZeroTime { return goZeroTimeText }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter.string(from: date)
    }

    /// Parses an RFC 3339 timestamp with no fractional part.
    ///
    /// - Parameter text: The timestamp text, for example
    ///   `"2026-07-01T12:00:00+02:00"`.
    /// - Returns: The date, or `nil`.
    static func plainRFC3339(_ text: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: text)
    }
}
