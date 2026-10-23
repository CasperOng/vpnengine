import Foundation

/// The parsed contents of a `PUSH_REPLY` control channel message.
///
/// A server answers the client's `PUSH_REQUEST` with
///
/// ```
/// PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,route-gateway 10.8.0.1,
/// topology subnet,redirect-gateway def1,dhcp-option DNS 10.0.0.1,
/// cipher AES-256-GCM,peer-id 3
/// ```
///
/// (`process_incoming_push_msg()` / `process_incoming_push_reply()` in
/// `src/openvpn/push.c`). The message travels inside the TLS session, is NUL
/// terminated, and its options are comma separated with `"` quoting for values
/// that contain spaces or commas.
///
/// Parsing never throws: unrecognised options are kept in ``unknown`` and
/// malformed ones are described in ``parseWarnings``, because a client should
/// use everything it *does* understand from a server it does not fully agree
/// with.
public struct OVPNPushReply: Sendable, Equatable {

    /// An `ifconfig`/`ifconfig-ipv6` assignment.
    public struct Ifconfig: Sendable, Equatable {
        /// Local tunnel address.
        public var localAddress: String
        /// Second argument: a netmask under `topology subnet`, otherwise the
        /// peer's address (`topology net30`).
        public var secondArgument: String
        /// `true` when ``secondArgument`` is a dotted-quad netmask.
        public var secondArgumentIsNetmask: Bool
        /// Prefix length derived from ``secondArgument`` when it is a netmask.
        public var prefixLength: Int?

        /// Create an ifconfig value.
        public init(localAddress: String, secondArgument: String) {
            self.localAddress = localAddress
            self.secondArgument = secondArgument
            let isNetmask = OVPNRoute.prefixLength(dottedQuad: secondArgument) != nil
            self.secondArgumentIsNetmask = isNetmask
            self.prefixLength = isNetmask ? OVPNRoute.prefixLength(dottedQuad: secondArgument) : nil
        }
    }

    /// IPv4 `ifconfig` assignment.
    public var ifconfig: Ifconfig?
    /// IPv6 `ifconfig-ipv6` assignment.
    public var ifconfigIPv6: Ifconfig?
    /// `route` options pushed by the server.
    public var routes: [OVPNRoute] = []
    /// `dhcp-option DNS` values.
    public var dnsServers: [String] = []
    /// `dhcp-option DOMAIN` / `DOMAIN-SEARCH` values.
    public var dnsSearchDomains: [String] = []
    /// `route-gateway` value.
    public var routeGateway: String?
    /// `true` when the server asked for `redirect-gateway`.
    public var redirectGateway: Bool = false
    /// Flags following `redirect-gateway` (`def1`, `bypass-dhcp`, ...).
    public var redirectGatewayFlags: [String] = []
    /// `block-outside-dns` was pushed.
    public var blockOutsideDNS: Bool = false
    /// Data channel cipher the server selected.
    public var cipher: String?
    /// `data-ciphers` list the server selected from.
    public var dataCiphers: [String] = []
    /// `--peer-id` (used by `P_DATA_V2`).
    public var peerID: UInt32?
    /// `topology` value.
    public var topology: String?
    /// `ping` interval in seconds.
    public var pingInterval: Int?
    /// `ping-restart` timeout in seconds.
    public var pingRestart: Int?
    /// `mssfix` value.
    public var mssFix: Int?
    /// `tun-mtu` value.
    public var mtu: Int?
    /// `compress` algorithm (`stub-v2`, ...).
    public var compression: String?
    /// `key-derivation` value (`tls-ekm` on OpenVPN 2.6 servers).
    public var keyDerivation: String?
    /// `auth-token` issued by the server for reconnects.
    public var authToken: String?
    /// `explicit-exit-notify` argument.
    public var explicitExitNotify: Int?
    /// Options that were not recognised, keyed by name.
    public var unknown: [String: [String]] = [:]
    /// The options as received, in order, after pull filters were applied.
    public var rawOptions: [String] = []
    /// Options dropped by a `--pull-filter ignore`, in order.
    public var ignoredOptions: [String] = []
    /// Options that matched a `--pull-filter reject`.
    public var rejectedOptions: [String] = []
    /// Problems found while parsing.
    public var parseWarnings: [String] = []

    /// Create an empty reply.
    public init() {}

    /// `true` when the reply tells the client to route everything through the
    /// tunnel.
    public var routesEverything: Bool { redirectGateway }

    /// Parse a `PUSH_REPLY` (or `PUSH_UPDATE`) message.
    ///
    /// - Parameters:
    ///   - text: the message body, with or without the leading `PUSH_REPLY,`
    ///     and with or without the trailing NUL that OpenVPN appends.
    ///   - filters: `--pull-filter` entries to apply.
    /// - Returns: the parsed reply. Never throws.
    public static func parse(_ text: String, filters: [OVPNPullFilter] = []) -> OVPNPushReply {
        var reply = OVPNPushReply()

        var body = text.replacingOccurrences(of: "\0", with: "")
        body = body.trimmingCharacters(in: .whitespacesAndNewlines)
        if body.hasPrefix("PUSH_REPLY") {
            body = String(body.dropFirst("PUSH_REPLY".count))
            if body.hasPrefix(",") { body = String(body.dropFirst()) }
        } else if body.hasPrefix("PUSH_UPDATE") {
            body = String(body.dropFirst("PUSH_UPDATE".count))
            if body.hasPrefix(",") { body = String(body.dropFirst()) }
        }

        for option in splitOptions(body) {
            let tokens = OVPNLexer.tokenize(option).tokens
            guard let name = tokens.first?.lowercased() else { continue }
            let arguments = Array(tokens.dropFirst())

            // Pull filters can drop or reject an option before we look at it.
            if let filter = filters.first(where: { $0.matches(option: name, value: arguments.first) }) {
                switch filter.action {
                case .accept:
                    break
                case .ignore:
                    reply.ignoredOptions.append(option)
                    continue
                case .reject:
                    reply.rejectedOptions.append(option)
                    continue
                }
            }
            reply.rawOptions.append(option)

            func integer(_ index: Int) -> Int? {
                guard arguments.count > index else { return nil }
                return Int(arguments[index])
            }

            switch name {
            case "ifconfig":
                guard arguments.count >= 2 else {
                    reply.parseWarnings.append("ifconfig needs two arguments: '\(option)'")
                    break
                }
                reply.ifconfig = Ifconfig(localAddress: arguments[0], secondArgument: arguments[1])
            case "ifconfig-ipv6":
                guard arguments.count >= 2 else {
                    reply.parseWarnings.append("ifconfig-ipv6 needs two arguments: '\(option)'")
                    break
                }
                reply.ifconfigIPv6 = Ifconfig(localAddress: arguments[0], secondArgument: arguments[1])
            case "route":
                if let route = OVPNConfiguration.parseRoute(arguments, isIPv6: false, warning: { reply.parseWarnings.append($0) }) {
                    reply.routes.append(route)
                }
            case "route-ipv6":
                if let route = OVPNConfiguration.parseRoute(arguments, isIPv6: true, warning: { reply.parseWarnings.append($0) }) {
                    reply.routes.append(route)
                }
            case "route-gateway":
                reply.routeGateway = arguments.first
            case "redirect-gateway":
                reply.redirectGateway = true
                reply.redirectGatewayFlags.append(contentsOf: arguments)
            case "redirect-private":
                reply.redirectGatewayFlags.append(contentsOf: arguments)
            case "block-outside-dns":
                reply.blockOutsideDNS = true
            case "dhcp-option":
                guard let kind = arguments.first?.uppercased() else { break }
                let value = arguments.count > 1 ? arguments[1] : nil
                switch kind {
                case "DNS":
                    if let value { reply.dnsServers.append(value) }
                case "DOMAIN", "DOMAIN-SEARCH":
                    if let value { reply.dnsSearchDomains.append(value) }
                case "DNS6":
                    if let value { reply.dnsServers.append(value) }
                default:
                    reply.unknown[name, default: []].append(OVPNLexer.joined(arguments))
                }
            case "cipher":
                reply.cipher = arguments.first
            case "data-ciphers":
                guard let value = arguments.first else { break }
                reply.dataCiphers = value.split(separator: ":").map(String.init)
            case "peer-id":
                if let value = integer(0), value >= 0 { reply.peerID = UInt32(value) }
            case "topology":
                reply.topology = arguments.first
            case "ping":
                reply.pingInterval = integer(0)
            case "ping-restart":
                reply.pingRestart = integer(0)
            case "mssfix":
                reply.mssFix = integer(0) ?? 0
            case "tun-mtu", "mtu":
                reply.mtu = integer(0)
            case "compress":
                reply.compression = arguments.first?.lowercased() ?? "stub"
            case "key-derivation":
                reply.keyDerivation = arguments.first
            case "auth-token":
                reply.authToken = OVPNLexer.joined(arguments)
            case "explicit-exit-notify":
                reply.explicitExitNotify = integer(0) ?? 1
            case "ping-exit", "inactive", "sndbuf", "rcvbuf", "socket-flags", "block-ipv6",
                 "route-metric", "route-method", "ifconfig-noexec", "route-noexec",
                 "persist-tun", "persist-key", "max-routes-per-client", "setenv":
                reply.unknown[name, default: []].append(OVPNLexer.joined(arguments))
            default:
                reply.unknown[name, default: []].append(OVPNLexer.joined(arguments))
            }
        }

        return reply
    }

    /// Split an option string on commas that are not inside double quotes.
    static func splitOptions(_ body: String) -> [String] {
        var options: [String] = []
        var current = ""
        var inQuotes = false
        for character in body {
            if character == "\"" {
                inQuotes.toggle()
                current.append(character)
                continue
            }
            if character == ",", !inQuotes {
                options.append(current.trimmingCharacters(in: .whitespaces))
                current = ""
                continue
            }
            current.append(character)
        }
        options.append(current.trimmingCharacters(in: .whitespaces))
        return options.filter { !$0.isEmpty }
    }

    /// The `PUSH_REQUEST` control channel string, including the NUL that
    /// OpenVPN's `send_control_channel_string()` appends.
    public static var pushRequestPayload: Data {
        Data("PUSH_REQUEST\0".utf8)
    }
}
