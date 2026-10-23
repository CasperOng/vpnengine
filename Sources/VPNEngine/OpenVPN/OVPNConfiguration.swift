import Foundation

// MARK: - Lexer

/// A single parsed `.ovpn` directive (or inline `<name>...</name>` block).
struct OVPNToken {
    enum Kind {
        /// `key value value...` or a bare flag.
        case directive
        /// `<ca>...</ca>` — `arguments` holds the verbatim body as one element.
        case inline
    }

    let kind: Kind
    let name: String
    let arguments: [String]
    let line: Int
}

/// Line-oriented lexer for `openvpn` configuration files.
///
/// Implements the rules `options.c` applies to a config file:
///
/// * `#` and `;` start a comment that runs to the end of the line, unless it
///   appears inside a double quoted string (which makes trailing comments
///   after a quoted value work).
/// * values may be quoted with `"`; `\"` and `\\` escape inside quotes.
/// * a trailing `\` continues the logical line.
/// * `<name> ... </name>` blocks are taken verbatim, byte for byte, and never
///   have comments stripped (this is how certificates and keys are embedded).
enum OVPNLexer {

    /// Split text into directives, reporting non-fatal problems.
    static func tokens(_ text: String) -> (tokens: [OVPNToken], warnings: [String]) {
        var tokens: [OVPNToken] = []
        var warnings: [String] = []
        let lines = splitLines(text)
        var index = 0

        while index < lines.count {
            let (lineNumber, rawLine) = lines[index]
            index += 1

            var line = rawLine
            // Line continuation: a trailing backslash joins the next line.
            while line.hasSuffix("\\"), index < lines.count {
                line.removeLast()
                line += " " + lines[index].1
                index += 1
            }

            let lexed = tokenize(line)
            if let warning = lexed.warning {
                warnings.append("line \(lineNumber): \(warning)")
            }
            guard let first = lexed.tokens.first else { continue }

            // Inline block start: <name> ... </name>
            if first.hasPrefix("<"), first.hasSuffix(">"), !first.hasPrefix("</") {
                let name = String(first.dropFirst().dropLast())
                if name.isEmpty {
                    warnings.append("line \(lineNumber): empty inline directive tag")
                    continue
                }
                var body: [String] = []
                var closed = false
                // A block can open and close on one line.
                if let sameLine = closeRemainder(of: line, name: name) {
                    body.append(sameLine)
                    closed = true
                }
                while !closed, index < lines.count {
                    let candidate = lines[index].1
                    index += 1
                    if candidate.trimmingCharacters(in: .whitespaces) == "</\(name)>" { closed = true; continue }
                    if candidate.contains("</\(name)>") {
                        // Closing tag glued to the last body line.
                        let head = candidate.replacingOccurrences(of: "</\(name)>", with: "")
                        body.append(head)
                        closed = true
                        continue
                    }
                    body.append(candidate)
                }
                if !closed {
                    warnings.append("line \(lineNumber): unterminated <\(name)> block")
                }
                tokens.append(OVPNToken(kind: .inline, name: name, arguments: [body.joined(separator: "\n")], line: lineNumber))
                continue
            }

            tokens.append(OVPNToken(kind: .directive, name: first, arguments: Array(lexed.tokens.dropFirst()), line: lineNumber))
        }

        return (tokens, warnings)
    }

    /// Re-assemble tokens into a single value, re-quoting anything that
    /// contains whitespace or a quote so the result can be tokenised again
    /// (this is what `push`, `pull-filter` and the `extra` bag store).
    static func joined(_ tokens: [String]) -> String {
        tokens.map { token in
            if token.contains(" ") || token.contains("\t") || token.contains("\"") {
                let escaped = token.replacingOccurrences(of: "\"", with: "\\\"")
                return "\"\(escaped)\""
            }
            return token
        }
        .joined(separator: " ")
    }

    /// If `line` is `<name>...body...</name>` in a single line, return the body.
    private static func closeRemainder(of line: String, name: String) -> String? {
        guard let open = line.firstIndex(of: ">") else { return nil }
        let afterOpen = line.index(after: open)
        guard let closeRange = line.range(of: "</\(name)>", range: afterOpen..<line.endIndex) else { return nil }
        let body = line[afterOpen..<closeRange.lowerBound]
        return body.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Normalise line endings and number the lines.
    private static func splitLines(_ text: String) -> [(Int, String)] {
        var out: [(Int, String)] = []
        var number = 0
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            number += 1
            var line = String(rawLine)
            if line.hasSuffix("\r") { line.removeLast() }
            out.append((number, line))
        }
        return out
    }

    /// Strip comments and split on whitespace, honouring double quotes.
    static func tokenize(_ raw: String) -> (tokens: [String], warning: String?) {
        var tokens: [String] = []
        var current = ""
        var inQuotes = false
        var warning: String?
        var index = raw.startIndex

        func flush() {
            if !current.isEmpty {
                tokens.append(current)
                current = ""
            }
        }

        while index < raw.endIndex {
            let character = raw[index]
            if inQuotes {
                if character == "\\" {
                    let next = raw.index(after: index)
                    if next < raw.endIndex, raw[next] == "\"" || raw[next] == "\\" {
                        current.append(raw[next])
                        index = raw.index(after: next)
                        continue
                    }
                } else if character == "\"" {
                    inQuotes = false
                    index = raw.index(after: index)
                    continue
                }
                current.append(character)
                index = raw.index(after: index)
                continue
            }

            switch character {
            case "\"":
                inQuotes = true
            case "#", ";":
                // Comment: the rest of the line is dropped.
                flush()
                index = raw.endIndex
                continue
            case " ", "\t":
                flush()
            default:
                current.append(character)
            }
            index = raw.index(after: index)
        }

        flush()
        if inQuotes { warning = "unterminated double quote" }
        return (tokens, warning)
    }
}

// MARK: - Model

/// Transport protocol of a `remote` entry or the global `proto` directive.
public enum OVPNProto: String, Sendable, Codable, CaseIterable {
    /// UDP (the default).
    case udp
    /// TCP, client role (`tcp`, `tcp-client`).
    case tcpClient
    /// TCP, server role (`tcp-server`).
    case tcpServer

    /// The token OpenVPN uses in a config file.
    public var token: String {
        switch self {
        case .udp: return "udp"
        case .tcpClient: return "tcp-client"
        case .tcpServer: return "tcp-server"
        }
    }

    /// Parse `udp`, `tcp`, `tcp-client`, `tcp-server`, `udp4`, `udp6`,
    /// `tcp4`, `tcp6-client`, ... (the address-family suffix is ignored).
    public static func parse(_ token: String) -> OVPNProto? {
        let lowered = token.lowercased()
        if lowered.hasPrefix("udp") { return .udp }
        if lowered.hasPrefix("tcp") {
            return lowered.contains("server") ? .tcpServer : .tcpClient
        }
        return nil
    }
}

/// Whether the tunnel device carries IP packets (`tun`) or Ethernet frames
/// (`tap`).
public enum OVPNDeviceType: String, Sendable, Codable {
    /// Layer 3: IP packets.
    case tun
    /// Layer 2: Ethernet frames.
    case tap
}

/// A `remote host [port] [proto]` entry.
public struct OVPNRemote: Sendable, Equatable {
    /// Host name or literal address.
    public var host: String
    /// Destination port (defaults to the global `port`, 1194).
    public var port: UInt16
    /// Per-remote protocol override; `nil` means "use the global `proto`".
    public var proto: OVPNProto?
    /// `true` when this entry belongs to the `--remote-random` pool, i.e. the
    /// session is free to pick it at random.
    public var isRandom: Bool

    /// Create a remote entry.
    public init(host: String, port: UInt16 = 1194, proto: OVPNProto? = nil, isRandom: Bool = false) {
        self.host = host
        self.port = port
        self.proto = proto
        self.isRandom = isRandom
    }
}

/// One `route` / `route-ipv6` directive.
public struct OVPNRoute: Sendable, Equatable {
    /// Network address (`10.0.0.0`) or an IPv6 prefix (`2001:db8::/32`).
    public var network: String
    /// Dotted-quad netmask, if the directive used the two-argument form.
    public var netmask: String?
    /// `vpn_gateway`, `net_gateway`, `remote_host`, `default` or a literal IP.
    public var gateway: String?
    /// Route metric, if given.
    public var metric: Int?
    /// `true` for `route-ipv6` / IPv6 literals.
    public var isIPv6: Bool

    /// Create a route entry.
    public init(network: String, netmask: String? = nil, gateway: String? = nil, metric: Int? = nil, isIPv6: Bool = false) {
        self.network = network
        self.netmask = netmask
        self.gateway = gateway
        self.metric = metric
        self.isIPv6 = isIPv6
    }

    /// `10.0.0.0/8` style text when a prefix length can be derived.
    public var cidrNotation: String? {
        if isIPv6 || network.contains("/") { return network }
        guard let mask = netmask, let prefix = Self.prefixLength(dottedQuad: mask) else { return nil }
        return "\(network)/\(prefix)"
    }

    /// `255.255.255.0` -> `24`.
    static func prefixLength(dottedQuad: String) -> Int? {
        let parts = dottedQuad.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var value: UInt32 = 0
        for part in parts {
            guard let octet = UInt8(part) else { return nil }
            value = value << 8 | UInt32(octet)
        }
        // A netmask must be a run of ones followed by a run of zeros.
        var count = 0
        var seenZero = false
        for bit in stride(from: 31, through: 0, by: -1) {
            let set = (value >> UInt32(bit)) & 1 == 1
            if set {
                if seenZero { return nil }
                count += 1
            } else {
                seenZero = true
            }
        }
        return count
    }
}

/// `--auth-user-pass` material.
public struct OVPNCredentials: Sendable, Equatable {
    /// User name, when the credentials were embedded in the config.
    public var username: String?
    /// Password, when the credentials were embedded in the config.
    public var password: String?
    /// File the credentials should be read from, when not embedded.
    public var path: String?

    /// Create a credentials value.
    public init(username: String? = nil, password: String? = nil, path: String? = nil) {
        self.username = username
        self.password = password
        self.path = path
    }
}

/// A key reference used by `--tls-auth` and `--tls-crypt`: either an inline
/// `<tls-auth>` body or a path on disk, plus an optional key direction.
public struct OVPNTLSKey: Sendable, Equatable {
    /// Key direction 0/1 (`nil` for bidirectional).
    public var direction: Int?
    /// Verbatim inline block body, when the config embedded the key.
    public var inline: String?
    /// Path argument, when the config referenced a file.
    public var path: String?

    /// Create a key reference.
    public init(direction: Int? = nil, inline: String? = nil, path: String? = nil) {
        self.direction = direction
        self.inline = inline
        self.path = path
    }

    /// The static key, when the key was embedded in the config.
    public var staticKey: OVPNStaticKey? {
        inline.flatMap(OVPNStaticKey.parse)
    }
}

/// A `pull-filter <accept|ignore|reject> <option> [value]` directive.
///
/// Pull filters are applied to the option string the server returns in
/// `PUSH_REPLY`; `OVPNPushReply.parse` takes them as an argument.
public struct OVPNPullFilter: Sendable, Equatable {
    /// What to do with a matching option.
    public enum Action: String, Sendable {
        /// Keep the option.
        case accept
        /// Drop the option.
        case ignore
        /// Drop the option and abort the connection.
        case reject
    }

    /// The action to take.
    public var action: Action
    /// Option name the filter applies to (`redirect-gateway`).
    public var option: String
    /// Optional value the filter must also match.
    public var value: String?

    /// Create a filter.
    public init(action: Action, option: String, value: String? = nil) {
        self.action = action
        self.option = option
        self.value = value
    }

    /// Parse `ignore redirect-gateway` / `accept "route" 10.0.0.0`.
    public init?(string: String) {
        let tokens = OVPNLexer.tokenize(string).tokens
        guard tokens.count >= 2, let action = Action(rawValue: tokens[0].lowercased()) else { return nil }
        self.action = action
        self.option = tokens[1].lowercased()
        self.value = tokens.count > 2 ? tokens[2...].joined(separator: " ") : nil
    }

    /// `true` when this filter applies to `option`/`value`.
    func matches(option: String, value: String?) -> Bool {
        guard option.lowercased() == self.option else { return false }
        guard let filterValue = self.value else { return true }
        guard let value else { return false }
        let trimmed = filterValue.trimmingCharacters(in: CharacterSet(charactersIn: "\""))
        return value.hasPrefix(trimmed)
    }
}

// MARK: - Configuration

/// A fully parsed OpenVPN configuration file.
///
/// The parser is deliberately permissive: anything it does not implement is
/// preserved in ``extra`` and anything it recognises but cannot honour is
/// reported in ``parseWarnings``, so a real-world `.ovpn` file handed to the
/// engine always produces a usable model plus an explanation of what was
/// dropped. Parsing never touches the filesystem; use
/// ``loadStaticKeyFile()`` and friends for that.
public struct OVPNConfiguration: Sendable, Equatable {

    // MARK: Connection

    /// Every `remote` directive, in file order. When several are present and
    /// ``remoteRandom`` is set, the session picks one at random.
    public var remotes: [OVPNRemote] = []

    /// Global `proto` directive (default `udp`).
    public var proto: OVPNProto = .udp

    /// `dev` value exactly as written (`tun`, `tap`, `utun5`, ...).
    public var dev: String = "tun"

    /// Layer 2 or layer 3.
    public var devType: OVPNDeviceType = .tun

    /// Default port used by `remote` entries that omit one.
    public var port: UInt16 = 1194

    /// `nobind` — do not bind a fixed local port.
    public var nobind: Bool = false

    /// `lport` — local port to bind.
    public var localPort: Int?

    // MARK: Certificates and keys

    /// Inline `<ca>` PEM body (only set when the CA was embedded).
    public var ca: String?
    /// Inline `<cert>` PEM body (only set when the certificate was embedded).
    public var cert: String?
    /// Inline `<key>` PEM body (only set when the private key was embedded).
    public var key: String?
    /// `ca` file path, when the CA was referenced rather than embedded.
    public var caPath: String?
    /// `cert` file path, when referenced rather than embedded.
    public var certPath: String?
    /// `key` file path, when referenced rather than embedded.
    public var keyPath: String?
    /// `tls-auth` key (control channel HMAC).
    public var tlsAuth: OVPNTLSKey?
    /// `tls-crypt` key (control channel AEAD wrapping).
    public var tlsCrypt: OVPNTLSKey?
    /// `tls-crypt-v2` client key: verbatim inline blob or a path.
    public var tlsCryptV2: String?
    /// `key-direction` applying to whichever key directive is present.
    public var keyDirection: Int?
    /// `--secret` in static key mode: the embedded key material.
    public var staticKey: OVPNStaticKeyFile?
    /// `--secret` in static key mode: the file path, when referenced.
    public var staticKeyPath: String?
    /// `true` for `--secret` (no TLS control channel at all).
    public var isStaticKeyMode: Bool = false

    // MARK: Crypto

    /// `cipher` — the data channel cipher.
    public var cipher: String?
    /// `data-ciphers` — the negotiation list (OpenVPN 2.5+).
    public var dataCiphers: [String] = []
    /// `data-ciphers-fallback`.
    public var dataCiphersFallback: String?
    /// `auth` — the HMAC digest for non-AEAD data channel ciphers.
    public var auth: String?
    /// `tls-version-min` value, if given.
    public var tlsVersionMin: String?
    /// `tls-cipher` value, if given.
    public var tlsCipher: String?
    /// `replay-window` size (default 64 when unset).
    public var replayWindow: Int?
    /// `no-replay` — disable replay protection.
    public var replayDisabled: Bool = false

    // MARK: Compression

    /// `comp-lzo` argument (`yes`, `no`, `adaptive`).
    public var compLZO: String?
    /// `compress` / `comp-lzo` algorithm (`stub`, `stub-v2`, `lz4`, ...).
    public var compAlgorithm: String?

    // MARK: Authentication

    /// `auth-user-pass` present (with or without a file).
    public var authUserPass: Bool = false
    /// Credentials, when embedded in an `<auth-user-pass>` block or referenced
    /// by path.
    public var credentials: OVPNCredentials?
    /// `tls-client` / implied by `client`.
    public var tlsClient: Bool = false
    /// `pull` / implied by `client`.
    public var pull: Bool = false
    /// `verify-x509-name` name.
    public var verifyX509Name: String?
    /// `verify-x509-name` match type (`subject`, `name`, `name-prefix`).
    public var verifyX509NameType: String?
    /// Legacy `tls-remote` name.
    public var tlsRemote: String?
    /// `ns-cert-type` / `remote-cert-tls` value.
    public var nsCertType: String?

    // MARK: Routing and pushed options

    /// `redirect-gateway` present.
    public var redirectGateway: Bool = false
    /// `block-outside-dns` present.
    public var blockOutsideDNS: Bool = false
    /// `route` / `route-ipv6` entries.
    public var routes: [OVPNRoute] = []
    /// `pull-filter` entries, in file order.
    public var pullFilters: [String] = []
    /// `push` directives (only meaningful for server configurations).
    public var pushes: [String] = []
    /// `dhcp-option DNS x` values from the config file.
    public var dnsServers: [String] = []
    /// `topology` value (`subnet`, `net30`, `p2p`).
    public var topology: String?

    // MARK: Timing and tuning

    /// `mtu` / `tun-mtu`.
    public var mtu: Int?
    /// `mssfix` argument (`0` disables).
    public var mssFix: Int?
    /// `reneg-sec` (default 3600, `0` disables renegotiation).
    public var renegSec: Int? = 3600
    /// `ping` interval in seconds.
    public var pingInterval: Int?
    /// `ping-restart` timeout in seconds.
    public var pingRestart: Int?
    /// `hand-window` timeout in seconds.
    public var handWindow: Int?
    /// `persist-tun`.
    public var persistentTun: Bool = false
    /// `persist-key`.
    public var persistKey: Bool = false
    /// `remote-random` — choose one of ``remotes`` at random.
    public var remoteRandom: Bool = false
    /// `explicit-exit-notify` argument.
    public var explicitExitNotify: Int?
    /// `verb` level.
    public var verb: Int?

    // MARK: Escape hatches

    /// Unknown directives, keyed by name in lower case; repeated directives
    /// accumulate into the same array.
    public var extra: [String: [String]] = [:]

    /// Non-fatal problems found while parsing.
    public var parseWarnings: [String] = []

    /// Create an empty configuration (all defaults).
    public init() {}

    // MARK: Derived values

    /// `true` when the tunnel runs a TLS control channel.
    public var isTLSMode: Bool { !isStaticKeyMode }

    /// The embedded `tls-auth` key, when inline.
    public var tlsAuthKeyFile: OVPNStaticKeyFile? {
        guard let tlsAuth, let key = tlsAuth.staticKey else { return nil }
        return OVPNStaticKeyFile(direction: tlsAuth.direction ?? keyDirection, key: key)
    }

    /// The embedded `tls-crypt` key, when inline.
    public var tlsCryptKeyFile: OVPNStaticKeyFile? {
        guard let tlsCrypt, let key = tlsCrypt.staticKey else { return nil }
        return OVPNStaticKeyFile(direction: tlsCrypt.direction ?? keyDirection, key: key)
    }

    /// The embedded `tls-crypt-v2` client key, when inline and well formed.
    public var tlsCryptV2ClientKey: OVPNTlsCryptV2ClientKey? {
        guard let tlsCryptV2 else { return nil }
        return OVPNTlsCryptV2ClientKey.parse(tlsCryptV2)
    }

    /// `pull-filter` entries as typed values.
    public var typedPullFilters: [OVPNPullFilter] {
        pullFilters.compactMap { OVPNPullFilter(string: $0) }
    }

    /// The data channel ciphers the client is willing to negotiate, most
    /// preferred first. `cipher` is the last resort OpenVPN 2.5 uses.
    public var negotiationCiphers: [String] {
        var list = dataCiphers
        if let fallback = dataCiphersFallback, !list.contains(fallback) { list.append(fallback) }
        if let cipher, !list.contains(cipher) { list.append(cipher) }
        return list
    }

    // MARK: File loading

    /// Load the `--secret` key, reading ``staticKeyPath`` when necessary.
    public func loadStaticKeyFile() throws -> OVPNStaticKeyFile {
        if let staticKey { return staticKey }
        guard let path = staticKeyPath else {
            throw OVPNError.missingRequiredDirective("secret")
        }
        let text = try Self.readFile(path)
        guard let parsed = OVPNStaticKey.parse(text) else {
            throw OVPNError.invalidStaticKey("\(path) is not a 256-byte OpenVPN static key")
        }
        return OVPNStaticKeyFile(direction: keyDirection, key: parsed)
    }

    /// Load the `tls-auth` key, reading the file when the config referenced one.
    public func loadTLSAuthKeyFile() throws -> OVPNStaticKeyFile? {
        try Self.load(tlsAuth, fallbackDirection: keyDirection)
    }

    /// Load the `tls-crypt` key, reading the file when the config referenced one.
    public func loadTLSCryptKeyFile() throws -> OVPNStaticKeyFile? {
        try Self.load(tlsCrypt, fallbackDirection: keyDirection)
    }

    /// Load the `tls-crypt-v2` client key, reading the file when referenced.
    public func loadTLSCryptV2ClientKey() throws -> OVPNTlsCryptV2ClientKey? {
        guard let tlsCryptV2 else { return nil }
        if let inline = OVPNTlsCryptV2ClientKey.parse(tlsCryptV2) { return inline }
        let text = try Self.readFile(tlsCryptV2)
        guard let parsed = OVPNTlsCryptV2ClientKey.parse(text) else {
            throw OVPNError.invalidStaticKey("\(tlsCryptV2) is not a tls-crypt-v2 client key")
        }
        return parsed
    }

    private static func load(_ reference: OVPNTLSKey?, fallbackDirection: Int?) throws -> OVPNStaticKeyFile? {
        guard let reference else { return nil }
        let direction = reference.direction ?? fallbackDirection
        if let inline = reference.inline {
            guard let parsed = OVPNStaticKey.parse(inline) else {
                throw OVPNError.invalidStaticKey("inline key block is not a 256-byte static key")
            }
            return OVPNStaticKeyFile(direction: direction, key: parsed)
        }
        guard let path = reference.path else { return nil }
        let text = try Self.readFile(path)
        guard let parsed = OVPNStaticKey.parse(text) else {
            throw OVPNError.invalidStaticKey("\(path) is not a 256-byte OpenVPN static key")
        }
        return OVPNStaticKeyFile(direction: direction, key: parsed)
    }

    private static func readFile(_ path: String) throws -> String {
        do {
            return try String(contentsOfFile: path, encoding: .utf8)
        } catch {
            throw OVPNError.transportFailure("cannot read \(path): \(error.localizedDescription)")
        }
    }

    // MARK: Parsing

    /// Parse `.ovpn` text.
    ///
    /// Throws only for structural problems the engine cannot work around (an
    /// unknown transport protocol, a malformed inline key). Everything else
    /// lands in ``parseWarnings`` or ``extra``.
    public static func parse(_ text: String) throws -> OVPNConfiguration {
        let lexed = OVPNLexer.tokens(text)
        return try parse(tokens: lexed.tokens, warnings: lexed.warnings, isTopLevel: true)
    }

    private static func parse(
        tokens parsedTokens: [OVPNToken],
        warnings initialWarnings: [String],
        isTopLevel: Bool
    ) throws -> OVPNConfiguration {
        var configuration = OVPNConfiguration()
        configuration.parseWarnings = initialWarnings

        var pendingKeyDirection: Int?
        var defaultPort: UInt16 = 1194
        var remotePortGiven: [Bool] = []

        for token in parsedTokens {
            let name = token.name.lowercased()
            let arguments = token.arguments

            func warn(_ message: String) {
                configuration.parseWarnings.append("line \(token.line): \(message)")
            }
            func unhandled() {
                configuration.extra[name, default: []].append(OVPNLexer.joined(arguments))
            }
            func intArgument(_ index: Int = 0) -> Int? {
                guard arguments.count > index else { return nil }
                return Int(arguments[index])
            }
            func requireValue() -> String? {
                guard let first = arguments.first, !first.isEmpty else {
                    warn("directive '\(name)' needs a value")
                    return nil
                }
                return first
            }

            switch name {

            // ---------------------------------------------------------------
            // Mode helpers
            // ---------------------------------------------------------------
            case "client":
                configuration.pull = true
                configuration.tlsClient = true
                configuration.nobind = true
                configuration.isStaticKeyMode = false
            case "pull":
                configuration.pull = true
            case "tls-client":
                configuration.tlsClient = true
                configuration.isStaticKeyMode = false
            case "tls-server":
                warn("tls-server mode is not supported by this client engine")
            case "server":
                warn("server mode is not supported by this client engine")
            case "mode":
                unhandled()

            // ---------------------------------------------------------------
            // Transport
            // ---------------------------------------------------------------
            case "remote":
                guard let host = requireValue() else { break }
                var remote = OVPNRemote(host: host)
                var consumed = 1
                var explicitPort = false
                if arguments.count > 1, let port = UInt16(arguments[1]) {
                    remote.port = port
                    consumed = 2
                    explicitPort = true
                }
                if arguments.count > consumed, let parsed = OVPNProto.parse(arguments[consumed]) {
                    remote.proto = parsed
                    consumed += 1
                }
                if arguments.count > consumed {
                    warn("ignoring extra 'remote' tokens: \(arguments[consumed...].joined(separator: " "))")
                }
                configuration.remotes.append(remote)
                remotePortGiven.append(explicitPort)
            case "remote-random":
                configuration.remoteRandom = true
            case "remote-random-hostname":
                configuration.extra[name, default: []].append("")
            case "proto":
                guard let value = requireValue() else { break }
                guard let parsed = OVPNProto.parse(value) else {
                    throw OVPNError.configSyntax(line: token.line, detail: "unknown proto '\(value)'")
                }
                configuration.proto = parsed
            case "port":
                if let value = intArgument(), let port = UInt16(exactly: value) {
                    defaultPort = port
                    configuration.port = port
                }
            case "lport":
                configuration.localPort = intArgument()
            case "rport":
                configuration.extra[name, default: []].append(OVPNLexer.joined(arguments))
            case "nobind":
                configuration.nobind = true
            case "bind":
                configuration.nobind = false
                unhandled()
            case "dev":
                guard let value = requireValue() else { break }
                configuration.dev = value
                if let derived = deviceType(forDeviceName: value) {
                    configuration.devType = derived
                } else {
                    warn("cannot infer device type from '\(value)'")
                }
            case "dev-type":
                guard let value = requireValue()?.lowercased() else { break }
                if let type = OVPNDeviceType(rawValue: value) {
                    configuration.devType = type
                } else {
                    warn("unknown dev-type '\(value)'")
                }
            case "dev-node":
                unhandled()
            case "topology":
                configuration.topology = requireValue()
            case "resolv-retry", "connect-retry", "connect-retry-max", "connect-timeout",
                 "server-poll-timeout", "socket-flags", "route-delay", "tun-mtu-extra",
                 "sndbuf", "rcvbuf", "iproute":
                unhandled()
            case "tcp-nodelay":
                unhandled()
            case "http-proxy", "http-proxy-retry", "http-proxy-option", "socks-proxy":
                unhandled()
                warn("'\(name)' is not implemented; the host app must proxy the socket")

            // ---------------------------------------------------------------
            // Certificates and keys
            // ---------------------------------------------------------------
            case "ca":
                if token.kind == .inline {
                    configuration.ca = arguments.first
                } else {
                    configuration.caPath = arguments.first
                }
            case "cert":
                if token.kind == .inline {
                    configuration.cert = arguments.first
                } else {
                    configuration.certPath = arguments.first
                }
            case "key":
                if token.kind == .inline {
                    configuration.key = arguments.first
                } else {
                    configuration.keyPath = arguments.first
                }
            case "crl-verify", "extra-certs", "pkcs12", "pkcs8", "askpass", "provider", "engine":
                unhandled()
                warn("'\(name)' is not implemented")
            case "dh":
                if token.kind != .inline, let path = arguments.first {
                    configuration.extra[name, default: []].append(path)
                }
                // A client never needs the DH parameters; OpenVPN ignores them too.
            case "auth-user-pass":
                configuration.authUserPass = true
                if token.kind == .inline {
                    let lines = (arguments.first ?? "")
                        .split(separator: "\n", omittingEmptySubsequences: false)
                        .map { $0.trimmingCharacters(in: .whitespaces) }
                        .filter { !$0.isEmpty }
                    configuration.credentials = OVPNCredentials(
                        username: lines.first,
                        password: lines.count > 1 ? lines[1] : nil
                    )
                } else if let path = arguments.first {
                    configuration.credentials = OVPNCredentials(path: path)
                }
            case "auth-retry", "auth-nocache", "auth-gen-token":
                unhandled()
            case "tls-auth":
                guard let value = requireValue() else { break }
                if token.kind == .inline {
                    configuration.tlsAuth = OVPNTLSKey(inline: value)
                } else {
                    configuration.tlsAuth = OVPNTLSKey(direction: intArgument(1), inline: nil, path: value)
                }
            case "tls-crypt":
                guard let value = requireValue() else { break }
                if token.kind == .inline {
                    configuration.tlsCrypt = OVPNTLSKey(inline: value)
                } else {
                    configuration.tlsCrypt = OVPNTLSKey(direction: intArgument(1), inline: nil, path: value)
                }
            case "tls-crypt-v2":
                configuration.tlsCryptV2 = arguments.first
            case "tls-crypt-v2-verify", "tls-crypt-v2-genkey", "tls-crypt-v2-force-cookie":
                unhandled()
                warn("'\(name)' is not implemented")
            case "key-direction":
                pendingKeyDirection = intArgument()
            case "secret":
                configuration.isStaticKeyMode = true
                configuration.tlsClient = false
                if token.kind == .inline {
                    guard let body = arguments.first, let key = OVPNStaticKey.parse(body) else {
                        throw OVPNError.invalidStaticKey("inline <secret> block is not a 256-byte static key")
                    }
                    configuration.staticKey = OVPNStaticKeyFile(
                        direction: intArgument(1) ?? pendingKeyDirection,
                        key: key
                    )
                } else if let path = arguments.first {
                    configuration.staticKeyPath = path
                    if arguments.count > 1, let direction = Int(arguments[1]) {
                        pendingKeyDirection = direction
                    }
                }
            case "key-method":
                if intArgument() != 2 { warn("only key-method 2 is supported") }
            case "tls-remote":
                configuration.tlsRemote = requireValue()
            case "verify-x509-name":
                guard let value = requireValue() else { break }
                configuration.verifyX509Name = value
                if arguments.count > 1 {
                    configuration.verifyX509NameType = arguments[1].lowercased()
                }
            case "ns-cert-type":
                configuration.nsCertType = requireValue()?.lowercased()
            case "remote-cert-tls":
                configuration.nsCertType = requireValue()?.lowercased()
                unhandled()
            case "remote-cert-ku", "remote-cert-eku", "peer-fingerprint":
                unhandled()
            case "tls-version-min":
                configuration.tlsVersionMin = requireValue()
            case "tls-version-max", "tls-ciphersuites", "tls-cert-profile", "tls-timeout",
                 "tls-exit", "reneg-bytes", "reneg-pkts", "single-session",
                 "trans-window", "mtu-disc", "passtos", "nameserver",
                 "verify-hash", "x509-username-field":
                unhandled()
            case "tls-cipher":
                configuration.tlsCipher = requireValue()
            case "hand-window":
                configuration.handWindow = intArgument()
                unhandled()

            // ---------------------------------------------------------------
            // Crypto
            // ---------------------------------------------------------------
            case "cipher":
                configuration.cipher = requireValue()
            case "data-ciphers":
                guard let value = requireValue() else { break }
                configuration.dataCiphers = value
                    .split(separator: ":")
                    .map { String($0).trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty }
            case "data-ciphers-fallback":
                configuration.dataCiphersFallback = requireValue()
            case "ncp-disable", "ncp-ciphers", "iv", "no-iv", "use-iv":
                unhandled()
                warn("'\(name)' is deprecated and ignored (negotiation is implicit)")
            case "auth":
                configuration.auth = requireValue()
            case "replay-window":
                configuration.replayWindow = intArgument()
                if arguments.count > 1 { configuration.extra[name, default: []].append(arguments[1]) }
            case "no-replay":
                configuration.replayDisabled = true
            case "mute-replay-warnings":
                unhandled()

            // ---------------------------------------------------------------
            // Compression
            // ---------------------------------------------------------------
            case "comp-lzo":
                let value = arguments.first?.lowercased() ?? "adaptive"
                configuration.compLZO = value
                warn("compression (comp-lzo) is not implemented; the tunnel will not carry compressed packets")
            case "compress":
                configuration.compAlgorithm = arguments.first?.lowercased() ?? "stub"
                warn("compression (compress) is not implemented; the tunnel will not carry compressed packets")
            case "allow-compression", "comp-noadapt":
                unhandled()
                warn("compression is not implemented")
            case "push-compression":
                unhandled()

            // ---------------------------------------------------------------
            // Routing and pushed options
            // ---------------------------------------------------------------
            case "redirect-gateway":
                configuration.redirectGateway = true
                if !arguments.isEmpty { unhandled() }
            case "redirect-private":
                if !arguments.isEmpty { unhandled() }
            case "block-outside-dns":
                configuration.blockOutsideDNS = true
            case "route":
                if let route = parseRoute(arguments, isIPv6: false, warning: warn) {
                    configuration.routes.append(route)
                }
            case "route-ipv6":
                if let route = parseRoute(arguments, isIPv6: true, warning: warn) {
                    configuration.routes.append(route)
                }
            case "pull-filter":
                guard arguments.count >= 2, OVPNPullFilter(string: arguments.joined(separator: " ")) != nil else {
                    warn("malformed pull-filter '\(arguments.joined(separator: " "))'")
                    break
                }
                configuration.pullFilters.append(OVPNLexer.joined(arguments))
            case "push":
                configuration.pushes.append(OVPNLexer.joined(arguments))
            case "route-nopull":
                configuration.extra[name, default: []].append("")
            case "dhcp-option":
                if arguments.first?.uppercased() == "DNS", arguments.count > 1 {
                    configuration.dnsServers.append(arguments[1])
                }
                unhandled()
            case "route-gateway", "route-metric", "route-method", "redirect-gateway-ipv6",
                 "ifconfig", "ifconfig-ipv6", "ifconfig-noexec", "route-noexec", "service",
                 "setenv", "setenv-safe", "max-routes", "client-nat", "route-up",
                 "route-pre-down", "ipchange", "inactive":
                unhandled()

            // ---------------------------------------------------------------
            // Timing
            // ---------------------------------------------------------------
            case "ping":
                configuration.pingInterval = intArgument()
            case "ping-restart":
                configuration.pingRestart = intArgument()
            case "ping-exit", "ping-timer-rem":
                unhandled()
                if name == "ping-exit" { configuration.pingRestart = intArgument() }
            case "keepalive":
                configuration.pingInterval = intArgument(0)
                configuration.pingRestart = intArgument(1)
            case "handshake-window":
                configuration.handWindow = intArgument()
            case "reneg-sec":
                configuration.renegSec = intArgument()
            case "mtu", "tun-mtu":
                configuration.mtu = intArgument()
                if name == "tun-mtu" { unhandled() }
            case "mssfix":
                configuration.mssFix = intArgument() ?? 0
            case "fragment":
                unhandled()
                warn("fragmentation is not implemented; lower the MTU instead")
            case "persist-tun":
                configuration.persistentTun = true
            case "persist-key":
                configuration.persistKey = true
            case "persist-local-ip", "persist-remote-ip", "up-restart":
                unhandled()
            case "explicit-exit-notify":
                configuration.explicitExitNotify = intArgument() ?? 1
            case "float", "fast-io", "mlock", "nice", "writepid", "user", "group", "chroot",
                 "daemon", "log", "log-append", "status", "status-version", "mute", "verb",
                 "verb-2", "config", "cd", "script-security", "up", "down", "duplicate-cn",
                 "server-bridge", "ifconfig-pool", "client-config-dir", "max-clients",
                 "management", "management-client", "msg-channel", "syslog", "suppress-timestamps",
                 "machine-readable-output", "show-ciphers", "show-digests", "show-engines",
                 "show-tls", "show-gateway", "show-net-up", "lladdr", "netif-driver",
                 "block-ipv6", "windows-driver", "auto-proxy", "web-proxy", "http-proxy-user-pass",
                 "socks-proxy-retry", "allow-pull-fqdn", "pull-filter-del":
                if name == "verb" { configuration.verb = intArgument() }
                if name == "up" || name == "down" {
                    warn("'\(name)' scripts must be implemented by the host app")
                }
                unhandled()

            // ---------------------------------------------------------------
            // Per-connection blocks
            // ---------------------------------------------------------------
            case "connection":
                guard token.kind == .inline, let body = arguments.first else {
                    warn("<connection> must be an inline block")
                    break
                }
                let nested = try OVPNConfiguration.parse(body)
                configuration.remotes.append(contentsOf: nested.remotes)
                remotePortGiven.append(contentsOf: Array(repeating: true, count: nested.remotes.count))
                configuration.routes.append(contentsOf: nested.routes)
                if nested.proto != .udp || body.lowercased().contains("proto") {
                    configuration.proto = nested.proto
                }
                if nested.remoteRandom { configuration.remoteRandom = true }
                configuration.parseWarnings.append(contentsOf: nested.parseWarnings.map {
                    "line \(token.line) <connection>: \($0)"
                })
                configuration.parseWarnings.append("line \(token.line): <connection> blocks are flattened into the top-level configuration")

            default:
                if token.kind == .inline {
                    // Never dump certificate-sized bodies into `extra`.
                    let size = (arguments.first ?? "").count
                    configuration.extra[name, default: []].append("<inline \(name) block, \(size) bytes>")
                } else {
                    unhandled()
                }
            }
        }

        // A `key-direction` may appear before or after the key directive.
        if let direction = pendingKeyDirection {
            configuration.keyDirection = direction
            if configuration.staticKey?.direction == nil, var staticKey = configuration.staticKey {
                staticKey.direction = direction
                configuration.staticKey = staticKey
            }
        }

        // Remote entries with no explicit port inherit the global `port`.
        for index in configuration.remotes.indices {
            if index < remotePortGiven.count, !remotePortGiven[index] {
                configuration.remotes[index].port = defaultPort
            }
        }
        if configuration.remoteRandom {
            for index in configuration.remotes.indices {
                configuration.remotes[index].isRandom = true
            }
        }

        if isTopLevel, configuration.remotes.isEmpty, !configuration.isStaticKeyMode {
            configuration.parseWarnings.append("no 'remote' directive found")
        }

        return configuration
    }

    /// `tun`/`utun`/`tap` prefix sniffing, as `options.c` does.
    private static func deviceType(forDeviceName name: String) -> OVPNDeviceType? {
        let lowered = name.lowercased()
        if lowered.hasPrefix("tun") || lowered.hasPrefix("utun") { return .tun }
        if lowered.hasPrefix("tap") { return .tap }
        return nil
    }

    /// Parse `route NETWORK [NETMASK] [GATEWAY] [METRIC]` and
    /// `route-ipv6 PREFIX [GATEWAY] [METRIC]`.
    ///
    /// Shared with ``OVPNPushReply`` so a route pushed by the server and one
    /// written in the config file produce the same value.
    static func parseRoute(_ arguments: [String], isIPv6: Bool, warning: (String) -> Void) -> OVPNRoute? {
        guard let network = arguments.first else {
            warning("route needs at least a network")
            return nil
        }
        var route = OVPNRoute(network: network, isIPv6: isIPv6 || network.contains(":"))
        var rest = Array(arguments.dropFirst())

        if !route.isIPv6, let candidate = rest.first, OVPNRoute.prefixLength(dottedQuad: candidate) != nil {
            route.netmask = candidate
            rest.removeFirst()
        }
        if let candidate = rest.first {
            route.gateway = candidate
            rest.removeFirst()
        }
        if let candidate = rest.first, let metric = Int(candidate) {
            route.metric = metric
            rest.removeFirst()
        }
        if !rest.isEmpty {
            warning("ignoring extra 'route' tokens: \(rest.joined(separator: " "))")
        }
        return route
    }
}
