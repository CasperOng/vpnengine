//
//  CIDR.swift
//  VPNEngine
//
//  An IPv4 or IPv6 address with a prefix length, used for WireGuard interface
//  addresses and peer `AllowedIPs` (whitepaper, section 3).
//
//  The address is stored exactly as it was written, so an interface address
//  such as `10.7.0.2/24` keeps its host bits and round-trips through
//  ``description``. Matching always ignores the host bits, which is the
//  behaviour `AllowedIPs` needs.
//

import Foundation

/// An IP address together with a prefix length, for example `10.0.0.0/8` or `::/0`.
public struct CIDR: Hashable, Sendable, CustomStringConvertible, Codable {

    /// The raw address: 4 bytes for IPv4, 16 bytes for IPv6.
    ///
    /// The host bits are preserved as written; see ``networkAddress`` for the
    /// masked form.
    public let address: Data

    /// The number of leading bits that must match, 0...32 for IPv4 and 0...128
    /// for IPv6.
    public let prefixLength: Int

    // MARK: - Creation

    /// Creates a range from an address and prefix length.
    ///
    /// - Parameters:
    ///   - address: Exactly 4 (IPv4) or 16 (IPv6) bytes.
    ///   - prefixLength: 0...32 for IPv4, 0...128 for IPv6.
    /// - Returns: `nil` when the address size and prefix length do not agree.
    public init?(address: Data, prefixLength: Int) {
        let limit: Int
        switch address.count {
        case 4: limit = 32
        case 16: limit = 128
        default: return nil
        }
        guard prefixLength >= 0, prefixLength <= limit else { return nil }
        self.address = address
        self.prefixLength = prefixLength
    }

    /// Parses a range such as `10.0.0.0/8`, `2001:db8::/32` or a bare address.
    ///
    /// A bare address is treated as a host route: `/32` for IPv4 and `/128` for
    /// IPv6. Surrounding whitespace is ignored. An embedded IPv4 tail
    /// (`::ffff:192.0.2.1`) is understood.
    ///
    /// - Parameter string: The textual range.
    /// - Returns: `nil` when the text is not a valid address range.
    public init?(string: String) {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        var addressText = trimmed
        var prefix: Int?

        if let slashIndex = trimmed.firstIndex(of: "/") {
            addressText = String(trimmed[trimmed.startIndex ..< slashIndex])
            let prefixText = String(trimmed[trimmed.index(after: slashIndex)...])
            guard let value = Int(prefixText), value >= 0 else { return nil }
            prefix = value
            guard !addressText.isEmpty else { return nil }
        }

        let bytes: [UInt8]
        let defaultPrefix: Int
        if addressText.contains(":") {
            guard let parsed = CIDR.parseIPv6(addressText) else { return nil }
            bytes = parsed
            defaultPrefix = 128
        } else {
            guard let parsed = CIDR.parseIPv4(addressText) else { return nil }
            bytes = parsed
            defaultPrefix = 32
        }

        self.init(address: Data(bytes), prefixLength: prefix ?? defaultPrefix)
    }

    // MARK: - Properties

    /// The address family of the range.
    public var family: IPAddressFamily {
        address.count == 4 ? .ipv4 : .ipv6
    }

    /// Whether this range matches every address of its family, i.e. `0.0.0.0/0`
    /// or `::/0`.
    public var isDefaultRoute: Bool {
        prefixLength == 0
    }

    /// The address with all host bits cleared.
    public var networkAddress: Data {
        var bytes = [UInt8](address)
        for index in 0 ..< bytes.count {
            let bitStart = index * 8
            if bitStart >= prefixLength {
                bytes[index] = 0
            } else if bitStart + 8 > prefixLength {
                let keep = prefixLength - bitStart
                bytes[index] &= UInt8(truncatingIfNeeded: 0xFF << (8 - keep))
            }
        }
        return Data(bytes)
    }

    /// The textual form, using the address exactly as it was written.
    public var description: String {
        "\(CIDR.format(address))/\(prefixLength)"
    }

    /// Whether `address` falls inside this range.
    ///
    /// The families must match: an IPv4 range never contains an IPv6 address.
    ///
    /// - Parameter address: 4 or 16 raw address bytes.
    /// - Returns: `true` when the leading ``prefixLength`` bits are equal.
    public func contains(_ address: Data) -> Bool {
        guard address.count == self.address.count else { return false }
        let candidate = [UInt8](address)
        let network = [UInt8](self.address)

        let wholeBytes = prefixLength / 8
        if wholeBytes > 0 {
            for index in 0 ..< wholeBytes where candidate[index] != network[index] {
                return false
            }
        }
        let remainingBits = prefixLength % 8
        if remainingBits > 0 {
            let mask = UInt8(truncatingIfNeeded: 0xFF << (8 - remainingBits))
            if (candidate[wholeBytes] ^ network[wholeBytes]) & mask != 0 {
                return false
            }
        }
        return true
    }

    // MARK: - Codable

    /// Encodes the range as its textual form, so a JSON configuration reads
    /// `"allowedIPs": ["0.0.0.0/0"]` rather than a base64 blob.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }

    /// Decodes a range from its textual form.
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let text = try container.decode(String.self)
        guard let value = CIDR(string: text) else {
            throw DecodingError.dataCorruptedError(in: container,
                                                   debugDescription: "\"\(text)\" is not a valid address range")
        }
        self = value
    }

    // MARK: - Parsing helpers

    /// Parses a dotted quad such as `192.0.2.1`.
    ///
    /// Leading zeros are accepted and read as decimal, so `010` is ten.
    ///
    /// - Parameter text: The text to parse.
    /// - Returns: Four bytes, or `nil` when the text is not a dotted quad.
    static func parseIPv4(_ text: String) -> [UInt8]? {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(4)
        for part in parts {
            guard !part.isEmpty, part.count <= 3 else { return nil }
            guard part.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
            guard let value = Int(part), value >= 0, value <= 255 else { return nil }
            bytes.append(UInt8(value))
        }
        return bytes
    }

    /// Parses an IPv6 address, including `::` compression and an embedded IPv4
    /// tail.
    ///
    /// - Parameter text: The text to parse.
    /// - Returns: Sixteen bytes, or `nil` when the text is not a valid address.
    static func parseIPv6(_ text: String) -> [UInt8]? {
        var head = text
        var tail: [UInt8] = []

        // An embedded IPv4 tail occupies the last two 16 bit groups.
        if head.contains(".") {
            guard let lastColon = head.lastIndex(of: ":") else { return nil }
            let ipv4Text = String(head[head.index(after: lastColon)...])
            guard let ipv4 = parseIPv4(ipv4Text) else { return nil }
            tail = ipv4
            head = String(head[head.startIndex ..< lastColon])
        }

        func parseGroups(_ text: String) -> [UInt16]? {
            guard !text.isEmpty else { return [] }
            var groups: [UInt16] = []
            for group in text.split(separator: ":", omittingEmptySubsequences: false) {
                guard !group.isEmpty, group.count <= 4 else { return nil }
                guard group.allSatisfy({ $0.isHexDigit }) else { return nil }
                guard let value = UInt16(group, radix: 16) else { return nil }
                groups.append(value)
            }
            return groups
        }

        var groups: [UInt16]
        let tailGroupCount = tail.isEmpty ? 0 : 2

        if let range = head.range(of: "::") {
            guard let left = parseGroups(String(head[head.startIndex ..< range.lowerBound])),
                  let right = parseGroups(String(head[range.upperBound...])) else { return nil }
            let total = left.count + right.count + tailGroupCount
            guard total <= 8 else { return nil }
            groups = left + [UInt16](repeating: 0, count: 8 - total) + right
        } else {
            guard let parsed = parseGroups(head) else { return nil }
            guard parsed.count + tailGroupCount == 8 else { return nil }
            groups = parsed
        }

        // The embedded IPv4 tail provides the last two groups.
        if tail.count == 4 {
            groups.append(UInt16(tail[0]) << 8 | UInt16(tail[1]))
            groups.append(UInt16(tail[2]) << 8 | UInt16(tail[3]))
        }

        var bytes = [UInt8]()
        bytes.reserveCapacity(16)
        for group in groups {
            bytes.append(UInt8(truncatingIfNeeded: group >> 8))
            bytes.append(UInt8(truncatingIfNeeded: group))
        }
        return bytes.count == 16 ? bytes : nil
    }

    /// Formats an address, compressing the longest run of zero groups in IPv6
    /// addresses as RFC 5952 requires.
    ///
    /// - Parameter address: 4 or 16 raw bytes.
    /// - Returns: The textual form, or an empty string for other sizes.
    static func format(_ address: Data) -> String {
        let bytes = [UInt8](address)
        switch bytes.count {
        case 4:
            return bytes.map(String.init).joined(separator: ".")
        case 16:
            return formatIPv6(bytes)
        default:
            return ""
        }
    }

    /// Formats sixteen bytes as an IPv6 address (RFC 5952).
    ///
    /// - Parameter bytes: Exactly 16 bytes.
    /// - Returns: The textual form.
    static func formatIPv6(_ bytes: [UInt8]) -> String {
        var groups = [UInt16](repeating: 0, count: 8)
        for index in 0 ..< 8 {
            groups[index] = UInt16(bytes[index * 2]) << 8 | UInt16(bytes[index * 2 + 1])
        }

        // Find the longest run of at least two zero groups.
        var bestStart = -1
        var bestLength = 0
        var index = 0
        while index < 8 {
            guard groups[index] == 0 else {
                index += 1
                continue
            }
            var end = index
            while end < 8, groups[end] == 0 { end += 1 }
            if end - index > bestLength {
                bestLength = end - index
                bestStart = index
            }
            index = end
        }
        if bestLength < 2 {
            bestStart = -1
            bestLength = 0
        }

        var out = ""
        var position = 0
        while position < 8 {
            if position == bestStart {
                out += "::"
                position += bestLength
                continue
            }
            if !out.isEmpty, !out.hasSuffix(":") { out += ":" }
            out += String(groups[position], radix: 16)
            position += 1
        }
        return out
    }
}

/// The address family of an IP address.
public enum IPAddressFamily: String, Sendable, Codable, CaseIterable {

    /// A 32 bit address (`4` raw bytes).
    case ipv4

    /// A 128 bit address (`16` raw bytes).
    case ipv6
}
