//
//  IPPacket.swift
//  VPNEngine
//
//  Parsing and checksum maintenance for the IP packets that travel inside the
//  tunnel.
//
//  WireGuard does not look inside packets except to decide which peer they
//  belong to, but the engine sits between two network stacks that disagree
//  about checksums: a TUN device hands over packets whose checksums are already
//  filled in, and a packet whose length the tunnel adjusts (because of
//  padding, or an MTU change) needs them recomputed. Doing that here keeps the
//  logic in one place and out of the tunnels themselves.
//
//  Everything is bounds checked: a malformed packet yields `nil` from
//  ``inspect(_:)`` or is left untouched by ``recomputeChecksums(_:)``.
//

import Foundation

/// Utilities for the IPv4 and IPv6 packets carried by a tunnel.
public enum IPPacket {

    /// IPv4 protocol number for ICMP.
    public static let protocolICMP: UInt8 = 1

    /// IP protocol number for TCP.
    public static let protocolTCP: UInt8 = 6

    /// IP protocol number for UDP.
    public static let protocolUDP: UInt8 = 17

    /// IPv6 next-header value for ICMPv6.
    public static let protocolICMPv6: UInt8 = 58

    /// The minimum size of an IPv4 header.
    public static let minimumIPv4HeaderLength = 20

    /// The size of an IPv6 header; unlike IPv4 it has no options field.
    public static let ipv6HeaderLength = 40

    /// What ``inspect(_:)`` learns about a packet.
    public struct Info: Sendable, Equatable {

        /// The IP version: 4 or 6.
        public let version: Int

        /// The source address: 4 bytes for IPv4, 16 for IPv6.
        public let source: Data

        /// The destination address: 4 bytes for IPv4, 16 for IPv6.
        public let destination: Data

        /// The upper layer protocol number.
        ///
        /// For IPv6 this is the last next-header value, so extension headers
        /// are skipped and this is the protocol of the payload itself.
        public let protocolNumber: UInt8

        /// The offset of the transport header from the start of the packet.
        public let payloadOffset: Int

        /// The total length the packet's own header claims, when it is
        /// plausible.
        public let declaredLength: Int?

        /// The number of payload bytes the transport checksum should cover.
        public let transportLength: Int
    }

    // MARK: - Inspection

    /// Inspects a packet's header without modifying it.
    ///
    /// - Parameter packet: A complete IP packet. Leading bytes belonging to the
    ///   operating system's framing must already be removed.
    /// - Returns: What the header says, or `nil` when the packet is not a
    ///   well-formed IPv4 or IPv6 datagram.
    public static func inspect(_ packet: Data) -> Info? {
        inspect([UInt8](packet))
    }

    /// Returns the total length the packet's header claims.
    ///
    /// WireGuard pads the plaintext of a transport message with zero bytes to
    /// hide the exact length of small packets, so the receiver must use this to
    /// find where the real packet ends.
    ///
    /// - Parameter packet: A complete IP packet, possibly with trailing zero
    ///   padding.
    /// - Returns: The packet's own idea of its length, or `nil` when it cannot
    ///   be determined.
    public static func declaredLength(_ packet: Data) -> Int? {
        inspect([UInt8](packet))?.declaredLength
    }

    // MARK: - Mutation

    /// Writes an IPv4 packet's total length field.
    ///
    /// The header checksum is deliberately *not* updated, matching the
    /// reference implementation; call ``recomputeChecksums(_:)`` afterwards to
    /// make the packet consistent again.
    ///
    /// - Parameters:
    ///   - packet: An IPv4 packet.
    ///   - length: The new total length, in bytes, including the header.
    ///     Ignored when it does not fit in the packet.
    public static func setTotalLength(_ packet: inout Data, _ length: UInt16) {
        var bytes = [UInt8](packet)
        guard bytes.count >= 4, bytes[0] >> 4 == 4 else { return }
        guard Int(length) >= 4, Int(length) <= bytes.count else { return }
        bytes[2] = UInt8(truncatingIfNeeded: length >> 8)
        bytes[3] = UInt8(truncatingIfNeeded: length)
        packet = Data(bytes)
    }

    /// Generates a random IPv4 identification field.
    ///
    /// Used when the tunnel has to fabricate an outer IPv4 header.
    ///
    /// - Returns: Sixteen random bits.
    public static func generateIPv4FragmentIdentifier() -> UInt16 {
        UInt16.random(in: .min ... .max)
    }

    /// Recomputes every checksum the tunnel is responsible for.
    ///
    /// This always fixes the IPv4 header checksum of an IPv4 packet, and then
    /// recomputes the TCP or UDP checksum when the payload is TCP or UDP. ICMP
    /// and ICMPv6 checksums are left alone: they are covered by the same
    /// transport rules but the reference implementation does not touch them,
    /// and the ICMP checksum does not include a pseudo-header for IPv4.
    ///
    /// A packet that cannot be parsed, or whose transport header is truncated,
    /// is returned unchanged.
    ///
    /// - Parameter packet: The packet to fix up, in place.
    public static func recomputeChecksums(_ packet: inout Data) {
        var bytes = [UInt8](packet)
        guard let info = inspect(bytes) else { return }

        if info.version == 4 {
            recomputeIPv4HeaderChecksum(&bytes, headerLength: info.payloadOffset)
        }

        switch info.protocolNumber {
        case IPPacket.protocolTCP:
            recomputeTransportChecksum(&bytes,
                                       info: info,
                                       checksumOffset: 16,
                                       minimumLength: 20,
                                       useUDPHeaderLength: false)
        case IPPacket.protocolUDP:
            recomputeTransportChecksum(&bytes,
                                       info: info,
                                       checksumOffset: 6,
                                       minimumLength: 8,
                                       useUDPHeaderLength: true)
        default:
            break
        }

        packet = Data(bytes)
    }

    /// Checks a packet's existing checksums, for tests and diagnostics.
    ///
    /// - Parameter packet: A complete IP packet.
    /// - Returns: `true` when every checksum the packet carries is consistent.
    public static func hasValidChecksums(_ packet: Data) -> Bool {
        let bytes = [UInt8](packet)
        guard let info = inspect(bytes) else { return false }

        if info.version == 4 {
            var header = Array(bytes[0 ..< info.payloadOffset])
            header[10] = 0
            header[11] = 0
            let computed = InternetChecksum.compute(header)
            let stored = UInt16(bytes[10]) << 8 | UInt16(bytes[11])
            if computed != stored { return false }
        }

        switch info.protocolNumber {
        case IPPacket.protocolTCP:
            return transportChecksumMatches(bytes, info: info, checksumOffset: 16, useUDPHeaderLength: false)
        case IPPacket.protocolUDP:
            let stored = UInt16(bytes[info.payloadOffset + 6]) << 8 | UInt16(bytes[info.payloadOffset + 7])
            // A zero UDP checksum means "not computed" in IPv4.
            if info.version == 4, stored == 0 { return true }
            return transportChecksumMatches(bytes, info: info, checksumOffset: 6, useUDPHeaderLength: true)
        default:
            return true
        }
    }

    // MARK: - Internals

    /// Inspects a packet held as bytes.
    ///
    /// - Parameter bytes: The whole packet.
    /// - Returns: The parsed header, or `nil`.
    static func inspect(_ bytes: [UInt8]) -> Info? {
        guard let firstByte = bytes.first else { return nil }
        switch firstByte >> 4 {
        case 4: return inspectIPv4(bytes)
        case 6: return inspectIPv6(bytes)
        default: return nil
        }
    }

    /// Parses an IPv4 header.
    ///
    /// - Parameter bytes: The whole packet.
    /// - Returns: The parsed header, or `nil`.
    private static func inspectIPv4(_ bytes: [UInt8]) -> Info? {
        guard bytes.count >= minimumIPv4HeaderLength else { return nil }
        guard bytes[0] >> 4 == 4 else { return nil }

        let headerLength = Int(bytes[0] & 0x0F) * 4
        guard headerLength >= minimumIPv4HeaderLength, headerLength <= bytes.count else { return nil }

        let declaredLength = Int(bytes[2]) << 8 | Int(bytes[3])
        let available = bytes.count - headerLength
        // The declared length is only trusted when it fits the buffer, and the
        // transport checksum covers whatever is actually there otherwise.
        let payloadLength: Int
        let plausibleDeclared: Int?
        if declaredLength >= headerLength, declaredLength <= bytes.count {
            payloadLength = declaredLength - headerLength
            plausibleDeclared = declaredLength
        } else if declaredLength >= headerLength {
            payloadLength = available
            plausibleDeclared = nil
        } else {
            payloadLength = available
            plausibleDeclared = nil
        }

        return Info(version: 4,
                    source: Data(bytes[12 ..< 16]),
                    destination: Data(bytes[16 ..< 20]),
                    protocolNumber: bytes[9],
                    payloadOffset: headerLength,
                    declaredLength: plausibleDeclared,
                    transportLength: payloadLength)
    }

    /// Parses an IPv6 header, skipping any extension headers.
    ///
    /// - Parameter bytes: The whole packet.
    /// - Returns: The parsed header, or `nil`.
    private static func inspectIPv6(_ bytes: [UInt8]) -> Info? {
        guard bytes.count >= ipv6HeaderLength else { return nil }
        guard bytes[0] >> 4 == 6 else { return nil }

        let declaredLength = ipv6HeaderLength + (Int(bytes[4]) << 8 | Int(bytes[5]))
        var nextHeader = bytes[6]
        var offset = ipv6HeaderLength

        // Walk extension headers, bounded so that a malformed chain cannot spin.
        for _ in 0 ..< 8 {
            guard let headerLength = IPv6ExtensionHeader.length(nextHeader, at: offset, in: bytes) else { break }
            guard offset + headerLength <= bytes.count, headerLength > 0 else { break }
            nextHeader = bytes[offset]
            offset += headerLength
        }

        let available = bytes.count - offset
        let payloadLength: Int
        let plausibleDeclared: Int?
        if declaredLength >= offset, declaredLength <= bytes.count {
            payloadLength = declaredLength - offset
            plausibleDeclared = declaredLength
        } else {
            payloadLength = available
            plausibleDeclared = declaredLength <= bytes.count ? declaredLength : nil
        }

        return Info(version: 6,
                    source: Data(bytes[8 ..< 24]),
                    destination: Data(bytes[24 ..< 40]),
                    protocolNumber: nextHeader,
                    payloadOffset: offset,
                    declaredLength: plausibleDeclared,
                    transportLength: payloadLength)
    }

    /// Recomputes the IPv4 header checksum in place.
    ///
    /// - Parameters:
    ///   - bytes: The packet, modified in place.
    ///   - headerLength: The header length in bytes.
    private static func recomputeIPv4HeaderChecksum(_ bytes: inout [UInt8], headerLength: Int) {
        guard headerLength >= minimumIPv4HeaderLength, headerLength <= bytes.count else { return }
        bytes[10] = 0
        bytes[11] = 0
        let checksum = InternetChecksum.compute(bytes[0 ..< headerLength])
        bytes[10] = UInt8(truncatingIfNeeded: checksum >> 8)
        bytes[11] = UInt8(truncatingIfNeeded: checksum)
    }

    /// Recomputes a TCP or UDP checksum in place.
    ///
    /// - Parameters:
    ///   - bytes: The packet, modified in place.
    ///   - info: The parsed header.
    ///   - checksumOffset: Offset of the checksum field within the transport
    ///     header: 16 for TCP, 6 for UDP.
    ///   - minimumLength: The smallest legal transport header size.
    ///   - useUDPHeaderLength: Whether the checksum length should come from the
    ///     UDP length field rather than the IP header.
    private static func recomputeTransportChecksum(_ bytes: inout [UInt8],
                                                   info: Info,
                                                   checksumOffset: Int,
                                                   minimumLength: Int,
                                                   useUDPHeaderLength: Bool) {
        let start = info.payloadOffset
        guard start + minimumLength <= bytes.count else { return }

        var length = info.transportLength
        if useUDPHeaderLength {
            let udpLength = Int(bytes[start + 4]) << 8 | Int(bytes[start + 5])
            if udpLength >= minimumLength, start + udpLength <= bytes.count {
                length = udpLength
            }
        }
        guard length >= minimumLength, start + length <= bytes.count else { return }

        bytes[start + checksumOffset] = 0
        bytes[start + checksumOffset + 1] = 0

        var accumulator = InternetChecksum()
        accumulator.add(pseudoHeader(info: info, length: length))
        accumulator.add(bytes[start ..< start + length])
        var checksum = accumulator.value()

        // UDP transmits an all-ones checksum where the sum is zero, because an
        // all-zero field means "no checksum" in IPv4 and is illegal in IPv6.
        if info.protocolNumber == IPPacket.protocolUDP, checksum == 0 {
            checksum = 0xFFFF
        }

        bytes[start + checksumOffset] = UInt8(truncatingIfNeeded: checksum >> 8)
        bytes[start + checksumOffset + 1] = UInt8(truncatingIfNeeded: checksum)
    }

    /// Verifies an existing TCP or UDP checksum.
    ///
    /// - Parameters:
    ///   - bytes: The whole packet.
    ///   - info: The parsed header.
    ///   - checksumOffset: Offset of the checksum field within the transport
    ///     header.
    ///   - useUDPHeaderLength: Whether the length comes from the UDP header.
    /// - Returns: `true` when the stored checksum matches.
    private static func transportChecksumMatches(_ bytes: [UInt8],
                                                info: Info,
                                                checksumOffset: Int,
                                                useUDPHeaderLength: Bool) -> Bool {
        let start = info.payloadOffset
        guard start + checksumOffset + 2 <= bytes.count else { return false }

        var length = info.transportLength
        if useUDPHeaderLength {
            let udpLength = Int(bytes[start + 4]) << 8 | Int(bytes[start + 5])
            if udpLength >= 8, start + udpLength <= bytes.count {
                length = udpLength
            }
        }
        guard length >= 8, start + length <= bytes.count else { return false }

        var copy = Array(bytes[start ..< start + length])
        let stored = UInt16(copy[checksumOffset]) << 8 | UInt16(copy[checksumOffset + 1])
        copy[checksumOffset] = 0
        copy[checksumOffset + 1] = 0

        var accumulator = InternetChecksum()
        accumulator.add(pseudoHeader(info: info, length: length))
        accumulator.add(copy)
        var computed = accumulator.value()
        if computed == 0, stored == 0xFFFF { computed = 0xFFFF }
        return computed == stored
    }

    /// Builds the transport pseudo-header for a checksum.
    ///
    /// - Parameters:
    ///   - info: The parsed IP header.
    ///   - length: The transport payload length.
    /// - Returns: Twelve bytes for IPv4, forty for IPv6.
    private static func pseudoHeader(info: Info, length: Int) -> [UInt8] {
        var header: [UInt8] = []
        header.append(contentsOf: info.source)
        header.append(contentsOf: info.destination)

        if info.version == 4 {
            header.append(0)
            header.append(info.protocolNumber)
            header.append(UInt8(truncatingIfNeeded: length >> 8))
            header.append(UInt8(truncatingIfNeeded: length))
        } else {
            // IPv6 uses a 32 bit length and the *last* next header value, which
            // is why extension headers are walked during inspection.
            header.append(UInt8(truncatingIfNeeded: length >> 24))
            header.append(UInt8(truncatingIfNeeded: length >> 16))
            header.append(UInt8(truncatingIfNeeded: length >> 8))
            header.append(UInt8(truncatingIfNeeded: length))
            header.append(0)
            header.append(0)
            header.append(0)
            header.append(info.protocolNumber)
        }
        return header
    }
}

/// Sizes of the IPv6 extension headers the inspector understands.
private enum IPv6ExtensionHeader {

    /// The length of the extension header starting at `offset`, or `nil` when
    /// `nextHeader` does not introduce an extension header we know about.
    ///
    /// - Parameters:
    ///   - nextHeader: The next-header value.
    ///   - offset: Where the header starts.
    ///   - bytes: The whole packet, for bounds checks.
    /// - Returns: The header length in bytes, including the next-header field.
    static func length(_ nextHeader: UInt8, at offset: Int, in bytes: [UInt8]) -> Int? {
        guard offset + 2 <= bytes.count else { return nil }
        let lengthField = Int(bytes[offset + 1])
        switch nextHeader {
        case 0, 43, 60:
            // Hop-by-Hop Options, Routing, Destination Options: length is
            // (Hdr Ext Len + 1) * 8.
            return (lengthField + 1) * 8
        case 44:
            // Fragment header: always eight bytes.
            return 8
        case 51:
            // Authentication Header: (Payload Len + 2) * 4.
            return (lengthField + 2) * 4
        default:
            return nil
        }
    }
}
