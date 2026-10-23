//
//  IPPacketTests.swift
//  VPNEngineTests
//
//  The internet checksum and the IP packet layer, against whole packets whose
//  checksums were computed by an independent implementation of RFC 1071 (see
//  `regenerate-packet-vectors.py`).
//

import XCTest
@testable import VPNEngine

final class InternetChecksumTests: XCTestCase {

    /// RFC 1071 section 3 shows a complete, valid IPv4 header: summing it,
    /// checksum field included, must give zero.
    func testValidHeaderSumsToZero() {
        let header = hexBytes(TestVectors.ipv4Header)
        XCTAssertEqual(InternetChecksum.compute(header), 0x0000,
                       "a valid header must sum to zero")
    }

    func testChecksumOfHeaderWithZeroedField() {
        var header = hexBytes(TestVectors.ipv4Header)
        header[10] = 0
        header[11] = 0
        XCTAssertEqual(InternetChecksum.compute(header),
                       UInt16(TestVectors.ipv4HeaderChecksum, radix: 16),
                       "the checksum of the zeroed header")
    }

    func testEmptyAndSingleByteInputs() {
        XCTAssertEqual(InternetChecksum.compute([]), 0xFFFF, "the sum of nothing is all ones")
        // A single byte is treated as the high half of a word.
        XCTAssertEqual(InternetChecksum.compute([0x01]), 0xFEFF)
        XCTAssertEqual(InternetChecksum.compute([0x00, 0x01]), 0xFFFE)
    }

    /// Splitting a buffer at an odd boundary must give the same answer as
    /// summing it whole, which is what the pending byte exists for.
    func testIncrementalSumsMatchWholeBuffer() {
        let bytes = [UInt8]("the quick brown fox jumps over the lazy dog".utf8)
        let whole = InternetChecksum.compute(bytes)
        for split in 0 ... bytes.count {
            var accumulator = InternetChecksum()
            accumulator.add(Array(bytes[0 ..< split]))
            accumulator.add(Array(bytes[split...]))
            XCTAssertEqual(accumulator.value(), whole, "split at \(split)")
        }
    }

    func testFoldingOfManyCarries() {
        // A long run of 0xFFFF words overflows the 16 bit accumulator many
        // times over.
        let bytes = [UInt8](repeating: 0xFF, count: 512)
        XCTAssertEqual(InternetChecksum.compute(bytes), 0x0000)
        XCTAssertEqual(InternetChecksum.compute([UInt8](repeating: 0xFF, count: 510)), 0x0000)
    }
}

final class IPPacketTests: XCTestCase {

    private let allVectors: [String] = [
        PacketVectors.ipv4UDP,
        PacketVectors.ipv4TCP,
        PacketVectors.ipv4ICMP,
        PacketVectors.ipv6UDP,
        PacketVectors.ipv6OptionsUDP,
        PacketVectors.ipv6TCP,
    ]

    func testInspectsEveryVector() {
        let expected: [(version: Int, source: String, destination: String, proto: UInt8, offset: Int)] = [
            (4, PacketVectors.ipv4Source, PacketVectors.ipv4Destination, 17, 20),
            (4, PacketVectors.ipv4Source, PacketVectors.ipv4Destination, 6, 20),
            (4, PacketVectors.ipv4Source, PacketVectors.ipv4Destination, 1, 20),
            (6, PacketVectors.ipv6Source, PacketVectors.ipv6Destination, 17, 40),
            // The Hop-by-Hop header is eight bytes and the transport is UDP.
            (6, PacketVectors.ipv6Source, PacketVectors.ipv6Destination, 17, 48),
            (6, PacketVectors.ipv6Source, PacketVectors.ipv6Destination, 6, 40),
        ]

        for (index, hex) in allVectors.enumerated() {
            let packet = hexData(hex)
            guard let info = IPPacket.inspect(packet) else {
                XCTFail("vector \(index) did not inspect")
                continue
            }
            XCTAssertEqual(info.version, expected[index].version, "vector \(index)")
            XCTAssertEqual(info.source, hexData(expected[index].source), "vector \(index)")
            XCTAssertEqual(info.destination, hexData(expected[index].destination), "vector \(index)")
            XCTAssertEqual(info.protocolNumber, expected[index].proto, "vector \(index)")
            XCTAssertEqual(info.payloadOffset, expected[index].offset, "vector \(index)")
            XCTAssertEqual(info.declaredLength, packet.count, "vector \(index)")
            XCTAssertEqual(info.transportLength, packet.count - expected[index].offset, "vector \(index)")
        }
    }

    /// The property that matters: recomputing every checksum must reproduce the
    /// bytes an independent implementation produced.
    func testRecomputedChecksumsMatchTheVectors() {
        for (index, hex) in allVectors.enumerated() {
            var packet = hexData(hex)
            XCTAssertTrue(IPPacket.hasValidChecksums(packet), "vector \(index) should start valid")

            // Zero out the checksums the engine is responsible for.
            guard let info = IPPacket.inspect(packet) else {
                XCTFail("vector \(index) did not inspect")
                continue
            }
            var zeroed = packet
            if info.version == 4 {
                zeroed[10] = 0
                zeroed[11] = 0
            }
            if info.protocolNumber == IPPacket.protocolTCP {
                zeroed[info.payloadOffset + 16] = 0
                zeroed[info.payloadOffset + 17] = 0
            } else if info.protocolNumber == IPPacket.protocolUDP {
                zeroed[info.payloadOffset + 6] = 0
                zeroed[info.payloadOffset + 7] = 0
            }
            XCTAssertNotEqual(zeroed, packet, "vector \(index) had nothing to recompute")

            IPPacket.recomputeChecksums(&zeroed)
            XCTAssertBytesEqual(zeroed, packet, "vector \(index) recomputed differently")
        }
    }

    func testLeavesICMPChecksumsAlone() {
        // The IPv4 header checksum is fixed, but the ICMP checksum inside is
        // not the engine's business, so it must survive untouched.
        var packet = hexData(PacketVectors.ipv4ICMP)
        let original = packet
        IPPacket.recomputeChecksums(&packet)
        XCTAssertBytesEqual(packet, original, "an ICMP packet must come back unchanged")
    }

    func testDeclaredLengthFindsTheEndOfAPaddedPacket() {
        let packet = hexData(PacketVectors.ipv4UDP)
        var padded = packet
        padded.append(contentsOf: [UInt8](repeating: 0, count: 13))
        XCTAssertEqual(IPPacket.declaredLength(padded), packet.count)

        let v6Padded = hexData(PacketVectors.ipv6UDP) + Data(repeating: 0, count: 4)
        XCTAssertEqual(IPPacket.declaredLength(v6Padded), hexData(PacketVectors.ipv6UDP).count)
    }

    func testSetTotalLength() {
        var packet = hexData(PacketVectors.ipv4UDP)
        let originalLength = packet.count
        IPPacket.setTotalLength(&packet, UInt16(originalLength))
        XCTAssertEqual(IPPacket.inspect(packet)?.declaredLength, originalLength)
        XCTAssertTrue(IPPacket.hasValidChecksums(packet))

        // Shortening the length field leaves the rest of the bytes alone, and
        // recomputing the checksum makes the packet self consistent again.
        IPPacket.setTotalLength(&packet, 28)
        XCTAssertFalse(IPPacket.hasValidChecksums(packet), "the header checksum is deliberately stale")
        IPPacket.recomputeChecksums(&packet)
        XCTAssertTrue(IPPacket.hasValidChecksums(packet))
        XCTAssertEqual(IPPacket.inspect(packet)?.declaredLength, 28)

        // Nonsense lengths are ignored rather than written.
        var untouched = hexData(PacketVectors.ipv4UDP)
        IPPacket.setTotalLength(&untouched, 0)
        XCTAssertEqual(IPPacket.inspect(untouched)?.declaredLength, originalLength)
        IPPacket.setTotalLength(&untouched, UInt16(originalLength + 100))
        XCTAssertEqual(IPPacket.inspect(untouched)?.declaredLength, originalLength)
    }

    func testGenerateFragmentIdentifierIsInRange() {
        var seen = Set<UInt16>()
        for _ in 0 ..< 200 {
            seen.insert(IPPacket.generateIPv4FragmentIdentifier())
        }
        XCTAssertGreaterThan(seen.count, 100, "identifiers should vary")
    }

    func testMalformedPacketsAreRejectedWithoutCrashing() {
        let malformed: [Data] = [
            Data(),
            Data([0x00]),
            Data([0x45]),
            Data([0x45, 0x00, 0x00, 0x14]),
            Data(repeating: 0xFF, count: 20),
            hexData(PacketVectors.ipv4UDP).prefix(19),
            hexData(PacketVectors.ipv6UDP).prefix(39),
            // IPv4 header claiming a header longer than the packet: IHL is
            // fifteen words, so sixty bytes.
            hexData("4f0000140000400040110000c000020ac6336414"),
            // IPv4 header claiming an impossible IHL of zero words.
            hexData("400000140000400040110000c000020ac6336414"),
        ]
        for packet in malformed {
            XCTAssertNil(IPPacket.inspect(packet), "\(packet.count) bytes should not inspect")
            var copy = packet
            IPPacket.recomputeChecksums(&copy)
            XCTAssertBytesEqual(copy, packet, "a malformed packet must be left alone")
            IPPacket.setTotalLength(&copy, 100)
            XCTAssertBytesEqual(copy, packet, "a malformed packet must be left alone")
            XCTAssertFalse(IPPacket.hasValidChecksums(packet))
        }
    }

    /// A truncated transport header must not be checksummed, and must not crash.
    func testTruncatedTransportHeaderIsLeftAlone() {
        let packet = hexData(PacketVectors.ipv4UDP)
        let truncated = Data(packet.prefix(packet.count - 30))      // cut into the UDP payload
        var copy = truncated
        IPPacket.recomputeChecksums(&copy)

        // The IPv4 header checksum is still made consistent.
        var header = Array([UInt8](copy)[0 ..< 20])
        header[10] = 0
        header[11] = 0
        let bytes = [UInt8](copy)
        XCTAssertEqual(InternetChecksum.compute(header),
                       UInt16(bytes[10]) << 8 | UInt16(bytes[11]),
                       "the header checksum must be recomputed")

        // The packet is still parseable, and its declared length no longer fits
        // the buffer, which is what tells the engine to distrust it.
        XCTAssertNotNil(IPPacket.inspect(copy))
        XCTAssertNil(IPPacket.inspect(copy)?.declaredLength)
    }

    /// UDP carries an all-ones checksum where the sum comes to zero, because an
    /// all-zero checksum field means "not computed" in IPv4 and is illegal in
    /// IPv6. This packet is built so that the sum really is zero.
    func testUDPChecksumNeverBecomesZero() {
        // Source and destination 0.0.0.0 and zero ports, so the only
        // contributions to the sum are the protocol number, the two length
        // words and the payload. With a 0xFFDA payload the sum is exactly
        // 0xFFFF, which ones-complement arithmetic calls zero.
        let udp: [UInt8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0xFF, 0xDA]
        let pseudoHeader: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x11, 0x00, 0x0A]

        XCTAssertEqual(InternetChecksum.compute(pseudoHeader + udp), 0x0000,
                       "the fixture's sum must be zero")

        var packet: [UInt8] = [0x45, 0x00, 0x00, 0x1E, 0x00, 0x00, 0x40, 0x00,
                               0x40, 0x11, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]
        packet += udp
        var data = Data(packet)
        IPPacket.recomputeChecksums(&data)

        let bytes = [UInt8](data)
        let checksum = UInt16(bytes[26]) << 8 | UInt16(bytes[27])
        XCTAssertEqual(checksum, 0xFFFF, "a zero UDP checksum must be sent as all ones")
        XCTAssertTrue(IPPacket.hasValidChecksums(data))

        // The same packet with the checksum field forced to zero is still
        // "valid" for IPv4, because an all-zero UDP checksum is defined to mean
        // "not computed".
        var zeroed = data
        zeroed[26] = 0
        zeroed[27] = 0
        XCTAssertTrue(IPPacket.hasValidChecksums(zeroed))
    }
}
