//
//  InternetChecksum.swift
//  VPNEngine
//
//  The internet checksum of RFC 1071.
//
//  WireGuard hands IP packets between the tunnel and the operating system, and
//  the two sides disagree about who has already filled in which checksum, so
//  the engine recomputes them explicitly rather than assuming. This is the
//  arithmetic those computations are built on.
//
//  The sum is a one's complement sum of 16 bit words with the carries folded
//  back in, so it is endianness independent as long as the bytes are paired the
//  same way they appear on the wire.
//

import Foundation

/// An RFC 1071 one's complement checksum accumulator.
///
/// The accumulator can be fed several buffers in sequence, which is how the
/// transport checksums are built from an IP pseudo-header followed by the
/// transport header and payload.
public struct InternetChecksum: Sendable, Equatable {

    /// The running sum. Held in 64 bits so that a listener can add many words
    /// without folding after every one.
    private var sum: UInt64 = 0

    /// A byte whose partner has not been seen yet, if the last chunk ended on
    /// an odd boundary.
    private var pendingByte: UInt8?

    /// Creates an empty accumulator.
    public init() {}

    /// Adds bytes to the accumulator.
    ///
    /// Odd length chunks are handled correctly across calls: the dangling byte
    /// is remembered and paired with the first byte of the next chunk, exactly
    /// as if the two chunks had been concatenated first.
    ///
    /// - Parameter bytes: The next chunk of data.
    public mutating func add<C: Collection>(_ bytes: C) where C.Element == UInt8 {
        var high: UInt32 = 0
        var expectingSecond = false

        if let pending = pendingByte {
            high = UInt32(pending) << 8
            expectingSecond = true
            pendingByte = nil
        }

        for byte in bytes {
            if expectingSecond {
                sum &+= UInt64(high | UInt32(byte))
                expectingSecond = false
            } else {
                high = UInt32(byte) << 8
                expectingSecond = true
            }
        }

        if expectingSecond {
            pendingByte = UInt8(truncatingIfNeeded: high >> 8)
        }
    }

    /// The finished checksum.
    ///
    /// - Returns: The one's complement of the folded sum. Following the RFC, a
    ///   computed value of zero is a valid checksum; TCP and UDP have their own
    ///   rules about transmitting it as `0xFFFF` and those are applied by
    ///   ``IPPacket``.
    public func value() -> UInt16 {
        var folded = sum
        if let pending = pendingByte {
            folded &+= UInt64(pending) << 8
        }
        while folded >> 16 != 0 {
            folded = (folded & 0xFFFF) &+ (folded >> 16)
        }
        return UInt16(truncatingIfNeeded: ~folded)
    }

    /// Computes the checksum of a single buffer.
    ///
    /// - Parameter bytes: The data to sum.
    /// - Returns: The RFC 1071 checksum.
    public static func compute<C: Collection>(_ bytes: C) -> UInt16 where C.Element == UInt8 {
        var accumulator = InternetChecksum()
        accumulator.add(bytes)
        return accumulator.value()
    }

    /// Computes the checksum of a single buffer.
    ///
    /// - Parameter data: The data to sum.
    /// - Returns: The RFC 1071 checksum.
    public static func compute(_ data: Data) -> UInt16 {
        compute([UInt8](data))
    }
}
