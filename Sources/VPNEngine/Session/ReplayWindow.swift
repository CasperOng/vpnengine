//
//  ReplayWindow.swift
//  VPNEngine
//
//  Sliding window replay protection for transport data counters.
//
//  The whitepaper (section 5.4.6) requires the recipient of a transport data
//  message to keep "the greatest counter received, as well as a window of prior
//  messages received", and to apply it only after the AEAD tag has been
//  verified. UDP reorders packets, so a plain "must be greater than the last
//  one" rule would drop legitimately reordered traffic; a window accepts
//  reordering within its span while still refusing anything already seen.
//
//  Bit `i` of the bitset means "the counter `highest - i` has been received".
//

import Foundation

/// A replay protection window over 64 bit message counters.
public struct ReplayWindow: Sendable, Equatable {

    /// The default window size in messages.
    ///
    /// WireGuard's own implementations use a little over eight thousand; one
    /// thousand is plenty for the reordering a tunnel sees and keeps the
    /// structure small.
    public static let defaultSize = 1024

    /// How many counters the window spans.
    public let size: Int

    /// The greatest counter accepted so far.
    public private(set) var highest: UInt64 = 0

    /// Whether anything has been accepted yet.
    public private(set) var hasAcceptedAnything = false

    /// The bitmap of previously seen counters, bit 0 being `highest`.
    private var bits: [UInt64]

    /// Creates an empty window.
    ///
    /// - Parameter size: How many counters to remember. Values below one are
    ///   raised to one.
    public init(size: Int = ReplayWindow.defaultSize) {
        let clamped = Swift.max(1, size)
        self.size = clamped
        self.bits = [UInt64](repeating: 0, count: (clamped + 63) / 64)
    }

    /// Whether a counter would be accepted, without recording it.
    ///
    /// - Parameter counter: The counter to test.
    /// - Returns: `true` when the counter is new and inside the window.
    public func wouldAccept(_ counter: UInt64) -> Bool {
        guard hasAcceptedAnything else { return true }
        if counter > highest { return true }
        let distance = highest - counter
        guard distance < UInt64(bits.count * 64) else { return false }
        return !bit(at: Int(distance))
    }

    /// Records a counter.
    ///
    /// - Parameter counter: The counter to accept.
    /// - Returns: `true` when the counter is new and inside the window, in
    ///   which case it is now recorded; `false` when it is a replay or too far
    ///   behind to be judged.
    public mutating func accept(_ counter: UInt64) -> Bool {
        guard hasAcceptedAnything else {
            hasAcceptedAnything = true
            highest = counter
            setBit(at: 0)
            return true
        }

        if counter > highest {
            let distance = counter - highest
            if distance >= UInt64(bits.count * 64) {
                clear()
            } else {
                shift(by: distance)
            }
            highest = counter
            setBit(at: 0)
            return true
        }

        let distance = highest - counter
        guard distance < UInt64(bits.count * 64) else { return false }
        guard !bit(at: Int(distance)) else { return false }
        setBit(at: Int(distance))
        return true
    }

    /// Forgets every counter, as if newly created.
    public mutating func reset() {
        bits = [UInt64](repeating: 0, count: bits.count)
        highest = 0
        hasAcceptedAnything = false
    }

    // MARK: - Internals

    /// Reads a bit.
    ///
    /// - Parameter index: The bit index, 0 being `highest`.
    /// - Returns: Whether the bit is set.
    private func bit(at index: Int) -> Bool {
        let word = index / 64
        guard word >= 0, word < bits.count else { return false }
        return bits[word] & (UInt64(1) << UInt64(index % 64)) != 0
    }

    /// Sets a bit.
    ///
    /// - Parameter index: The bit index, 0 being `highest`.
    private mutating func setBit(at index: Int) {
        let word = index / 64
        guard word >= 0, word < bits.count else { return }
        bits[word] |= UInt64(1) << UInt64(index % 64)
    }

    /// Slides every bit towards higher indices.
    ///
    /// - Parameter distance: How far the window moves, less than its span.
    private mutating func shift(by distance: UInt64) {
        guard distance > 0 else { return }
        let wordShift = Int(distance / 64)
        let bitShift = Int(distance % 64)

        var shifted = [UInt64](repeating: 0, count: bits.count)
        for index in 0 ..< bits.count {
            let source = index - wordShift
            guard source >= 0 else { continue }
            var value = bits[source] << UInt64(bitShift)
            if bitShift > 0, source - 1 >= 0 {
                value |= bits[source - 1] >> UInt64(64 - bitShift)
            }
            shifted[index] = value
        }
        bits = shifted
    }

    /// Clears every bit.
    private mutating func clear() {
        for index in 0 ..< bits.count {
            bits[index] = 0
        }
    }
}
