import Foundation

/// Sliding-window replay protection for OpenVPN packet ids.
///
/// Implements `packet_id_test()`/`packet_id_add()` from
/// `src/openvpn/packet_id.c`:
///
/// * a packet id of `0` means "no packet id present" and is always accepted;
/// * ids ahead of the highest seen id advance the window;
/// * ids more than ``windowSize`` behind the highest seen id are rejected as
///   too old;
/// * ids inside the window that were already accepted are rejected as replays;
/// * an optional 32-bit timestamp (present when OpenVPN uses the *long form*
///   packet id) must not be older than the highest timestamp seen minus
///   ``timeBacktrack`` seconds.
///
/// This is a class because a codec value has to be able to enforce replays
/// from a non-mutating `decode` while staying `Sendable`.
public final class OVPNReplayWindow: @unchecked Sendable {

    /// Number of packet ids remembered behind the highest one (OpenVPN's
    /// `--replay-window`, default 64).
    public let windowSize: Int

    /// Seconds of timestamp backtracking allowed (`--replay-window n t`,
    /// default 15). `nil` disables the timestamp check.
    public let timeBacktrack: Int?

    private let lock = OVPNMutex()
    private var highest: UInt32?
    private var highestTimestamp: UInt32?
    /// `seen[0]` corresponds to `highest`, `seen[i]` to `highest - i`.
    private var seen: [Bool]

    /// Create a replay window.
    /// - Parameters:
    ///   - windowSize: how many packet ids to remember (clamped to 1...4096).
    ///   - timeBacktrack: allowed timestamp backtracking in seconds.
    public init(windowSize: Int = 64, timeBacktrack: Int? = 15) {
        self.windowSize = max(1, min(windowSize, 4096))
        self.timeBacktrack = timeBacktrack
        self.seen = Array(repeating: false, count: max(1, min(windowSize, 4096)))
    }

    /// The highest packet id accepted so far.
    public var highestSequence: UInt32? {
        lock.lock()
        defer { lock.unlock() }
        return highest
    }

    /// Reset the window (used when a key state is renegotiated).
    public func reset() {
        lock.lock()
        defer { lock.unlock() }
        highest = nil
        highestTimestamp = nil
        for index in seen.indices { seen[index] = false }
    }

    /// Validate `sequence` and, if it is fresh, mark it as seen.
    ///
    /// - Throws: ``OVPNError/replayDetected(id:)`` when the packet is a
    ///   duplicate or too old.
    public func testAndMark(sequence: UInt32, timestamp: UInt32? = nil) throws {
        lock.lock()
        defer { lock.unlock() }

        // A short-form packet id of 0 means "this packet has no packet id" and
        // is never replay protected (`packet_id_test` checks
        // `pin->id == 0 && pin->time == 0`). A long-form id of 0 with a real
        // timestamp *is* a packet id and is protected like any other.
        guard sequence != 0 || (timestamp ?? 0) != 0 else { return }

        if let timestamp, let timeBacktrack, let lastSeen = highestTimestamp {
            let delta = Int64(lastSeen) - Int64(timestamp)
            if delta > Int64(timeBacktrack) {
                throw OVPNError.replayDetected(id: sequence)
            }
            if timestamp > lastSeen { highestTimestamp = timestamp }
        } else if let timestamp, highestTimestamp == nil {
            highestTimestamp = timestamp
        }

        guard let currentHighest = highest else {
            highest = sequence
            seen[0] = true
            return
        }

        if sequence > currentHighest {
            let delta = Int(sequence - currentHighest)
            if delta >= windowSize {
                for index in seen.indices { seen[index] = false }
            } else {
                var index = seen.count - 1
                while index >= delta {
                    seen[index] = seen[index - delta]
                    index -= 1
                }
                for index in 0..<delta { seen[index] = false }
            }
            seen[0] = true
            highest = sequence
            return
        }

        let delta = Int(currentHighest - sequence)
        guard delta < windowSize else {
            throw OVPNError.replayDetected(id: sequence)
        }
        guard !seen[delta] else {
            throw OVPNError.replayDetected(id: sequence)
        }
        seen[delta] = true
    }
}
