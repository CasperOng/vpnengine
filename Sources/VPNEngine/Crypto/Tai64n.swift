//
//  Tai64n.swift
//  VPNEngine
//
//  TAI64N timestamps, used by the WireGuard handshake initiation message
//  (whitepaper, section 5.1) to provide replay protection in the absence of a
//  protocol cookie.
//
//  A TAI64N value is twelve bytes: an eight byte big endian 64 bit count of
//  TAI seconds followed by a four byte big endian nanosecond count. TAI is
//  ahead of UTC by the offset 2^62 + 10 in the TAI64 encoding, which is where
//  the constant ``Tai64n/taiOffset`` comes from.
//

import Foundation

/// TAI64N timestamps (twelve bytes, big endian).
public enum Tai64n {

    /// Size of a TAI64N timestamp in bytes.
    public static let timestampSize = 12

    /// The TAI64 offset for Unix epoch seconds: 2^62 + 10.
    ///
    /// TAI64 counts seconds from 1970-01-01 00:00:00 TAI; at the Unix epoch the
    /// value is 2^62 + 10 because of the ten second difference between TAI and
    /// UTC at that instant.
    public static let taiOffset: UInt64 = 4_611_686_018_427_387_914

    /// Builds a timestamp from raw counters.
    ///
    /// - Parameters:
    ///   - seconds: Unix epoch seconds (not TAI seconds).
    ///   - nanoseconds: Sub-second nanoseconds, 0...999_999_999.
    /// - Returns: Twelve bytes: `(seconds + taiOffset)` big endian 64 bit,
    ///   then `nanoseconds` big endian 32 bit.
    public static func timestamp(seconds: UInt64, nanoseconds: UInt32) -> [UInt8] {
        let taiSeconds = seconds &+ taiOffset
        var out = [UInt8](repeating: 0, count: timestampSize)
        for i in 0 ..< 8 {
            out[7 - i] = UInt8(truncatingIfNeeded: taiSeconds >> (8 * i))
        }
        for i in 0 ..< 4 {
            out[8 + (3 - i)] = UInt8(truncatingIfNeeded: nanoseconds >> (8 * i))
        }
        return out
    }

    /// Builds a timestamp for a point in time.
    ///
    /// - Parameter date: The point in time.
    /// - Returns: Twelve bytes of TAI64N.
    public static func timestamp(for date: Date) -> [UInt8] {
        let interval = date.timeIntervalSince1970
        let clamped = interval < 0 ? 0 : interval
        let seconds = UInt64(clamped)
        let nanoseconds = UInt32(((clamped - Double(seconds)) * 1_000_000_000).rounded())
        return timestamp(seconds: seconds, nanoseconds: Swift.min(nanoseconds, 999_999_999))
    }

    /// The current time as a TAI64N timestamp.
    ///
    /// Uses `CLOCK_REALTIME` where available so that the nanosecond field is
    /// genuine rather than inferred from floating point seconds.
    ///
    /// - Returns: Twelve bytes of TAI64N.
    public static func now() -> [UInt8] {
        #if canImport(Darwin) || canImport(Glibc)
        var time = timespec()
        if clock_gettime(CLOCK_REALTIME, &time) == 0, time.tv_sec >= 0 {
            let nanoseconds = time.tv_nsec < 0 ? 0 : UInt32(clamping: time.tv_nsec)
            return timestamp(seconds: UInt64(time.tv_sec), nanoseconds: nanoseconds)
        }
        #endif
        return timestamp(for: Date())
    }

    /// Decodes a TAI64N timestamp for comparison against another one.
    ///
    /// WireGuard only ever compares timestamps for ordering, so the decoded
    /// representable set is kept simple: TAI seconds (without the offset) and
    /// nanoseconds.
    ///
    /// - Parameter timestamp: Twelve bytes of TAI64N.
    /// - Returns: `(seconds, nanoseconds)` or `nil` when the input is not
    ///   exactly twelve bytes.
    public static func decode(_ timestamp: [UInt8]) -> (seconds: UInt64, nanoseconds: UInt32)? {
        guard timestamp.count == timestampSize else { return nil }
        var taiSeconds: UInt64 = 0
        for i in 0 ..< 8 {
            taiSeconds = (taiSeconds << 8) | UInt64(timestamp[i])
        }
        var nanoseconds: UInt32 = 0
        for i in 8 ..< 12 {
            nanoseconds = (nanoseconds << 8) | UInt32(timestamp[i])
        }
        return (taiSeconds >= taiOffset ? taiSeconds - taiOffset : 0, nanoseconds)
    }

    /// Orders two TAI64N timestamps.
    ///
    /// The canonical encoding was designed so that byte order equals time
    /// order, so this is a plain big endian comparison over twelve bytes.
    ///
    /// - Parameters:
    ///   - lhs: A timestamp.
    ///   - rhs: Another timestamp.
    /// - Returns: `true` when `lhs` is strictly later than `rhs`.
    public static func isLater(_ lhs: [UInt8], than rhs: [UInt8]) -> Bool {
        guard lhs.count == timestampSize, rhs.count == timestampSize else { return false }
        for i in 0 ..< timestampSize {
            if lhs[i] != rhs[i] { return lhs[i] > rhs[i] }
        }
        return false
    }
}
