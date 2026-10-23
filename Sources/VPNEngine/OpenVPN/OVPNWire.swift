import Foundation
#if canImport(Security)
import Security
#endif

/// Small wire-format helpers shared by the OpenVPN codecs.
///
/// OpenVPN writes every multi-byte integer in network byte order (big endian)
/// and every length prefix as a single byte, so these helpers are used instead
/// of `withUnsafeBytes`/`loadUnaligned` at each call site: they always bounds
/// check and always throw instead of trapping.
enum OVPNWire {

    /// Read a big-endian `UInt16` at `offset`.
    static func readUInt16(_ data: Data, at offset: Int, field: String) throws -> UInt16 {
        guard offset >= 0, data.count >= offset + 2 else {
            throw OVPNError.packetTooShort(field: field, need: offset + 2, have: data.count)
        }
        let base = data.startIndex + offset
        return UInt16(data[base]) << 8 | UInt16(data[base + 1])
    }

    /// Read a big-endian `UInt32` at `offset`.
    static func readUInt32(_ data: Data, at offset: Int, field: String) throws -> UInt32 {
        guard offset >= 0, data.count >= offset + 4 else {
            throw OVPNError.packetTooShort(field: field, need: offset + 4, have: data.count)
        }
        let base = data.startIndex + offset
        return UInt32(data[base]) << 24
            | UInt32(data[base + 1]) << 16
            | UInt32(data[base + 2]) << 8
            | UInt32(data[base + 3])
    }

    /// Read a big-endian `UInt32` ending at `end` (i.e. at `end - 4`).
    static func readUInt32(_ data: Data, endingAt end: Int, field: String) throws -> UInt32 {
        try readUInt32(data, at: end - 4, field: field)
    }

    /// Read a fixed-size field, bounds checked.
    static func readBytes(_ data: Data, at offset: Int, count: Int, field: String) throws -> Data {
        guard offset >= 0, count >= 0, data.count >= offset + count else {
            throw OVPNError.packetTooShort(field: field, need: offset + count, have: data.count)
        }
        let start = data.startIndex + offset
        return data[start..<(start + count)]
    }

    /// Read the remaining bytes after `offset`.
    static func readRemainder(_ data: Data, after offset: Int, field: String) throws -> Data {
        guard offset >= 0, offset <= data.count else {
            throw OVPNError.packetTooShort(field: field, need: offset, have: data.count)
        }
        return data[(data.startIndex + offset)...]
    }

    /// Append `value` as a big-endian `UInt32`.
    static func append(_ value: UInt32, to data: inout Data) {
        data.append(UInt8(truncatingIfNeeded: value >> 24))
        data.append(UInt8(truncatingIfNeeded: value >> 16))
        data.append(UInt8(truncatingIfNeeded: value >> 8))
        data.append(UInt8(truncatingIfNeeded: value))
    }

    /// Big-endian `UInt32` bytes.
    static func bytes(_ value: UInt32) -> Data {
        var out = Data()
        append(value, to: &out)
        return out
    }

    /// Compare two byte strings without leaking the position of the first
    /// differing byte through timing.
    static func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for index in 0..<lhs.count {
            difference |= lhs[lhs.startIndex + index] ^ rhs[rhs.startIndex + index]
        }
        return difference == 0
    }

    /// Cryptographically secure random bytes (`SecRandomCopyBytes` when the
    /// Security framework is available, `SystemRandomNumberGenerator`
    /// otherwise). Used for IVs and session ids.
    static func randomBytes(_ count: Int) -> Data {
        guard count > 0 else { return Data() }
        #if canImport(Security)
        var secure = Data(count: count)
        let status = secure.withUnsafeMutableBytes { buffer -> Int32 in
            guard let base = buffer.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        if status == errSecSuccess { return secure }
        #endif
        // `#if` regions share the enclosing scope in Swift, so the fallback
        // below deliberately uses a different variable name.
        var generator = SystemRandomNumberGenerator()
        var fallback = Data()
        fallback.reserveCapacity(count)
        for _ in 0..<count {
            fallback.append(UInt8.random(in: .min ... .max, using: &generator))
        }
        return fallback
    }

    /// Parse a hexadecimal string (whitespace already removed, even length).
    static func decodeHex(_ text: String) -> Data? {
        let scalars = Array(text.unicodeScalars)
        guard scalars.count % 2 == 0 else { return nil }
        var out = Data()
        out.reserveCapacity(scalars.count / 2)
        var index = 0
        while index < scalars.count {
            guard let high = hexNibble(scalars[index]), let low = hexNibble(scalars[index + 1]) else {
                return nil
            }
            out.append(high << 4 | low)
            index += 2
        }
        return out
    }

    /// Lower-case hexadecimal for a byte string.
    static func encodeHex(_ data: Data) -> String {
        var out = String()
        out.reserveCapacity(data.count * 2)
        for byte in data {
            out.append(hexDigits[Int(byte >> 4)])
            out.append(hexDigits[Int(byte & 0x0F)])
        }
        return out
    }

    private static let hexDigits = Array("0123456789abcdef")

    private static func hexNibble(_ scalar: Unicode.Scalar) -> UInt8? {
        switch scalar {
        case "0"..."9": return UInt8(scalar.value - 48)
        case "a"..."f": return UInt8(scalar.value - 87)
        case "A"..."F": return UInt8(scalar.value - 55)
        default: return nil
        }
    }
}
