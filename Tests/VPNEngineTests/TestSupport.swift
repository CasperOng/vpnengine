//
//  TestSupport.swift
//  VPNEngineTests
//
//  Small helpers shared by the test suite: hex conversion, byte comparisons
//  that print something readable on failure, and an async polling helper for
//  the session tests.
//

import Foundation
import XCTest

/// Decodes a hex string into bytes, failing the test on malformed input.
///
/// - Parameters:
///   - text: Hex digits, no separators.
///   - file: The calling file (for failure reporting).
///   - line: The calling line (for failure reporting).
/// - Returns: The decoded bytes.
func hexBytes(_ text: String,
              file: StaticString = #filePath,
              line: UInt = #line) -> [UInt8] {
    guard text.count % 2 == 0 else {
        XCTFail("hex string has an odd number of digits: \(text)", file: file, line: line)
        return []
    }
    var out = [UInt8]()
    out.reserveCapacity(text.count / 2)
    var index = text.startIndex
    while index < text.endIndex {
        let next = text.index(index, offsetBy: 2)
        guard let byte = UInt8(text[index ..< next], radix: 16) else {
            XCTFail("hex string is not valid hex: \(text)", file: file, line: line)
            return []
        }
        out.append(byte)
        index = next
    }
    return out
}

/// Decodes a hex string into `Data`.
///
/// - Parameters:
///   - text: Hex digits, no separators.
///   - file: The calling file (for failure reporting).
///   - line: The calling line (for failure reporting).
/// - Returns: The decoded bytes.
func hexData(_ text: String,
             file: StaticString = #filePath,
             line: UInt = #line) -> Data {
    Data(hexBytes(text, file: file, line: line))
}

/// Lower-case hex for a byte array.
///
/// - Parameter bytes: The bytes to encode.
/// - Returns: The hex string.
func hexString(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

/// Lower-case hex for `Data`.
///
/// - Parameter data: The bytes to encode.
/// - Returns: The hex string.
func hexString(_ data: Data) -> String {
    hexString([UInt8](data))
}

extension Data {
    /// Lower-case hex for the receiver.
    var hexString: String { VPNEngineTests.hexString(self) }

    /// Creates `Data` from a hex string, failing the test on malformed input.
    ///
    /// - Parameters:
    ///   - hex: Hex digits, no separators.
    ///   - file: The calling file (for failure reporting).
    ///   - line: The calling line (for failure reporting).
    init(testHex hex: String,
         file: StaticString = #filePath,
         line: UInt = #line) {
        self = hexData(hex, file: file, line: line)
    }
}

/// Asserts that a byte array equals the expected hex string.
///
/// Hex comparisons are used instead of `XCTAssertEqual` on byte arrays so that
/// a failure message is legible without dumping decimal arrays.
///
/// - Parameters:
///   - actual: The value produced by the code under test.
///   - expectedHex: The expected value, hex encoded.
///   - message: Extra context for the failure.
///   - file: The calling file (for failure reporting).
///   - line: The calling line (for failure reporting).
func XCTAssertHexEqual(_ actual: [UInt8],
                       _ expectedHex: String,
                       _ message: String = "",
                       file: StaticString = #filePath,
                       line: UInt = #line) {
    let actualHex = hexString(actual)
    if actualHex != expectedHex.lowercased() {
        let prefix = message.isEmpty ? "" : "\(message): "
        XCTFail("\(prefix)expected \(expectedHex.lowercased())\n"
                + "               got \(actualHex)", file: file, line: line)
    }
}

/// Asserts that two `Data` values have identical bytes.
///
/// - Parameters:
///   - actual: The value produced by the code under test.
///   - expected: The expected value.
///   - message: Extra context for the failure.
///   - file: The calling file (for failure reporting).
///   - line: The calling line (for failure reporting).
func XCTAssertBytesEqual(_ actual: Data,
                         _ expected: Data,
                         _ message: String = "",
                         file: StaticString = #filePath,
                         line: UInt = #line) {
    XCTAssertHexEqual([UInt8](actual), hexString(expected), message, file: file, line: line)
}

/// Polls a condition until it becomes true or the timeout elapses.
///
/// Used by the session tests, which must wait for asynchronous handshakes and
/// timer driven traffic.
///
/// - Parameters:
///   - timeout: How long to keep polling, in seconds.
///   - pollInterval: How long to sleep between checks.
///   - condition: The condition to poll.
/// - Returns: `true` if the condition became true before the deadline.
func waitUntil(timeout: TimeInterval = 5,
               pollInterval: Duration = .milliseconds(10),
               _ condition: @Sendable () async -> Bool) async -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if await condition() { return true }
        try? await Task.sleep(for: pollInterval)
    }
    return await condition()
}

/// A thread-safe byte counter used to observe callbacks from the session.
final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: Int = 0

    /// The current value.
    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    /// Adds one to the counter.
    func increment() {
        lock.lock()
        storage += 1
        lock.unlock()
    }
}

/// A thread-safe collector for values handed to a callback.
final class Collector<Element>: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [Element] = []

    /// A snapshot of everything collected so far.
    var values: [Element] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    /// The number of collected values.
    var count: Int { values.count }

    /// Appends a value.
    ///
    /// - Parameter value: The value to collect.
    func append(_ value: Element) {
        lock.lock()
        storage.append(value)
        lock.unlock()
    }
}
