//
//  TailscaleHTTPUpgrade.swift
//  VPNEngine
//
//  The HTTP/1.1 `Upgrade` dance that turns a TCP (or TLS) connection to a
//  Tailscale or Headscale login server into a raw byte stream carrying the
//  Noise control protocol.
//
//  `URLSession` cannot do this: an `Upgrade: …` request that is answered with
//  `101 Switching Protocols` hands the connection over to the caller, and
//  `URLSession` has no API for taking it. So the connection is opened here with
//  `NWConnection` and the HTTP exchange is written by hand.
//
//  The one thing that is genuinely easy to get wrong — and the reason this type
//  owns a buffer rather than handing a socket straight back — is that the
//  server's first Noise bytes usually arrive in the *same TCP segment* as the
//  response headers. A reader that consumes the headers with a single
//  `receive` and discards the rest of the buffer loses the beginning of the
//  Noise stream, which shows up much later as a mysterious handshake failure.
//  Here the header block is read until its terminating empty line, everything
//  after it is kept, and ``read()`` drains that kept bytes first, so the caller
//  sees an uninterrupted stream.
//
//  References:
//   * `control/controlhttp/client.go` in https://github.com/tailscale/tailscale
//     (BSD-3-Clause), particularly `tryURLUpgrade`
//   * RFC 9112, sections 2.2 (message format) and 5 (field syntax)
//

import Foundation
import Network

#if canImport(Security)
import Security
#endif

/// A bidirectional byte stream: the interface the control transport needs, and
/// the seam that lets it be driven from memory in a test.
public protocol TailscaleByteStream: AnyObject, Sendable {

    /// Writes bytes to the peer.
    ///
    /// - Parameter data: The bytes to write.
    /// - Throws: A ``TailscaleControlError`` when the stream is broken.
    func write(_ data: Data) async throws

    /// Reads whatever bytes are available next.
    ///
    /// - Throws: A ``TailscaleControlError`` when the stream is broken.
    /// - Returns: The bytes, or `nil` at end of stream.
    func read() async throws -> Data?

    /// Closes the stream. Safe to call more than once.
    func close() async
}

/// A parsed HTTP response status line and header block.
public struct TailscaleHTTPResponseHead: Sendable, Equatable {

    /// The three digit status code.
    public let status: Int

    /// The reason phrase, which may be empty.
    public let reason: String

    /// The header fields, with lowercased names.
    ///
    /// Duplicate names are joined with a comma, as RFC 9110 section 5.2 allows
    /// for the field values that appear more than once.
    public let headers: [String: String]

    /// The raw status line and header block, terminator included, for logging
    /// and tests.
    public let raw: Data

    /// Looks up a header field.
    ///
    /// - Parameter name: The field name, in any case.
    /// - Returns: The value, or `nil` when the field is absent.
    public func header(_ name: String) -> String? {
        headers[name.lowercased()]
    }

    /// The result of parsing a header block out of a buffer.
    public struct ParseResult: Sendable {

        /// The parsed status line and headers.
        public let head: TailscaleHTTPResponseHead

        /// The bytes that followed the terminating empty line: the start of the
        /// response body, or of whatever protocol the upgrade switched to.
        public let leftover: Data
    }

    /// Parses an HTTP response head out of a buffer.
    ///
    /// Accepts `\r\n` and bare `\n` line endings, matches field names
    /// case-insensitively, and unfolds obsolete line folding (a continuation
    /// line beginning with a space or a horizontal tab, RFC 9112 section 5.2)
    /// onto the preceding field.
    ///
    /// - Parameter buffer: The bytes read so far.
    /// - Throws: ``TailscaleControlError/invalidUpgradeResponse(_:)`` when the
    ///   status line is not a valid HTTP response line.
    /// - Returns: The head and the bytes after it, or `nil` when the
    ///   terminating empty line has not arrived yet.
    public static func parse(_ buffer: Data) throws -> ParseResult? {
        let bytes = [UInt8](buffer)

        var lines: [String] = []
        var lineStart = 0
        var cursor = 0
        var endOfHead: Int?
        while cursor < bytes.count {
            if bytes[cursor] == 0x0A {
                var end = cursor
                if end > lineStart, bytes[end - 1] == 0x0D { end -= 1 }
                let line = String(decoding: bytes[lineStart ..< end], as: UTF8.self)
                if line.isEmpty {
                    endOfHead = cursor + 1
                    break
                }
                lines.append(line)
                lineStart = cursor + 1
            }
            cursor += 1
        }

        guard let endOfHead, let statusLine = lines.first else { return nil }

        let statusParts = statusLine.split(separator: " ", maxSplits: 2,
                                           omittingEmptySubsequences: false)
        guard statusParts.count >= 2,
              statusParts[0].hasPrefix("HTTP/"),
              let status = Int(statusParts[1]) else {
            throw TailscaleControlError.invalidUpgradeResponse(
                "not an HTTP response line: \(statusLine.prefix(120))")
        }
        let reason = statusParts.count >= 3 ? String(statusParts[2]) : ""

        var headers: [String: String] = [:]
        var currentName: String?
        for line in lines.dropFirst() {
            if let first = line.utf8.first, first == 0x20 || first == 0x09 {
                // Obsolete line folding: append to the previous field's value.
                guard let name = currentName else { continue }
                let continuation = line.trimmingCharacters(in: .whitespaces)
                headers[name] = (headers[name].map { $0 + " " } ?? "") + continuation
                continue
            }
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[line.startIndex ..< colon]
                .trimmingCharacters(in: .whitespaces)
                .lowercased()
            let value = line[line.index(after: colon)...]
                .trimmingCharacters(in: .whitespaces)
            guard !name.isEmpty else { continue }
            if let existing = headers[name] {
                headers[name] = existing + ", " + value
            } else {
                headers[name] = value
            }
            currentName = name
        }

        let head = TailscaleHTTPResponseHead(status: status,
                                             reason: reason,
                                             headers: headers,
                                             raw: Data(bytes[0 ..< endOfHead]))
        return ParseResult(head: head, leftover: Data(bytes[endOfHead...]))
    }
}

/// An `NWConnection` exposed as a ``TailscaleByteStream``.
///
/// `NWConnection` is asynchronous, delivers its callbacks on a queue of its
/// own, and is not `Sendable`; this wrapper gives it the two `async` methods
/// the transport wants and serialises nothing else.
public final class NWConnectionByteStream: TailscaleByteStream, @unchecked Sendable {

    /// The connection this stream reads and writes.
    public let connection: NWConnection

    /// The queue `NWConnection` delivers its callbacks on.
    private let queue: DispatchQueue

    /// Closes the stream exactly once, and lets ``read()`` report a clean end
    /// rather than an error when the close was ours.
    private let state = State()

    /// Mutable state shared between the caller's tasks and the connection's
    /// callbacks.
    private final class State: @unchecked Sendable {
        private let lock = NSLock()
        private var closed = false

        func markClosed() -> Bool {
            lock.lock()
            defer { lock.unlock() }
            let wasClosed = closed
            closed = true
            return !wasClosed
        }

        var isClosed: Bool {
            lock.lock()
            defer { lock.unlock() }
            return closed
        }
    }

    /// Wraps a connection that is already `ready`.
    ///
    /// - Parameters:
    ///   - connection: The connection.
    ///   - queue: The queue the connection was started on.
    public init(connection: NWConnection, queue: DispatchQueue) {
        self.connection = connection
        self.queue = queue
    }

    /// Writes bytes, failing with a typed error if the connection is broken.
    ///
    /// - Parameter data: The bytes to write.
    /// - Throws: ``TailscaleControlError/transportFailed(_:)``.
    public func write(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: TailscaleControlError.transportFailed(
                        "write failed: \(error.localizedDescription)"))
                } else {
                    continuation.resume()
                }
            })
        }
    }

    /// Reads the next chunk of bytes.
    ///
    /// - Throws: ``TailscaleControlError/transportFailed(_:)`` when the
    ///   connection fails, or ``TailscaleControlError/streamClosed`` when it
    ///   ended.
    /// - Returns: The bytes, or `nil` at end of stream.
    public func read() async throws -> Data? {
        while true {
            if state.isClosed { return nil }
            let (data, isComplete, error) = await receiveOnce()
            if let error {
                if state.isClosed { return nil }
                throw TailscaleControlError.transportFailed(error.localizedDescription)
            }
            if let data, !data.isEmpty { return data }
            if isComplete { return nil }
            // A receive can complete with nothing at all when the connection
            // was cancelled between calls; go round again rather than
            // reporting a spurious zero byte read.
        }
    }

    /// Closes the connection.
    public func close() async {
        guard state.markClosed() else { return }
        connection.cancel()
    }

    /// One `NWConnection.receive`, as an `async` call.
    ///
    /// - Returns: The bytes, whether the stream ended, and any error.
    private func receiveOnce() async -> (Data?, Bool, Error?) {
        await withCheckedContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1,
                               maximumLength: 64 * 1024) { data, _, isComplete, error in
                continuation.resume(returning: (data, isComplete, error))
            }
        }
    }
}

/// Opens a connection to a login server, performs the HTTP upgrade, and hands
/// back the raw stream positioned immediately after the response headers.
public final class TailscaleHTTPUpgrade: TailscaleByteStream, @unchecked Sendable {

    /// The parsed `101 Switching Protocols` response.
    public let response: TailscaleHTTPResponseHead

    /// The connection, positioned after the response head.
    private let stream: TailscaleByteStream

    /// Bytes that arrived with the response head and belong to the protocol
    /// that follows it. Drained by ``read()`` before the stream is touched.
    private var leftover: Data

    /// The lock that guards ``leftover``.
    private let lock = NSLock()

    /// Creates an upgrade from an already-open stream and a parsed response.
    ///
    /// - Parameters:
    ///   - stream: The stream, positioned after the response head.
    ///   - response: The parsed response head.
    ///   - leftover: Bytes that arrived after the response head.
    init(stream: TailscaleByteStream,
         response: TailscaleHTTPResponseHead,
         leftover: Data) {
        self.stream = stream
        self.response = response
        self.leftover = leftover
    }

    // MARK: - Connecting

    /// Opens a TCP or TLS connection to `host:port`, writes `request`, and
    /// reads the response head.
    ///
    /// - Parameters:
    ///   - host: The host name or address to connect to.
    ///   - port: The port.
    ///   - useTLS: Whether to wrap the connection in TLS. Headscale is normally
    ///     reached over HTTPS with a self-signed or private CA, so callers that
    ///     use TLS usually also pass `tlsTrust`.
    ///   - request: The complete request bytes, head and body.
    ///   - tlsTrust: Called with the server's `SecTrust` when TLS is in use.
    ///     Returning `true` accepts the certificate. When `nil`, the platform's
    ///     default verification applies.
    ///   - timeout: How long to wait for the connection and the response head.
    ///   - log: A logger that never receives key material.
    /// - Throws: ``TailscaleControlError`` when the connection fails, the
    ///   response is not `101 Switching Protocols`, or the response head cannot
    ///   be parsed.
    /// - Returns: The upgrade, positioned after the response head.
    public static func connect(host: String,
                               port: UInt16,
                               useTLS: Bool,
                               request: Data,
                               tlsTrust: ((SecTrust) -> Bool)? = nil,
                               timeout: TimeInterval = 10,
                               log: @escaping @Sendable (String) -> Void = { _ in }) async throws -> TailscaleHTTPUpgrade {
        guard let networkPort = NWEndpoint.Port(rawValue: port) else {
            throw TailscaleControlError.upgradeFailed("invalid port \(port)")
        }

        let queue = DispatchQueue(label: "com.vpnengine.tailscale.upgrade")
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.connectionTimeout = Int(timeout.rounded(.up))

        let parameters: NWParameters
        if useTLS {
            let tls = NWProtocolTLS.Options()
            #if canImport(Security)
            if let tlsTrust {
                sec_protocol_options_set_verify_block(tls.securityProtocolOptions,
                                                      { _, trust, complete in
                    #if swift(>=5.9)
                    let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
                    #else
                    let secTrust = unsafeBitCast(trust, to: SecTrust.self)
                    #endif
                    complete(tlsTrust(secTrust))
                }, queue)
            }
            #endif
            sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, "http/1.1")
            parameters = NWParameters(tls: tls, tcp: tcp)
        } else {
            parameters = NWParameters(tls: nil, tcp: tcp)
        }

        let connection = NWConnection(host: NWEndpoint.Host(host),
                                      port: networkPort,
                                      using: parameters)
        let stream = NWConnectionByteStream(connection: connection, queue: queue)

        do {
            try await start(connection, queue: queue, timeout: timeout)
            try await stream.write(request)
            let (head, leftover) = try await readResponseHead(from: stream, timeout: timeout)
            log("tailscale: upgrade response \(head.status) \(head.reason)")
            guard head.status == 101 else {
                await stream.close()
                throw TailscaleControlError.upgradeRejected(status: head.status, reason: head.reason)
            }
            if let upgraded = head.header("upgrade"), upgraded != TS2021.upgradeHeaderValue {
                log("tailscale: server switched to unexpected protocol \(upgraded)")
            }
            return TailscaleHTTPUpgrade(stream: stream, response: head, leftover: leftover)
        } catch {
            await stream.close()
            throw error
        }
    }

    /// Starts a connection and waits for it to become ready.
    ///
    /// - Parameters:
    ///   - connection: The connection to start.
    ///   - queue: The queue for its state callbacks.
    ///   - timeout: How long to wait for `.ready`.
    /// - Throws: ``TailscaleControlError/upgradeFailed(_:)`` on failure or
    ///   timeout.
    private static func start(_ connection: NWConnection,
                              queue: DispatchQueue,
                              timeout: TimeInterval) async throws {
        let gate = ResumeGate()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    gate.resumeOnce { continuation.resume() }
                case .failed(let error):
                    gate.resumeOnce {
                        continuation.resume(throwing: TailscaleControlError.upgradeFailed(
                            "connection failed: \(error.localizedDescription)"))
                    }
                case .cancelled:
                    gate.resumeOnce {
                        continuation.resume(throwing: TailscaleControlError.upgradeFailed(
                            "connection was cancelled before it was ready"))
                    }
                case .setup, .preparing, .waiting:
                    break
                @unknown default:
                    break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) {
                gate.resumeOnce {
                    connection.cancel()
                    continuation.resume(throwing: TailscaleControlError.upgradeFailed(
                        "timed out waiting for the connection to become ready"))
                }
            }
        }
    }

    /// Reads until the response head is complete.
    ///
    /// - Parameters:
    ///   - stream: The connection.
    ///   - timeout: How long to wait.
    /// - Throws: ``TailscaleControlError`` when the stream ends or the head is
    ///   malformed.
    /// - Returns: The parsed head and the bytes that followed it.
    private static func readResponseHead(from stream: TailscaleByteStream,
                                         timeout: TimeInterval) async throws -> (TailscaleHTTPResponseHead, Data) {
        var buffer = Data()
        let deadline = Date().addingTimeInterval(timeout)
        while true {
            if let parsed = try TailscaleHTTPResponseHead.parse(buffer) {
                return (parsed.head, parsed.leftover)
            }
            guard Date() < deadline else {
                throw TailscaleControlError.upgradeFailed(
                    "timed out waiting for the upgrade response headers")
            }
            guard let chunk = try await stream.read() else {
                throw TailscaleControlError.upgradeFailed(
                    "the server closed the connection before sending a complete response head")
            }
            buffer.append(chunk)
            guard buffer.count <= 64 * 1024 else {
                throw TailscaleControlError.invalidUpgradeResponse("the response head is implausibly large")
            }
        }
    }

    // MARK: - Byte stream

    /// Writes bytes to the connection.
    ///
    /// - Parameter data: The bytes.
    /// - Throws: A ``TailscaleControlError`` when the connection is broken.
    public func write(_ data: Data) async throws {
        try await stream.write(data)
    }

    /// Reads the next bytes, draining the buffer that arrived with the response
    /// head first.
    ///
    /// - Throws: A ``TailscaleControlError`` when the connection is broken.
    /// - Returns: The bytes, or `nil` at end of stream.
    public func read() async throws -> Data? {
        lock.lock()
        if !leftover.isEmpty {
            let buffered = leftover
            leftover = Data()
            lock.unlock()
            return buffered
        }
        lock.unlock()
        return try await stream.read()
    }

    /// Closes the connection.
    public func close() async {
        await stream.close()
    }

    /// The bytes that arrived with the response head and have not been read
    /// yet.
    ///
    /// Exposed so a test can assert that nothing was dropped.
    public var bufferedBytes: Data {
        lock.lock()
        defer { lock.unlock() }
        return leftover
    }
}

/// A one-shot continuation guard: lets several racing callbacks try to resume
/// the same continuation, and lets exactly the first one win.
///
/// `NWConnection` reports state changes and a timeout on different paths, and
/// resuming a continuation twice traps.
private final class ResumeGate: @unchecked Sendable {

    private let lock = NSLock()
    private var used = false

    /// Runs `body` unless a previous call already ran.
    ///
    /// - Parameter body: The work that resumes the continuation.
    func resumeOnce(_ body: () -> Void) {
        lock.lock()
        let alreadyUsed = used
        used = true
        lock.unlock()
        guard !alreadyUsed else { return }
        body()
    }
}
