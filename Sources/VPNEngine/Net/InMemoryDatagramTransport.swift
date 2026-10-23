//
//  InMemoryDatagramTransport.swift
//  VPNEngine
//
//  A datagram transport that delivers to another instance in the same process.
//
//  This exists so that two ``WireGuardSession`` instances can be wired together
//  and driven through a complete handshake and data exchange without a socket,
//  a network, or root privileges. It is also convenient for SwiftUI previews of
//  the tunnel UI.
//
//  Both ends of a pair must stay alive for the other to be able to send, which
//  is naturally the case when the sessions that own them do.
//

import Foundation

/// An in-process datagram transport.
///
/// Create a connected pair with ``pair(capacity:)`` and keep both ends alive.
public final class InMemoryDatagramTransport: DatagramTransport, @unchecked Sendable {

    /// The default number of datagrams a receive queue holds before the oldest
    /// is dropped, mirroring a UDP socket buffer.
    public static let defaultCapacity = 1024

    private let lock = NSLock()
    private let capacity: Int

    /// Datagrams that have arrived and not yet been received.
    private var inbox: [Data] = []

    /// Tasks parked in `receive()`, in arrival order.
    private var waiters: [CheckedContinuation<Data, Error>] = []

    private var isClosed = false
    private weak var peer: InMemoryDatagramTransport?
    private var sentDatagrams = 0
    private var receivedDatagrams = 0
    private var droppedDatagrams = 0

    private init(capacity: Int) {
        self.capacity = capacity
    }

    /// Creates two transports that are connected to each other.
    ///
    /// - Parameter capacity: How many undelivered datagrams each side buffers.
    /// - Returns: A connected pair: what either element sends, the other
    ///   element's ``receive()`` returns.
    public static func pair(capacity: Int = InMemoryDatagramTransport.defaultCapacity)
        -> (InMemoryDatagramTransport, InMemoryDatagramTransport) {
        let first = InMemoryDatagramTransport(capacity: capacity)
        let second = InMemoryDatagramTransport(capacity: capacity)
        first.peer = second
        second.peer = first
        return (first, second)
    }

    /// How many datagrams this transport has handed to its peer.
    public var sentCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return sentDatagrams
    }

    /// How many datagrams this transport has received.
    public var receivedCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return receivedDatagrams
    }

    /// How many datagrams were discarded because the queue was full.
    public var droppedCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return droppedDatagrams
    }

    /// Whether ``close()`` has been called.
    public var closed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return isClosed
    }

    // MARK: - DatagramTransport

    /// Delivers a datagram to the peer transport.
    ///
    /// - Parameter datagram: The bytes to send.
    /// - Throws: ``DatagramTransportError`` when this transport is closed or has
    ///   no peer.
    public func send(_ datagram: Data) async throws {
        let peer = try prepareSend()
        peer.deliver(datagram)
    }

    /// Checks that the transport can send, and returns its peer.
    ///
    /// Kept synchronous so that the lock is never taken directly from an
    /// asynchronous context.
    ///
    /// - Throws: ``DatagramTransportError`` when this transport is closed or has
    ///   no peer.
    /// - Returns: The transport to deliver to.
    private func prepareSend() throws -> InMemoryDatagramTransport {
        lock.lock()
        defer { lock.unlock() }
        guard !isClosed else {
            throw DatagramTransportError.closed
        }
        guard let peer else {
            throw DatagramTransportError.noPeer
        }
        sentDatagrams += 1
        return peer
    }

    /// Waits for the next datagram from the peer.
    ///
    /// - Throws: ``DatagramTransportError/closed`` when the transport closes
    ///   while waiting.
    /// - Returns: The next datagram.
    public func receive() async throws -> Data {
        switch nextBuffered() {
        case let .datagram(datagram):
            return datagram
        case .closed:
            throw DatagramTransportError.closed
        case .empty:
            break
        }

        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            switch nextBuffered() {
            case let .datagram(datagram):
                continuation.resume(returning: datagram)
            case .closed:
                continuation.resume(throwing: DatagramTransportError.closed)
            case .empty:
                park(continuation)
            }
        }
    }

    /// Closes the transport and fails any pending receive.
    public func close() async {
        let parked = performClose()
        for continuation in parked {
            continuation.resume(throwing: DatagramTransportError.closed)
        }
    }

    /// Marks the transport closed and hands back the parked receivers.
    ///
    /// Kept synchronous so that the lock is never taken directly from an
    /// asynchronous context.
    ///
    /// - Returns: The continuations that must be failed.
    private func performClose() -> [CheckedContinuation<Data, Error>] {
        lock.lock()
        guard !isClosed else {
            lock.unlock()
            return []
        }
        isClosed = true
        let parked = waiters
        waiters = []
        inbox = []
        lock.unlock()
        return parked
    }

    // MARK: - Internals

    /// What is waiting in the receive queue.
    private enum BufferedDatagram {

        /// A datagram is available.
        case datagram(Data)

        /// The transport is closed and the queue is empty.
        case closed

        /// Nothing is available yet.
        case empty
    }

    /// Takes the next queued datagram, if there is one.
    ///
    /// Kept synchronous so that the lock is never taken directly from an
    /// asynchronous context.
    ///
    /// - Returns: The next datagram, or why there is none.
    private func nextBuffered() -> BufferedDatagram {
        lock.lock()
        defer { lock.unlock() }
        if !inbox.isEmpty {
            let datagram = inbox.removeFirst()
            receivedDatagrams += 1
            return .datagram(datagram)
        }
        return isClosed ? .closed : .empty
    }

    /// Parks a continuation until a datagram arrives.
    ///
    /// - Parameter continuation: The continuation to resume later.
    private func park(_ continuation: CheckedContinuation<Data, Error>) {
        lock.lock()
        waiters.append(continuation)
        lock.unlock()
    }

    /// Hands a datagram to a waiter or to the queue.
    ///
    /// - Parameter datagram: The datagram to store.
    private func deliver(_ datagram: Data) {
        lock.lock()
        guard !isClosed else {
            lock.unlock()
            return
        }
        if !waiters.isEmpty {
            let continuation = waiters.removeFirst()
            receivedDatagrams += 1
            lock.unlock()
            continuation.resume(returning: datagram)
            return
        }
        if inbox.count >= capacity {
            inbox.removeFirst()
            droppedDatagrams += 1
        }
        inbox.append(datagram)
        lock.unlock()
    }
}
