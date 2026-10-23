//
//  AsyncDatagramQueue.swift
//  VPNEngine
//
//  A small bounded FIFO that bridges a synchronous producer to an asynchronous
//  consumer.
//
//  The session's `writeOutbound` is deliberately synchronous, because it is
//  called from the packet-flow path where awaiting would stall the caller, but
//  sending is asynchronous. Datagrams therefore go through this queue on their
//  way to the transport, which also keeps them in the order they were handed
//  over.
//

import Foundation

/// A bounded queue of datagrams with an asynchronous consumer.
final class AsyncDatagramQueue: @unchecked Sendable {

    /// How many datagrams to buffer before dropping the oldest.
    static let defaultCapacity = 512

    private let lock = NSLock()
    private let capacity: Int
    private var items: [Data] = []
    private var waiters: [CheckedContinuation<Data?, Never>] = []
    private var isClosed = false
    private var dropped = 0

    /// Creates a queue.
    ///
    /// - Parameter capacity: How many datagrams to hold. Values below one are
    ///   raised to one.
    init(capacity: Int = AsyncDatagramQueue.defaultCapacity) {
        self.capacity = Swift.max(1, capacity)
    }

    /// How many datagrams are waiting.
    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return items.count
    }

    /// How many datagrams were dropped because the queue was full.
    var droppedCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return dropped
    }

    /// Whether ``close()`` has been called.
    var closed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return isClosed
    }

    /// Appends a datagram, waking a waiter if there is one.
    ///
    /// - Parameter item: The datagram to queue.
    func push(_ item: Data) {
        lock.lock()
        guard !isClosed else {
            lock.unlock()
            return
        }
        if !waiters.isEmpty {
            let continuation = waiters.removeFirst()
            lock.unlock()
            continuation.resume(returning: item)
            return
        }
        if items.count >= capacity {
            items.removeFirst()
            dropped += 1
        }
        items.append(item)
        lock.unlock()
    }

    /// Waits for the next datagram.
    ///
    /// - Returns: The next datagram, or `nil` when the queue is closed and
    ///   empty.
    func pop() async -> Data? {
        switch nextBuffered() {
        case let .datagram(datagram):
            return datagram
        case .closed:
            return nil
        case .empty:
            break
        }

        return await withCheckedContinuation { (continuation: CheckedContinuation<Data?, Never>) in
            switch nextBuffered() {
            case let .datagram(datagram):
                continuation.resume(returning: datagram)
            case .closed:
                continuation.resume(returning: nil)
            case .empty:
                park(continuation)
            }
        }
    }

    /// Closes the queue, releasing every waiter.
    func close() {
        lock.lock()
        guard !isClosed else {
            lock.unlock()
            return
        }
        isClosed = true
        items.removeAll()
        let parked = waiters
        waiters = []
        lock.unlock()

        for continuation in parked {
            continuation.resume(returning: nil)
        }
    }

    // MARK: - Internals

    /// What is waiting in the queue.
    private enum BufferedDatagram {

        /// A datagram is available.
        case datagram(Data)

        /// The queue is closed and empty.
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
        if !items.isEmpty {
            return .datagram(items.removeFirst())
        }
        return isClosed ? .closed : .empty
    }

    /// Parks a continuation until something is pushed.
    ///
    /// - Parameter continuation: The continuation to resume later.
    private func park(_ continuation: CheckedContinuation<Data?, Never>) {
        lock.lock()
        waiters.append(continuation)
        lock.unlock()
    }
}
