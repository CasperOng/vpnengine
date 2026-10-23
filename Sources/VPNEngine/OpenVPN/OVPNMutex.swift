import Foundation

/// A mutual exclusion lock that is legal to use from asynchronous contexts.
///
/// `NSLock.lock()` is annotated `NS_SWIFT_UNAVAILABLE_FROM_ASYNC`, so calling
/// it directly inside an `async` function is a warning today and an error in
/// the Swift 6 language mode. The engine keeps its state behind short,
/// synchronous critical sections, so this thin wrapper exists purely to make
/// those sections callable from `async` code without restructuring them into
/// `withLock` closures.
///
/// It is a class, so the types that own one stay `@unchecked Sendable` and
/// document that the locking is what makes them safe.
final class OVPNMutex: @unchecked Sendable {
    private let mutex = NSLock()

    /// Acquire the lock, blocking the current thread.
    @inline(__always)
    func lock() {
        mutex.lock()
    }

    /// Release the lock.
    @inline(__always)
    func unlock() {
        mutex.unlock()
    }

    /// Run `body` while holding the lock.
    @inline(__always)
    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        mutex.lock()
        defer { mutex.unlock() }
        return try body()
    }
}
