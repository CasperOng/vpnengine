//
//  WireGuardSession.swift
//  VPNEngine
//
//  A running WireGuard tunnel: one interface, one UDP transport and a set of
//  peers, driven by two background loops.
//
//  The receive loop turns inbound datagrams into handshake progress, session
//  keys and inner IP packets. The timer loop implements the whitepaper's
//  section 6 state machine: it starts and retransmits handshakes, rekeys before
//  a key expires, sends keepalives, and gives up on an attempt that cannot
//  complete.
//
//  Callers see only ``WireGuardSessionState``, ``WireGuardStatistics``,
//  ``onInboundPackets`` and ``onStateChange``.
//

import Foundation

/// Where a session has got to.
public enum WireGuardSessionState: Sendable, Equatable {

    /// Not started, or stopped again.
    case idle

    /// A handshake is in progress and no usable keys exist yet.
    case handshaking

    /// Keys exist and can carry traffic; `since` is when they were established.
    case established(since: Date)

    /// The session gave up, with a human readable reason.
    case failed(String)
}

/// The counters a user interface wants to show.
public struct WireGuardStatistics: Sendable, Equatable {

    /// Encrypted bytes received from peers, transport data only.
    public var bytesReceived: UInt64

    /// Encrypted bytes sent to peers, transport data only.
    public var bytesSent: UInt64

    /// The most recent sign of life: when the session was established, or when
    /// the last transport message arrived from the peer, whichever is later.
    public var lastHandshake: Date?

    /// The session's state.
    public var state: WireGuardSessionState

    /// Creates a statistics snapshot.
    ///
    /// - Parameters:
    ///   - bytesReceived: Encrypted bytes received.
    ///   - bytesSent: Encrypted bytes sent.
    ///   - lastHandshake: The most recent session activity, if any.
    ///   - state: The session state.
    public init(bytesReceived: UInt64,
                bytesSent: UInt64,
                lastHandshake: Date?,
                state: WireGuardSessionState) {
        self.bytesReceived = bytesReceived
        self.bytesSent = bytesSent
        self.lastHandshake = lastHandshake
        self.state = state
    }
}

/// A running WireGuard session.
///
/// The type is thread safe: ``writeOutbound(_:)`` may be called from the packet
/// flow, ``statistics`` from a user interface, and the internal loops run
/// concurrently.
public final class WireGuardSession: @unchecked Sendable {

    // MARK: - Configuration

    private let configuration: WireGuardConfiguration
    private let transport: DatagramTransport
    private let timers: WireGuardSessionTimers
    private let log: @Sendable (String) -> Void

    // MARK: - Callbacks

    private var inboundHandler: (@Sendable ([Data]) -> Void)?
    private var stateHandler: (@Sendable (WireGuardSessionState) -> Void)?

    /// Called with the inner IP packets decrypted from inbound traffic.
    ///
    /// Keepalives produce no call, and transport padding is already removed, so
    /// every packet handed over is exactly what the peer's stack wrote. The
    /// closure runs on a background task and must not call back into the
    /// session.
    public var onInboundPackets: (@Sendable ([Data]) -> Void)? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return inboundHandler
        }
        set {
            lock.lock()
            inboundHandler = newValue
            lock.unlock()
        }
    }

    /// Called whenever ``WireGuardSessionState`` changes.
    ///
    /// The closure runs on a background task and must not call back into the
    /// session.
    public var onStateChange: (@Sendable (WireGuardSessionState) -> Void)? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return stateHandler
        }
        set {
            lock.lock()
            stateHandler = newValue
            lock.unlock()
        }
    }

    // MARK: - Internal state

    private let lock = NSLock()
    private var runtimes: [WireGuardPeerRuntime] = []
    private var pendingPackets: [Data: [Data]] = [:]
    private var currentState: WireGuardSessionState = .idle
    private var isRunning = false

    private let outbound: AsyncDatagramQueue
    private var receiveTask: Task<Void, Never>?
    private var timerTask: Task<Void, Never>?
    private var senderTask: Task<Void, Never>?

    /// How many packets to hold per peer while a handshake completes.
    private static let pendingPacketLimit = 64

    // MARK: - Creation

    /// Creates a session.
    ///
    /// - Parameters:
    ///   - configuration: The interface and peers to run.
    ///   - transport: Where datagrams go. A `NetworkExtension` passes an
    ///     `NWConnection` in UDP mode; tests pass an in-memory pair.
    ///   - log: A diagnostic sink. It is called synchronously from the
    ///     session's own queues, so it must not call back into the session.
    public convenience init(configuration: WireGuardConfiguration,
                            transport: DatagramTransport,
                            log: @escaping @Sendable (String) -> Void = { _ in }) {
        self.init(configuration: configuration,
                  transport: transport,
                  timers: WireGuardSessionTimers(),
                  log: log)
    }

    /// Creates a session with explicit timers.
    ///
    /// - Parameters:
    ///   - configuration: The interface and peers to run.
    ///   - transport: Where datagrams go.
    ///   - timers: The timer configuration. Tests shorten these.
    ///   - log: A diagnostic sink.
    public init(configuration: WireGuardConfiguration,
                transport: DatagramTransport,
                timers: WireGuardSessionTimers,
                log: @escaping @Sendable (String) -> Void = { _ in }) {
        self.configuration = configuration
        self.transport = transport
        self.timers = timers
        self.log = log
        self.outbound = AsyncDatagramQueue()
    }

    // MARK: - Lifecycle

    /// Starts the session.
    ///
    /// This validates the configuration, starts the receive, timer and send
    /// loops, and begins a handshake with every peer that has an endpoint.
    ///
    /// - Throws: ``VPNCryptoError`` when a key in the configuration has the
    ///   wrong size.
    public func start() async throws {
        try prepareStart()

        senderTask = Task { [weak self] in await self?.runSender() }
        receiveTask = Task { [weak self] in await self?.runReceiver() }
        timerTask = Task { [weak self] in await self?.runTimer() }

        setState(.handshaking)
        startInitialHandshakes()
    }

    /// Validates the configuration and prepares the session to run.
    ///
    /// Kept synchronous so that the lock is never taken directly from an
    /// asynchronous context.
    ///
    /// - Throws: ``VPNCryptoError`` when a key has the wrong size.
    private func prepareStart() throws {
        lock.lock()
        defer { lock.unlock() }

        guard !isRunning else { return }

        guard configuration.interface.privateKey.count == WireGuardWireFormat.publicKeySize else {
            throw VPNCryptoError.invalidKeySize(expected: WireGuardWireFormat.publicKeySize,
                                                actual: configuration.interface.privateKey.count)
        }
        for peer in configuration.peers {
            guard peer.publicKey.count == WireGuardWireFormat.publicKeySize else {
                throw VPNCryptoError.invalidKeySize(expected: WireGuardWireFormat.publicKeySize,
                                                    actual: peer.publicKey.count)
            }
            if let presharedKey = peer.presharedKey, presharedKey.count != WireGuardWireFormat.publicKeySize {
                throw VPNCryptoError.invalidKeySize(expected: WireGuardWireFormat.publicKeySize,
                                                    actual: presharedKey.count)
            }
        }

        runtimes = configuration.peers.map { peer in
            WireGuardPeerRuntime(peer: peer,
                                 localStaticPrivate: configuration.interface.privateKey,
                                 mtu: configuration.interface.mtu,
                                 timers: timers,
                                 log: log)
        }
        pendingPackets.removeAll()
        isRunning = true
    }

    /// Stops the session and closes the transport.
    ///
    /// Any packets still queued are discarded, and the state becomes
    /// ``WireGuardSessionState/idle``.
    public func stop() async {
        guard let prepared = prepareStop() else { return }

        for task in prepared.tasks {
            task?.cancel()
        }
        await transport.close()
        outbound.close()
        for task in prepared.tasks {
            _ = await task?.value
        }
        let now = Date()
        for runtime in prepared.peers {
            runtime.reset(now: now)
        }
        setState(.idle)
    }

    /// Marks the session as stopped and hands back what must be torn down.
    ///
    /// Kept synchronous so that the lock is never taken directly from an
    /// asynchronous context.
    ///
    /// - Returns: The tasks to cancel and the peers to reset, or `nil` when the
    ///   session was not running.
    private func prepareStop() -> (tasks: [Task<Void, Never>?], peers: [WireGuardPeerRuntime])? {
        lock.lock()
        defer { lock.unlock() }

        guard isRunning else { return nil }
        isRunning = false
        let tasks = [receiveTask, timerTask, senderTask]
        receiveTask = nil
        timerTask = nil
        senderTask = nil
        pendingPackets.removeAll()
        let peers = runtimes
        return (tasks, peers)
    }

    // MARK: - Data path

    /// Queues outbound IP packets for encryption.
    ///
    /// Each packet is routed to the peer whose `allowedIPs` contains its
    /// destination. Packets for a peer with no usable session are held briefly
    /// while a handshake completes; if the queue for that peer overflows, the
    /// oldest packet is dropped, because a tunnel that stalls is worse than one
    /// that loses a packet.
    ///
    /// - Parameter packets: The inner IP packets to send.
    public func writeOutbound(_ packets: [Data]) {
        guard !packets.isEmpty else { return }
        let now = Date()

        lock.lock()
        guard isRunning else {
            lock.unlock()
            log("dropped \(packets.count) packet(s): the session is not running")
            return
        }
        var toSend: [Data] = []
        var handshakePeers: [WireGuardPeerRuntime] = []

        for packet in packets {
            let destination = IPPacket.inspect(packet)?.destination
            let peer = destination.flatMap { configuration.peer(forDestination: $0) }
            guard let peer, let runtime = runtime(forPublicKey: peer.publicKey) else {
                log("dropped an outbound packet with no matching peer")
                continue
            }
            if let datagram = runtime.seal(packet: packet, now: now) {
                toSend.append(datagram)
            } else {
                enqueuePending(packet, for: runtime)
                handshakePeers.append(runtime)
            }
        }
        lock.unlock()

        for datagram in toSend {
            outbound.push(datagram)
        }
        for runtime in handshakePeers where !runtime.isHandshakeInFlight {
            startHandshake(with: runtime, now: now)
        }
    }

    /// The counters and state a user interface should display.
    public var statistics: WireGuardStatistics {
        lock.lock()
        var sent: UInt64 = 0
        var received: UInt64 = 0
        var lastActivity: Date?
        for runtime in runtimes {
            let counters = runtime.statistics
            sent += counters.sent
            received += counters.received
            if let candidate = runtime.lastHandshake {
                lastActivity = lastActivity.map { Swift.max($0, candidate) } ?? candidate
            }
        }
        let state = currentState
        lock.unlock()
        return WireGuardStatistics(bytesReceived: received,
                                   bytesSent: sent,
                                   lastHandshake: lastActivity,
                                   state: state)
    }

    /// Whether the session is running.
    public var isRunningSession: Bool {
        lock.lock()
        defer { lock.unlock() }
        return isRunning
    }

    /// How many outbound datagrams are waiting to reach the socket.
    public var queuedOutboundCount: Int { outbound.count }

    /// How many datagrams were dropped because the outbound queue was full.
    public var droppedOutboundCount: Int { outbound.droppedCount }

    // MARK: - Receive loop

    /// Reads datagrams until the transport closes.
    private func runReceiver() async {
        while !Task.isCancelled {
            let datagram: Data
            do {
                datagram = try await transport.receive()
            } catch {
                if !Task.isCancelled {
                    log("the transport stopped: \(error)")
                }
                return
            }
            handle(datagram)
        }
    }

    /// Processes one inbound datagram.
    ///
    /// - Parameter datagram: The datagram, which may be anything at all.
    private func handle(_ datagram: Data) {
        guard let type = wireGuardMessageType(of: datagram) else {
            // Not a WireGuard message: silently dropped, as the protocol
            // requires for anything that does not authenticate.
            return
        }
        let now = Date()

        switch type {
        case .handshakeInitiation:
            handleInitiation(datagram, now: now)
        case .handshakeResponse:
            handleResponse(datagram, now: now)
        case .cookieReply:
            handleCookieReply(datagram, now: now)
        case .transportData:
            handleTransport(datagram, now: now)
        }
    }

    /// Offers an initiation to every peer that could own it.
    ///
    /// An initiation carries no receiver index, so there is nothing to route on
    /// but the encrypted static key, which only the intended peer can decrypt.
    ///
    /// - Parameters:
    ///   - datagram: The initiation.
    ///   - now: The current time.
    private func handleInitiation(_ datagram: Data, now: Date) {
        lock.lock()
        let peers = runtimes
        lock.unlock()

        for runtime in peers {
            let outcome = runtime.handleHandshakeMessage(datagram, now: now)
            switch outcome {
            case let .send(response):
                outbound.push(response)
                markEstablishedIfPossible(runtime)
                return
            case .none, .established, .cookieStored:
                continue
            }
        }
        log("dropped a handshake initiation that no peer could consume")
    }

    /// Routes a response to the handshake attempt that is waiting for it.
    ///
    /// - Parameters:
    ///   - datagram: The response.
    ///   - now: The current time.
    private func handleResponse(_ datagram: Data, now: Date) {
        lock.lock()
        let peers = runtimes
        lock.unlock()

        for runtime in peers where runtime.ownsHandshakeMessage(datagram) {
            switch runtime.handleHandshakeMessage(datagram, now: now) {
            case .established:
                markEstablishedIfPossible(runtime)
                // One empty packet right after the handshake keeps the mapping
                // open and tells the peer the session works.
                if let keepalive = runtime.sealKeepalive(now: now) {
                    outbound.push(keepalive)
                }
                flushPendingPackets(for: runtime)
                return
            case .send, .none, .cookieStored:
                continue
            }
        }
        log("dropped a handshake response that matched no attempt")
    }

    /// Stores a cookie so the next handshake message carries a valid `mac2`.
    ///
    /// - Parameters:
    ///   - datagram: The cookie reply.
    ///   - now: The current time.
    private func handleCookieReply(_ datagram: Data, now: Date) {
        lock.lock()
        let peers = runtimes
        lock.unlock()

        for runtime in peers where runtime.ownsHandshakeMessage(datagram) {
            if runtime.handleHandshakeMessage(datagram, now: now) == .cookieStored {
                // The retransmission happens on the ordinary handshake timer, as
                // the whitepaper asks: a cookie reply must not itself trigger a
                // new handshake (section 5.4.7).
                return
            }
        }
        log("dropped a cookie reply that matched no attempt")
    }

    /// Decrypts a transport data message and dispatches the inner packet.
    ///
    /// - Parameters:
    ///   - datagram: The message.
    ///   - now: The current time.
    private func handleTransport(_ datagram: Data, now: Date) {
        guard let message = WireGuardTransportData.parse(datagram) else {
            log("dropped a truncated transport data message")
            return
        }

        lock.lock()
        let peers = runtimes
        lock.unlock()

        for runtime in peers {
            guard let packet = runtime.open(message: message, now: now) else { continue }
            markEstablishedIfPossible(runtime)
            let handler = onInboundPackets
            if !packet.isEmpty {
                handler?([packet])
            }
            return
        }
        // Unknown index, failed authentication or a replay: dropped silently.
    }

    // MARK: - Timer loop

    /// The peers to service, or `nil` when the session has stopped.
    ///
    /// Kept synchronous so that the lock is never taken directly from an
    /// asynchronous context.
    ///
    /// - Returns: A snapshot of the runtimes.
    private func snapshotPeersIfRunning() -> [WireGuardPeerRuntime]? {
        lock.lock()
        defer { lock.unlock() }
        return isRunning ? runtimes : nil
    }

    /// Runs the section 6 timer state machine.
    private func runTimer() async {
        while !Task.isCancelled {
            let now = Date()
            guard let peers = snapshotPeersIfRunning() else { return }

            for runtime in peers {
                let decision = runtime.timerDecision(now: now)

                if decision.teardown {
                    runtime.reset(now: now)
                    setState(.failed(decision.failureReason ?? "the session failed"))
                    continue
                }
                if decision.initiateHandshake, !runtime.isHandshakeInFlight {
                    startHandshake(with: runtime, now: now)
                }
                if decision.sendKeepalive, let datagram = runtime.sealKeepalive(now: now) {
                    outbound.push(datagram)
                }
                if runtime.hasUsableSendingSession(now: now) {
                    markEstablishedIfPossible(runtime)
                    flushPendingPackets(for: runtime)
                }
            }

            do {
                try await Task.sleep(for: .seconds(timers.tickInterval))
            } catch {
                return
            }
        }
    }

    // MARK: - Send loop

    /// Drains the outbound queue into the transport.
    private func runSender() async {
        while !Task.isCancelled {
            guard let datagram = await outbound.pop() else { return }
            do {
                try await transport.send(datagram)
            } catch {
                if !Task.isCancelled {
                    log("could not send a datagram: \(error)")
                }
                return
            }
        }
    }

    // MARK: - Internals

    /// Finds the runtime for a peer's public key.
    ///
    /// - Parameter publicKey: The peer's public key.
    /// - Returns: The runtime, or `nil` when the peer is not configured.
    private func runtime(forPublicKey publicKey: Data) -> WireGuardPeerRuntime? {
        runtimes.first { $0.publicKey == publicKey }
    }

    /// Starts an initial handshake with every peer that has an endpoint.
    private func startInitialHandshakes() {
        let now = Date()
        lock.lock()
        let peers = runtimes
        lock.unlock()
        for runtime in peers where runtime.canInitiate {
            startHandshake(with: runtime, now: now)
        }
    }

    /// Starts a handshake if the peer can be initiated to.
    ///
    /// - Parameters:
    ///   - runtime: The peer.
    ///   - now: The current time.
    private func startHandshake(with runtime: WireGuardPeerRuntime, now: Date) {
        guard let datagram = runtime.startHandshake(now: now) else { return }
        outbound.push(datagram)
        setStateIfNotEstablished(.handshaking)
    }

    /// Queues a packet until the peer has a session.
    ///
    /// - Parameters:
    ///   - packet: The inner IP packet.
    ///   - runtime: The peer it is routed to.
    private func enqueuePending(_ packet: Data, for runtime: WireGuardPeerRuntime) {
        var queue = pendingPackets[runtime.publicKey] ?? []
        if queue.count >= WireGuardSession.pendingPacketLimit {
            queue.removeFirst()
        }
        queue.append(packet)
        pendingPackets[runtime.publicKey] = queue
    }

    /// Sends everything that was waiting for this peer's session.
    ///
    /// - Parameter runtime: The peer.
    private func flushPendingPackets(for runtime: WireGuardPeerRuntime) {
        lock.lock()
        guard let queued = pendingPackets[runtime.publicKey], !queued.isEmpty else {
            lock.unlock()
            return
        }
        pendingPackets[runtime.publicKey] = []
        lock.unlock()

        let now = Date()
        for packet in queued {
            if let datagram = runtime.seal(packet: packet, now: now) {
                outbound.push(datagram)
            }
        }
    }

    /// Promotes the state to `.established` when a peer has a session.
    ///
    /// - Parameter runtime: The peer.
    private func markEstablishedIfPossible(_ runtime: WireGuardPeerRuntime) {
        guard let establishedAt = runtime.establishedAt else { return }
        lock.lock()
        let alreadyEstablished: Bool
        if case .established = currentState {
            alreadyEstablished = true
        } else {
            alreadyEstablished = false
        }
        lock.unlock()
        if !alreadyEstablished {
            setState(.established(since: establishedAt))
        }
    }

    /// Changes the state and notifies the observer.
    ///
    /// - Parameter state: The new state.
    private func setState(_ state: WireGuardSessionState) {
        lock.lock()
        guard currentState != state else {
            lock.unlock()
            return
        }
        currentState = state
        let handler = stateHandler
        lock.unlock()
        handler?(state)
    }

    /// Changes the state to `.handshaking` unless a session is already up.
    ///
    /// A rekey must not make a working tunnel look broken, so this never
    /// regresses an established session.
    ///
    /// - Parameter state: The state to set.
    private func setStateIfNotEstablished(_ state: WireGuardSessionState) {
        lock.lock()
        let established: Bool
        if case .established = currentState {
            established = true
        } else {
            established = false
        }
        lock.unlock()
        guard !established else { return }
        setState(state)
    }
}
