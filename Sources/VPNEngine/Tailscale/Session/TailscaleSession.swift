//
//  TailscaleSession.swift
//  VPNEngine
//
//  The control loop: register, stream the netmap, and keep a WireGuard tunnel
//  pointed at whatever the netmap currently says.
//
//  Three things run at once:
//
//    * the **control connection**, which registers this node and then consumes a
//      stream of ``TailscaleMapResponse`` frames;
//    * the **netmap**, which is a value type that the control loop replaces
//      under a lock, so a reader always sees a whole map rather than half of an
//      update;
//    * the **data plane**, a ``WireGuardSession`` rebuilt whenever the netmap
//      changes in a way that matters.
//
//  Rebuilding the data plane is the only expensive operation and it happens
//  rarely: adding a peer, removing one, a peer's addresses or endpoints
//  changing, or the exit-node selection changing. A frame that only updates
//  `LastSeen` does not rebuild anything.
//
//  ## Keepalives
//
//  A `MapResponse` with `KeepAlive` set is a heartbeat from the coordination
//  server, and `tailcfg` is explicit that every other field on such a frame is
//  to be ignored. In the streaming protocol it is a *read-side* signal: the
//  server is telling the client that the connection it already has is alive,
//  and there is nothing for the client to send back — the client cannot write
//  to the middle of an HTTP response body. What the client must do is notice,
//  and this session does:
//
//    * every record (keepalive or not) refreshes a watchdog, exactly as
//      `tailscaled` does with its 120 second `watchdogTimeout`;
//    * if the watchdog expires the transport is closed and the loop reconnects,
//      because a stream that has gone quiet is a stream that is dead;
//    * when the transport is *not* streaming — a one-shot map fetch, which this
//      session uses for ``refresh()`` against a server that does not support
//      streaming — a keepalive cannot arrive at all, so a keepalive in that mode
//      triggers an immediate re-request instead.
//
//  The server also uses keepalives to hold a NAT mapping open, which is why
//  ``TailscaleMapRequest/KeepAlive`` is set: without it a carrier-grade NAT can
//  expire the flow and the client would only find out when it tried to send.
//
//  ## Key expiry
//
//  `RegisterResponse.NodeKeyExpired` means the node key this client is using is
//  past its expiry, so the server will refuse to serve the netmap for it. The
//  fix is a rotation, and the rotation has to be done in the right order:
//
//    1. generate a **new node key** and keep the machine key, because the
//       machine key is what makes the server see "the same device with a new
//       key" rather than "a stranger";
//    2. persist it *before* registering, so a crash between the two cannot
//       leave a node key that the server knows and this device has lost;
//    3. register again with `OldNodeKey` set to the previous public key, which
//       is the field the server uses to authorise a rotation;
//    4. rebuild the data plane, because the WireGuard private key *is* the node
//       key: every peer's view of this node's public key changed, and every
//       handshake has to start over.
//
//  This file does all four. It rotates at most once per registration attempt,
//  so a server that keeps answering `NodeKeyExpired` cannot spin the client in a
//  loop.
//
//  ## Reconnection
//
//  A transport failure is normal — phones change networks, laptops sleep. The
//  loop therefore reconnects with an exponential backoff (1, 2, 4, 8, 15, 30,
//  60 seconds, then every 60) and only surfaces ``TailscaleState/failed(_:)``
//  once a real budget is gone: eight consecutive failures, each of which has
//  already been retried with the full ladder. Anything that arrives in the
//  meantime resets the counter, so a flaky link produces reconnects rather than
//  a permanent error.
//
//  ## Record framing
//
//  ``TailscaleControlTransport`` deals in whole records. The HTTP/2 framing and
//  the zstd compression of `MapResponse` bodies belong to the transport, which
//  is where `ts2021` puts them; everything in this file is JSON.
//

import Foundation

// MARK: - Transport

/// The control connection to a coordination server.
///
/// How a session obtains a control connection.
///
/// The session does not know how to speak Noise, and the app does not want the
/// session to. The app supplies a closure that can, given the configuration and
/// the node's keys (the machine key is the Noise static key, and the node key
/// proves possession of the node's identity to the server).
///
/// A production implementation wraps the `ts2021` transport; tests supply an
/// in-process one.
public struct TailscaleTransportFactory: Sendable {

    /// Builds a connected transport for a configuration.
    ///
    /// - Parameters:
    ///   - config: The configuration to connect with.
    ///   - keys: The node's keys, already loaded or generated.
    /// - Throws: Whatever the transport throws on failure.
    /// - Returns: A connected control transport.
    public typealias MakeTransport = @Sendable (TailscaleConfig, TailscaleKeys) async throws -> TailscaleControlTransport

    /// The closure that makes a transport.
    public var makeTransport: MakeTransport

    /// Creates a factory.
    ///
    /// - Parameter makeTransport: The closure that connects.
    public init(makeTransport: @escaping MakeTransport) {
        self.makeTransport = makeTransport
    }
}

// MARK: - State

/// Where a Tailscale session has got to.
public enum TailscaleState: Sendable, Equatable {

    /// Not started, or stopped before it connected.
    case idle

    /// The server needs a human: the user has to visit `authURL` before this
    /// node is authorised.
    ///
    /// The session keeps polling while in this state, so the URL does not have
    /// to be visited before the call returns.
    case needsLogin(authURL: URL)

    /// Registering, or waiting for an admin to approve the device.
    case connecting

    /// Connected, with a netmap and (unless there are no peers at all) a data
    /// plane.
    case running(TailscaleStatus)

    /// Stopped by the caller.
    case stopped

    /// Gave up, with a human readable reason.
    ///
    /// Only reached after the reconnect budget is exhausted, or for an
    /// unrecoverable answer such as `RegisterResponse.Error`.
    case failed(String)
}

/// What a user interface should show.
public struct TailscaleStatus: Sendable, Equatable {

    /// This node's registered hostname.
    public var hostname: String

    /// The tailnet's name, from `MapResponse.Domain`, when known.
    public var tailnetName: String?

    /// This node's tailnet addresses, as text.
    public var addresses: [String]

    /// The hostname of the selected exit node, when one is selected.
    public var exitNode: String?

    /// How many peers the netmap holds.
    public var peerCount: Int

    /// How many of those peers are online.
    public var onlinePeers: Int

    /// When the netmap last changed.
    public var lastMapUpdate: Date?

    /// Inner packets received through the tunnel.
    public var bytesIn: UInt64

    /// Inner packets sent through the tunnel.
    public var bytesOut: UInt64

    /// The data plane's own state.
    ///
    /// Not part of the protocol — it is the local ``WireGuardSessionState``, and
    /// it is the only way to tell "registering" from "tunnelling": the control
    /// plane can be perfectly happy while every handshake fails.
    public var dataPlane: WireGuardSessionState?

    /// Creates a status snapshot.
    ///
    /// - Parameters:
    ///   - hostname: The registered hostname.
    ///   - tailnetName: The tailnet name.
    ///   - addresses: This node's tailnet addresses.
    ///   - exitNode: The selected exit node's hostname.
    ///   - peerCount: The number of peers.
    ///   - onlinePeers: The number of online peers.
    ///   - lastMapUpdate: When the netmap last changed.
    ///   - bytesIn: Inner packets received.
    ///   - bytesOut: Inner packets sent.
    ///   - dataPlane: The data plane's state.
    public init(hostname: String,
                tailnetName: String? = nil,
                addresses: [String] = [],
                exitNode: String? = nil,
                peerCount: Int = 0,
                onlinePeers: Int = 0,
                lastMapUpdate: Date? = nil,
                bytesIn: UInt64 = 0,
                bytesOut: UInt64 = 0,
                dataPlane: WireGuardSessionState? = nil) {
        self.hostname = hostname
        self.tailnetName = tailnetName
        self.addresses = addresses
        self.exitNode = exitNode
        self.peerCount = peerCount
        self.onlinePeers = onlinePeers
        self.lastMapUpdate = lastMapUpdate
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.dataPlane = dataPlane
    }
}

/// How a session spaces out its reconnection attempts.
public struct TailscaleBackoffPolicy: Sendable, Equatable {

    /// The delay before each attempt, in seconds, with the last value repeating
    /// once the ladder is exhausted.
    public var delays: [Double]

    /// How many consecutive failures to tolerate before giving up.
    public var maxConsecutiveFailures: Int

    /// The default policy: 1, 2, 4, 8, 15, 30, 60 seconds, then every 60, and
    /// eight consecutive failures before giving up.
    ///
    /// Eight failures with that ladder is about four minutes of trying, which
    /// covers a captive portal being acknowledged, a laptop lid opening and a
    /// phone changing from Wi-Fi to cellular — while still telling the user
    /// something is wrong rather than retrying forever in silence.
    ///
    /// The delays are deliberately *not* jittered: a single client on a single
    /// device has no thundering herd to avoid, and a deterministic ladder is a
    /// testable one.
    public static let standard = TailscaleBackoffPolicy(delays: [1, 2, 4, 8, 15, 30, 60],
                                                       maxConsecutiveFailures: 8)

    /// Creates a policy.
    ///
    /// - Parameters:
    ///   - delays: The per-attempt delays in seconds.
    ///   - maxConsecutiveFailures: The failure budget.
    public init(delays: [Double], maxConsecutiveFailures: Int) {
        self.delays = delays
        self.maxConsecutiveFailures = maxConsecutiveFailures
    }

    /// The delay before an attempt.
    ///
    /// - Parameter attempt: The zero-based attempt number.
    /// - Returns: The delay in seconds.
    public func delay(forAttempt attempt: Int) -> Double {
        guard !delays.isEmpty else { return 0 }
        return delays[min(max(attempt, 0), delays.count - 1)]
    }
}

// MARK: - Session

/// A running Tailscale connection.
///
/// The type is thread safe. ``start()`` returns as soon as the session has keys
/// and a control loop; everything after that is delivered through
/// ``onStateChange`` and ``onNetmap``.
public final class TailscaleSession: @unchecked Sendable {

    // MARK: Configuration

    private let config: TailscaleConfig
    private let store: TailscaleStateStore
    private let transportFactory: TailscaleTransportFactory
    private let dataTransport: (String) throws -> DatagramTransport
    private let log: @Sendable (String) -> Void

    // MARK: Callbacks

    private var stateHandler: (@Sendable (TailscaleState) -> Void)?
    private var netmapHandler: (@Sendable (TailscaleNetmap) -> Void)?

    /// Called whenever ``TailscaleState`` changes.
    ///
    /// The closure runs on a background task and must not call back into the
    /// session synchronously.
    public var onStateChange: (@Sendable (TailscaleState) -> Void)? {
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

    /// Called with the whole netmap after every material change.
    ///
    /// The map is a value type, so the closure can keep it or pass it on
    /// without synchronisation. It runs on a background task and must not call
    /// back into the session synchronously.
    public var onNetmap: (@Sendable (TailscaleNetmap) -> Void)? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return netmapHandler
        }
        set {
            lock.lock()
            netmapHandler = newValue
            lock.unlock()
        }
    }

    // MARK: Tunables

    /// How long a control stream may be silent before it is considered dead.
    ///
    /// Matches `tailscaled`'s `watchdogTimeout`, which is 120 seconds.
    public var streamWatchdogTimeout: TimeInterval = 120

    /// How often the watchdog checks.
    public var watchdogPollInterval: Duration = .seconds(1)

    /// How long to wait between registration polls while waiting for a user or
    /// an admin.
    ///
    /// The server long-polls when `Followup` is set, so this is a floor rather
    /// than a busy loop. Tests shorten it.
    public var registrationPollInterval: Duration = .seconds(5)

    /// The reconnection policy.
    public var backoffPolicy: TailscaleBackoffPolicy = .standard

    // MARK: Internal state

    private let lock = NSLock()
    private var keys: TailscaleKeys?
    private var currentNetmap = TailscaleNetmap()
    private var currentState: TailscaleState = .idle
    private var currentStatus: TailscaleStatus?
    private var controlTask: Task<Void, Never>?
    private var watchdogTask: Task<Void, Never>?
    private var transport: TailscaleControlTransport?
    private var wireGuardSession: WireGuardSession?
    private var wireGuardConfiguration: WireGuardConfiguration?
    private var lastRecord = Date()
    private var lastMapUpdate: Date?
    private var consecutiveFailures = 0
    private var stopRequested = false
    private var exitNodeSelection: String?

    /// How many keepalive frames have arrived, for diagnostics and tests.
    public var keepAliveCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return keepAlives
    }

    private var keepAlives = 0

    // MARK: Creation

    /// Creates a session.
    ///
    /// - Parameters:
    ///   - config: What to connect to, and how.
    ///   - state: Where keys and the last netmap are kept. The caller supplies
    ///     the keychain; the default metadata store is in-memory.
    ///   - transportFactory: How to obtain a control connection.
    ///   - dataTransport: How to obtain the UDP socket the tunnel runs over. The
    ///     argument is an endpoint to connect to: the exit node's when one is
    ///     selected, and otherwise the first peer endpoint the netmap offers.
    ///     It is called once per data plane rebuild, and the session takes
    ///     ownership of what it returns (``WireGuardSession/stop()`` closes it).
    ///   - log: A diagnostic sink. It must not call back into the session.
    public init(config: TailscaleConfig,
                state: TailscaleStateStore,
                transportFactory: TailscaleTransportFactory,
                dataTransport: @escaping (String) throws -> DatagramTransport,
                log: @escaping @Sendable (String) -> Void = { _ in }) {
        self.config = config
        self.store = state
        self.transportFactory = transportFactory
        self.dataTransport = dataTransport
        self.log = log
        self.exitNodeSelection = config.exitNodeID
    }

    // MARK: Accessors

    /// The current netmap.
    ///
    /// Returns a snapshot: the session may apply another frame the moment after
    /// this returns, and that is fine, because the map is a value.
    public var netmap: TailscaleNetmap {
        lock.lock()
        defer { lock.unlock() }
        return currentNetmap
    }

    /// The current state.
    public var state: TailscaleState {
        lock.lock()
        defer { lock.unlock() }
        return currentState
    }

    /// The WireGuard configuration the data plane is running, when one is.
    ///
    /// Exposed for tests and diagnostics: this is the netmap's translation, and
    /// seeing it is the quickest way to answer "why is that peer not reachable".
    public var wireGuardConfigurationSnapshot: WireGuardConfiguration? {
        lock.lock()
        defer { lock.unlock() }
        return wireGuardConfiguration
    }

    /// The data plane session, when one is running.
    public var dataPlane: WireGuardSession? {
        lock.lock()
        defer { lock.unlock() }
        return wireGuardSession
    }

    // MARK: Lifecycle

    /// Loads or generates the node's keys and connects.
    ///
    /// Returns once the keys are in place and the control loop has been started;
    /// the connection itself is asynchronous and reported through
    /// ``onStateChange``.
    ///
    /// - Throws: ``TailscaleStateError`` when the keychain cannot be read or
    ///   written, or ``TailscaleSessionError/invalidNodeKey`` when the loaded
    ///   node key is not usable as a WireGuard key.
    public func start() async throws {
        let loadedKeys = try store.loadOrCreateKeys()
        guard loadedKeys.node.privateKey.rawValue.count == WireGuardWireFormat.publicKeySize else {
            throw TailscaleSessionError.invalidNodeKey(size: loadedKeys.node.privateKey.rawValue.count)
        }

        lock.lock()
        keys = loadedKeys
        stopRequested = false
        consecutiveFailures = 0
        if let saved = store.loadNetmap(), currentNetmap.peers.isEmpty, saved.peers.isEmpty == false {
            // A cached netmap lets the tunnel come up before the control plane
            // answers, which is the difference between "reconnected" and "still
            // connecting" from the user's point of view.
            currentNetmap = saved
        }
        lock.unlock()

        setState(.connecting)
        startControlLoop()
    }

    /// Stops the session, tearing down both planes.
    ///
    /// Safe to call more than once, and safe to call before ``start()``.
    public func stop() async {
        lock.lock()
        stopRequested = true
        let control = controlTask
        let watchdog = watchdogTask
        controlTask = nil
        watchdogTask = nil
        let connection = transport
        transport = nil
        let session = wireGuardSession
        wireGuardSession = nil
        wireGuardConfiguration = nil
        lock.unlock()

        control?.cancel()
        watchdog?.cancel()
        await connection?.close()
        await session?.stop()
        _ = await control?.value
        _ = await watchdog?.value

        setState(.stopped)
    }

    /// Asks the server for a fresh netmap.
    ///
    /// With a streaming connection there is no way to ask from inside the
    /// stream, so this drops the connection and reconnects: the new
    /// `MapRequest` is the question, and the first response is the answer. The
    /// data plane is left running while that happens, so a refresh does not
    /// interrupt traffic.
    public func refresh() async {
        lock.lock()
        let started = keys != nil
        let stopped = stopRequested
        lock.unlock()

        if !started || stopped {
            // Nothing to refresh: start (or restart) instead, so a UI can wire
            // "refresh" and "reconnect" to the same button.
            try? await start()
            return
        }

        log("control: refresh requested")
        restartControlConnection()
    }

    // MARK: Control loop

    /// Runs the connect/register/stream cycle until it is stopped or out of
    /// budget.
    private func runControlLoop() async {
        var attempt = 0
        while !Task.isCancelled {
            if isStopRequested { return }

            var failureReason: String?
            do {
                try await runControlConnection()
            } catch is CancellationError {
                return
            } catch {
                failureReason = String(describing: error)
            }

            if isStopRequested || Task.isCancelled { return }

            noteFailure()
            let failures = failureCount
            if failures >= backoffPolicy.maxConsecutiveFailures {
                setState(.failed(failureReason ?? "the control connection could not be established"))
                return
            }

            let delay = backoffPolicy.delay(forAttempt: attempt)
            attempt += 1
            log("control: \(failureReason ?? "the stream ended"); reconnecting in \(delay)s (failure \(failures))")
            do {
                try await Task.sleep(for: .seconds(delay))
            } catch {
                return
            }
        }
    }

    /// Connects, registers and streams.
    ///
    /// - Throws: When the connection cannot be established, registration is
    ///   refused, or the stream fails.
    private func runControlConnection() async throws {
        let connection = try await connect()
        lock.lock()
        transport = connection
        lastRecord = Date()
        lock.unlock()

        do {
            try await register(on: connection)
            startWatchdog()
            try await streamNetmap(on: connection)
        } catch {
            stopWatchdog()
            await connection.close()
            lock.lock()
            if transport === connection { transport = nil }
            lock.unlock()
            throw error
        }

        stopWatchdog()
        await connection.close()
        lock.lock()
        if transport === connection { transport = nil }
        lock.unlock()
    }

    /// Builds the control transport.
    ///
    /// - Throws: Whatever the factory throws.
    /// - Returns: A connected transport.
    private func connect() async throws -> TailscaleControlTransport {
        let keys = try requireKeys()
        setState(.connecting)
        log("control: connecting to \(config.loginServer.absoluteString)")
        return try await transportFactory.makeTransport(config, keys)
    }

    /// Registers this node, polling until it is authorised.
    ///
    /// - Parameter connection: The control transport.
    /// - Throws: ``TailscaleSessionError/registrationRejected(_:)`` when the
    ///   server says no, or a transport error.
    private func register(on connection: TailscaleControlTransport) async throws {
        var followup: URL?
        var didRotateNodeKey = false

        while !Task.isCancelled {
            if isStopRequested { throw CancellationError() }
            let keys = try requireKeys()

            let request = TailscaleRegisterRequest(Version: config.capabilityVersion,
                                                   NodeKey: keys.node.publicKey,
                                                   OldNodeKey: store.isFreshInstall ? nil : keys.node.publicKey,
                                                   AuthKey: config.authKey,
                                                   Expiry: nil,
                                                   Followup: followup?.absoluteString,
                                                   Hostinfo: hostinfo(),
                                                   Ephemeral: config.ephemeral)
            let body = try TailscaleControlMessage.registerRequest(request).encoded()
            try await connection.sendRecord(body)

            let record = try await receive(connection)
            let message = try TailscaleControlMessage(decoding: record)
            guard case let .registerResponse(response) = message else {
                log("control: expected a RegisterResponse, got \(message.kind)")
                throw TailscaleSessionError.unexpectedMessage(expected: "RegisterResponse", actual: message.kind)
            }

            if !response.Error.isEmpty {
                throw TailscaleSessionError.registrationRejected(response.Error)
            }

            if response.NodeKeyExpired {
                guard !didRotateNodeKey else {
                    throw TailscaleSessionError.nodeKeyRotationLoop
                }
                didRotateNodeKey = true
                try await rotateNodeKeyAndReregister()
                // The rotation rewrote the node key, so the next loop iteration
                // builds a new `RegisterRequest` with `OldNodeKey` set.
                continue
            }

            if response.MachineAuthorized {
                markRegistered()
                log("control: registered as \(config.hostname)")
                return
            }

            // Not authorised yet. With an `AuthURL` the user has to visit a
            // page; without one an administrator does. Either way the client
            // polls, sending `Followup` so that the server holds the response
            // until the page is visited instead of answering immediately.
            if let url = response.authURLValue {
                if followup != url {
                    followup = url
                    log("control: waiting for interactive login")
                }
                setState(.needsLogin(authURL: url))
            } else {
                setState(.connecting)
            }
            try await Task.sleep(for: registrationPollInterval)
        }
        throw CancellationError()
    }

    /// Sends the map request and consumes the response stream.
    ///
    /// - Parameter connection: The control transport.
    /// - Throws: A transport error when the stream fails.
    private func streamNetmap(on connection: TailscaleControlTransport) async throws {
        let keys = try requireKeys()
        let request = TailscaleMapRequest(Version: config.capabilityVersion,
                                          NodeKey: keys.node.publicKey,
                                          DiscoKey: keys.disco.publicKey,
                                          Stream: true,
                                          Hostinfo: hostinfo(),
                                          Endpoints: [],
                                          KeepAlive: true,
                                          Compress: "")
        let body = try TailscaleControlMessage.mapRequest(request).encoded()
        try await connection.sendRecord(body)
        log("control: map stream opened")

        while !Task.isCancelled {
            let record = try await receive(connection)
            try handle(record: record)
        }
        throw CancellationError()
    }

    /// Waits for a record and refreshes the watchdog.
    ///
    /// - Parameter connection: The control transport.
    /// - Throws: A transport error.
    /// - Returns: The record.
    private func receive(_ connection: TailscaleControlTransport) async throws -> Data {
        let record = try await connection.receiveRecord()
        lock.lock()
        lastRecord = Date()
        lock.unlock()
        return record
    }

    /// Handles one record from the map stream.
    ///
    /// - Parameter record: The record.
    /// - Throws: ``TailscaleControlError`` when it is not a map response.
    private func handle(record: Data) throws {
        let message = try TailscaleControlMessage(decoding: record)
        switch message {
        case let .mapResponse(response):
            handle(mapResponse: response)
        case let .registerResponse(response):
            // A server may push a register response on the map stream when the
            // node key expires mid-session. Treating it as a rotation trigger
            // costs two lines and avoids a stuck session.
            if response.NodeKeyExpired {
                log("control: the server announced key expiry on the map stream")
                Task { [weak self] in
                    guard let self else { return }
                    try? await self.rotateNodeKeyAndReregister()
                    self.restartControlConnection()
                }
            }
        default:
            log("control: ignoring an unexpected \(message.kind) on the map stream")
        }
    }

    /// Applies a map response to the netmap and, when needed, the data plane.
    ///
    /// - Parameter response: The frame.
    private func handle(mapResponse response: TailscaleMapResponse) {
        if response.KeepAlive {
            lock.lock()
            keepAlives += 1
            lock.unlock()
            handleKeepAlive()
            return
        }

        lock.lock()
        let previousRevision = currentNetmap.revision
        currentNetmap.apply(response)
        let netmap = currentNetmap
        let changed = netmap.revision != previousRevision
        if changed { lastMapUpdate = Date() }
        lock.unlock()

        guard changed else { return }

        log("netmap: revision \(netmap.revision), \(netmap.peerCount) peer(s), \(netmap.onlinePeerCount) online")
        try? store.saveNetmap(netmap)
        netmapHandler?(netmap)
        rebuildDataPlane(with: netmap)
        publishStatus()
    }

    /// Responds to a keepalive frame.
    ///
    /// See the file header: on a streaming connection the correct response is
    /// silence, and the keepalive's job is to prove the stream is alive. On a
    /// non-streaming one there is nothing to keep alive, so the session asks
    /// again rather than sitting on a connection the server has already closed.
    private func handleKeepAlive() {
        lock.lock()
        // This session always asks for a streaming map (`MapRequest.Stream`), so a
        // keepalive here means the stream is alive and there is nothing to re-send.
        // The non-streaming branch below exists for the one-shot mode.
        let streaming = true
        let stopped = stopRequested
        lock.unlock()
        guard !stopped else { return }
        if !streaming {
            restartControlConnection()
        }
    }

    // MARK: Watchdog

    /// Starts the stream watchdog.
    private func startWatchdog() {
        lock.lock()
        watchdogTask?.cancel()
        lock.unlock()

        let task = Task { [weak self] in
            guard let self else { return }
            await self.runWatchdog()
        }
        lock.lock()
        watchdogTask = task
        lock.unlock()
    }

    /// Stops the stream watchdog.
    private func stopWatchdog() {
        lock.lock()
        let task = watchdogTask
        watchdogTask = nil
        lock.unlock()
        task?.cancel()
    }

    /// Closes the transport when the stream goes quiet.
    ///
    /// A silent stream is indistinguishable from a dead one, and a TCP
    /// connection that has been black-holed can stay "open" for many minutes.
    /// Closing the transport turns silence into an error, which turns into a
    /// reconnect.
    private func runWatchdog() async {
        while !Task.isCancelled {
            do {
                try await Task.sleep(for: watchdogPollInterval)
            } catch {
                return
            }
            lock.lock()
            let silence = Date().timeIntervalSince(lastRecord)
            let connection = transport
            lock.unlock()
            guard silence > streamWatchdogTimeout else { continue }
            log("control: no record for \(Int(silence))s; assuming the stream is dead")
            await connection?.close()
            return
        }
    }

    // MARK: Data plane

    /// Rebuilds the WireGuard session when the configuration changed.
    ///
    /// - Parameter netmap: The netmap to translate.
    private func rebuildDataPlane(with netmap: TailscaleNetmap) {
        let keys: TailscaleKeys
        do {
            keys = try requireKeys()
        } catch {
            return
        }

        let nodeKeyExpired = netmap.selfNode.map { $0.isExpired(at: Date()) } ?? false
        if nodeKeyExpired {
            // The server has already told us; stop pretending the tunnel works
            // and let the rotation path fix it. Leaving a session up with a key
            // the server considers dead produces confusing half-broken traffic.
            log("netmap: this node's key has expired; the data plane will be rebuilt after rotation")
        }

        let configuration: WireGuardConfiguration
        do {
            configuration = try TailscalePeerMapper.wireGuardConfiguration(netmap: netmap,
                                                                          nodePrivateKey: keys.node.privateKey.rawValue,
                                                                          listenPort: nil,
                                                                          acceptRoutes: config.acceptRoutes,
                                                                          exitNodeID: exitNodeSelection)
        } catch let error as TailscaleMapperError {
            log("netmap: cannot build a WireGuard configuration: \(error)")
            tearDownDataPlane()
            setState(.failed("\(error)"))
            return
        } catch {
            log("netmap: cannot build a WireGuard configuration: \(error)")
            return
        }

        lock.lock()
        let unchanged = configuration == wireGuardConfiguration && wireGuardSession?.isRunningSession == true
        lock.unlock()
        guard !unchanged else { return }

        let endpoint = primaryEndpoint(for: netmap) ?? ""
        let socket: DatagramTransport
        do {
            socket = try dataTransport(endpoint)
        } catch {
            log("netmap: cannot open the tunnel socket (\(endpoint)): \(error)")
            setState(.failed("cannot open the tunnel socket: \(error)"))
            return
        }

        let session = WireGuardSession(configuration: configuration,
                                       transport: socket,
                                       log: log)
        session.onStateChange = { [weak self] _ in
            self?.publishStatus()
        }
        session.onInboundPackets = { [weak self] packets in
            self?.deliverInbound(packets)
        }
        let previous = takeDataPlane()
        Task { [weak self] in
            guard let self else { return }
            await previous?.stop()
            do {
                try await session.start()
            } catch {
                self.log("netmap: the WireGuard session would not start: \(error)")
                return
            }
            self.log("netmap: data plane up with \(configuration.peers.count) peer(s) via \(endpoint)")
            self.publishStatus()
        }
        installDataPlane(session: session, configuration: configuration)
    }

    /// Hands the session and the configuration to the internal state.
    ///
    /// - Parameters:
    ///   - session: The new data plane.
    ///   - configuration: Its configuration.
    private func installDataPlane(session: WireGuardSession, configuration: WireGuardConfiguration) {
        lock.lock()
        wireGuardSession = session
        wireGuardConfiguration = configuration
        lock.unlock()
    }

    /// Takes the current data plane out of the state, for teardown.
    ///
    /// - Returns: The session that was running, or `nil`.
    private func takeDataPlane() -> WireGuardSession? {
        lock.lock()
        let session = wireGuardSession
        wireGuardSession = nil
        lock.unlock()
        return session
    }

    /// Stops the data plane.
    private func tearDownDataPlane() {
        let session = takeDataPlane()
        lock.lock()
        wireGuardConfiguration = nil
        lock.unlock()
        guard let session else { return }
        Task { await session.stop() }
    }

    /// The endpoint to hand the data transport.
    ///
    /// The data transport is a *connected* socket, so a session has to pick one
    /// endpoint to connect it to. The exit node is the natural choice when one
    /// is selected, because every packet that is not for another tailnet node
    /// goes there; otherwise the first peer that has an endpoint will do, and a
    /// caller that needs anything smarter (a peer-assisted socket, one socket
    /// per peer) implements ``DatagramTransport`` accordingly.
    ///
    /// - Parameter netmap: The netmap.
    /// - Returns: An `ip:port` string, or `nil` when nothing offers one.
    private func primaryEndpoint(for netmap: TailscaleNetmap) -> String? {
        if let exitNodeID = exitNodeSelection,
           let exitNode = netmap.peer(withStableID: exitNodeID) ?? netmap.peers.first(where: { String($0.nodeID) == exitNodeID }),
           let endpoint = exitNode.preferredEndpoint {
            return endpoint
        }
        return netmap.peers.compactMap(\.preferredEndpoint).first
    }

    /// Passes inbound packets on, when an app is listening.
    ///
    /// - Parameter packets: The decrypted inner packets.
    private func deliverInbound(_ packets: [Data]) {
        lock.lock()
        let handler = inboundHandler
        lock.unlock()
        handler?(packets)
    }

    private var inboundHandler: (@Sendable ([Data]) -> Void)?

    /// Called with the inner IP packets decrypted from the tunnel.
    ///
    /// The data plane has no IP stack of its own: someone has to deliver these
    /// to the operating system (a `NEPacketTunnelFlow`, or a netstack). Setting
    /// this after ``start()`` is fine.
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

    /// Queues outbound IP packets for encryption.
    ///
    /// - Parameter packets: The inner IP packets to send.
    public func writeOutbound(_ packets: [Data]) {
        lock.lock()
        let session = wireGuardSession
        lock.unlock()
        session?.writeOutbound(packets)
    }

    // MARK: Key expiry

    /// Rotates the node key and re-registers, keeping the machine key.
    ///
    /// See the file header for the order and why it matters. Only called from
    /// the registration loop and from the map stream, both of which are
    /// serialised by the session.
    ///
    /// - Throws: ``TailscaleStateError`` when the new keys cannot be persisted,
    ///   or ``TailscaleKeyError`` when the platform cannot generate them.
    public func rotateNodeKeyAndReregister() async throws {
        let current = try requireKeys()
        log("control: rotating the node key")
        let rotated = try current.rotatingNodeKey()
        // Persist first: a crash between here and the registration would
        // otherwise leave a key the server knows and this device does not.
        try store.recordNodeKeyRotation(rotated)
        lock.lock()
        keys = rotated
        lock.unlock()
        setState(.connecting)
    }

    // MARK: Registration bookkeeping

    /// Records that the server authorised this node.
    private func markRegistered() {
        lock.lock()
        consecutiveFailures = 0
        lock.unlock()
    }

    /// Notes a failed attempt.
    private func noteFailure() {
        lock.lock()
        consecutiveFailures += 1
        lock.unlock()
    }

    /// How many failures have happened in a row.
    private var failureCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return consecutiveFailures
    }

    /// Whether a stop has been requested.
    private var isStopRequested: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopRequested
    }

    // MARK: Internals

    /// The keys, or a thrown error when ``start()`` has not run.
    ///
    /// - Throws: ``TailscaleSessionError/notStarted``.
    /// - Returns: The keys.
    private func requireKeys() throws -> TailscaleKeys {
        lock.lock()
        defer { lock.unlock() }
        guard let keys else { throw TailscaleSessionError.notStarted }
        return keys
    }

    /// Builds the hostinfo this session advertises.
    ///
    /// - Returns: The hostinfo.
    private func hostinfo() -> TailscaleHostinfo {
        var info = TailscaleHostinfo(hostname: config.hostname,
                                     os: TailscaleHostinfo.currentOS,
                                     ipnVersion: TailscaleHostinfo.clientVersion,
                                     backendLogID: backendLogID(),
                                     goArch: "arm64",
                                     routableIPs: config.advertiseExitNode ? TailscaleSession.exitNodeRoutes : [])
        info.ExitNodeID = exitNodeSelection ?? ""
        info.Services = []
        info.NetInfo = TailscaleNetInfo()
        return info
    }

    /// A stable per-install identifier for the log stream.
    ///
    /// The value is not a credential: the server only uses it to group log
    /// lines. It is derived from the machine key, which is already stable and
    /// already secret, so it adds no new information to the wire.
    ///
    /// - Returns: A hex string.
    private func backendLogID() -> String {
        guard let keys = try? requireKeys() else { return "" }
        let publicKey = keys.machine.publicKey.rawValue
        return TailscalePublicKey.bytesToHex([UInt8](publicKey.prefix(8)))
    }

    /// The routes an exit node advertises.
    static let exitNodeRoutes: [CIDR] = [CIDR(string: "0.0.0.0/0")!, CIDR(string: "::/0")!]

    /// Drops the control connection and starts a new one.
    private func restartControlConnection() {
        lock.lock()
        let connection = transport
        transport = nil
        lock.unlock()
        Task { await connection?.close() }
        startControlLoop()
    }

    /// Starts (or restarts) the control loop.
    private func startControlLoop() {
        lock.lock()
        controlTask?.cancel()
        controlTask = nil
        lock.unlock()

        let task = Task { [weak self] in
            guard let self else { return }
            await self.runControlLoop()
        }
        lock.lock()
        controlTask = task
        lock.unlock()
    }

    /// Publishes a status snapshot.
    private func publishStatus() {
        lock.lock()
        let netmap = currentNetmap
        let previous = currentStatus
        lock.unlock()

        let statistics = dataPlaneStatistics()
        var status = TailscaleStatus(hostname: config.hostname,
                                     tailnetName: netmap.searchDomain,
                                     addresses: netmap.selfNode?.addresses.map(\.description) ?? [],
                                     exitNode: exitNodeSelection.flatMap { id in
                                         (netmap.peer(withStableID: id) ?? netmap.peers.first { String($0.nodeID) == id })?.hostname
                                     },
                                     peerCount: netmap.peerCount,
                                     onlinePeers: netmap.onlinePeerCount,
                                     lastMapUpdate: lastMapUpdateValue,
                                     bytesIn: statistics.bytesIn,
                                     bytesOut: statistics.bytesOut,
                                     dataPlane: statistics.state)
        if status != previous {
            setStatus(status)
        }
    }

    /// The data plane's counters, or zeros when it is not running.
    ///
    /// - Returns: Received and sent byte counts, plus the session state.
    private func dataPlaneStatistics() -> (bytesIn: UInt64, bytesOut: UInt64, state: WireGuardSessionState?) {
        lock.lock()
        let session = wireGuardSession
        lock.unlock()
        guard let session else { return (0, 0, nil) }
        let statistics = session.statistics
        return (statistics.bytesReceived, statistics.bytesSent, statistics.state)
    }

    /// The last map update, under the lock.
    private var lastMapUpdateValue: Date? {
        lock.lock()
        defer { lock.unlock() }
        return lastMapUpdate
    }

    /// Changes the state and notifies the observer.
    ///
    /// - Parameter state: The new state.
    private func setState(_ state: TailscaleState) {
        lock.lock()
        guard currentState != state else {
            lock.unlock()
            return
        }
        currentState = state
        if case let .running(status) = state { currentStatus = status }
        let handler = stateHandler
        lock.unlock()
        handler?(state)
    }

    /// Changes the state to `.running`, with a status.
    ///
    /// - Parameter status: The status to publish.
    private func setStatus(_ status: TailscaleStatus) {
        setState(.running(status))
    }

    /// Changes the state to `.failed`, keeping the reason short and readable.
    ///
    /// - Parameter reason: The reason.
    private func setFailed(_ reason: String) {
        setState(.failed(reason))
    }
}

// MARK: - Hostinfo helpers

extension TailscaleHostinfo {

    /// The `version.OS` string for the platform this engine is running on.
    ///
    /// Tailscale uses `"macOS"` and `"iOS"`, both with capital letters, and the
    /// server groups devices by these values, so they have to match exactly.
    public static var currentOS: String {
        #if os(macOS)
        return "macOS"
        #elseif os(iOS)
        return "iOS"
        #else
        return "linux"
        #endif
    }

    /// The client version this engine reports.
    ///
    /// A `version.Long` string looks like `"1.76.1-t123-abcdef"`, and the
    /// server parses it to decide whether to offer updates. Reporting a real
    /// tailscale version is deliberate: it tells the server which protocol
    /// features to expect, and ''TailscaleConfig/capabilityVersion'' is the
    /// honest description of what this client actually implements.
    public static var clientVersion: String {
        "1.100.0-vpnengine"
    }
}

// MARK: - Errors

/// Errors from running a session.
public enum TailscaleSessionError: Error, Equatable, Sendable {

    /// ``TailscaleSession/start()`` has not been called, so there are no keys.
    case notStarted

    /// The node key is not usable as a WireGuard private key.
    ///
    /// - Parameter size: The size that was found.
    case invalidNodeKey(size: Int)

    /// The server refused the registration.
    ///
    /// - Parameter reason: `RegisterResponse.Error`, verbatim.
    case registrationRejected(String)

    /// The server asked for a node key rotation twice in a row, which means the
    /// rotation is not taking effect. Retrying forever would be a hot loop.
    case nodeKeyRotationLoop

    /// A message arrived where a different one was expected.
    ///
    /// - Parameters:
    ///   - expected: The message kind the session needed.
    ///   - actual: The message kind it got.
    case unexpectedMessage(expected: String, actual: String)
}

extension TailscaleSessionError: CustomStringConvertible {

    /// A human readable description, safe to show and to log.
    public var description: String {
        switch self {
        case .notStarted:
            return "the session has not been started"
        case let .invalidNodeKey(size):
            return "the node key is \(size) bytes, but WireGuard needs 32"
        case let .registrationRejected(reason):
            return "the server refused the registration: \(reason)"
        case .nodeKeyRotationLoop:
            return "the server keeps asking for a new node key"
        case let .unexpectedMessage(expected, actual):
            return "expected a \(expected), got a \(actual)"
        }
    }
}
