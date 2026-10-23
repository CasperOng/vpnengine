//
//  TailscaleStateStore.swift
//  VPNEngine
//
//  What a Tailscale node has to remember between launches, and where each piece
//  of it is allowed to live.
//
//  Two classes of state, with very different handling:
//
//    * **Private keys** (machine, node, disco) go into a ``Keychain`` and
//      nowhere else. The node key is the WireGuard private key: anyone who has
//      it can decrypt the node's traffic and impersonate it on the tailnet, and
//      there is no way to rotate it without the coordination server's help.
//      This file has no code path that can write a private key to a file, and
//      ``TailscalePrivateKey`` is not `Codable`, so it cannot be smuggled
//      through a `JSONEncoder` either.
//
//    * **Everything else** — the public half of the keys, the node's stable ID,
//      the last netmap — is not secret. A netmap holds public keys, tailnet
//      addresses and hostnames: all of it is information the tailnet already
//      shares with every one of its nodes. It goes through a
//      ``TailscaleMetadataStore`` so that the app picks where it lands (a file
//      in Application Support, `UserDefaults`, a database, or nothing at all)
//      without this engine having an opinion.
//
//  The split is what makes the app's job easy: the keychain seam is the only
//  thing it *must* implement, and an in-memory implementation makes the whole
//  thing testable without touching either the real keychain or the disk.
//

import Foundation

// MARK: - Keychain

/// Where a private key is kept.
///
/// The app supplies this. A real implementation wraps the Security framework
/// (`SecItemAdd` with `kSecClassGenericPassword` and
/// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, so that the key survives
/// a reboot but never leaves the device); ``InMemoryKeychain`` is for tests and
/// previews.
///
/// Implementations must be safe to call from several tasks.
public protocol Keychain: Sendable {

    /// Stores data under an account name, replacing any existing value.
    ///
    /// - Parameters:
    ///   - data: The secret bytes.
    ///   - account: The account name, for example
    ///     ``TailscaleAccount/nodePrivateKey``.
    /// - Throws: ``TailscaleStateError/keychainFailure(_:)`` when the store
    ///   refuses the write.
    func set(_ data: Data, for account: String) throws

    /// Reads data for an account.
    ///
    /// - Parameter account: The account name.
    /// - Throws: ``TailscaleStateError/keychainFailure(_:)`` when the store
    ///   fails. A missing item is *not* an error: it returns `nil`.
    /// - Returns: The stored bytes, or `nil` when nothing is stored.
    func get(_ account: String) throws -> Data?

    /// Deletes data for an account.
    ///
    /// Deleting an account that does not exist is not an error.
    ///
    /// - Parameter account: The account name.
    /// - Throws: ``TailscaleStateError/keychainFailure(_:)`` when the store
    ///   fails.
    func remove(_ account: String) throws
}

/// The account names this engine stores private keys under.
public enum TailscaleAccount {

    /// The machine (device) private key.
    public static let machinePrivateKey = "com.vpnengine.tailscale.machine.privatekey"

    /// The node private key, which is also the WireGuard private key.
    public static let nodePrivateKey = "com.vpnengine.tailscale.node.privatekey"

    /// The disco private key.
    public static let discoPrivateKey = "com.vpnengine.tailscale.disco.privatekey"

    /// Every account this engine owns, for a clean logout.
    public static let all = [machinePrivateKey, nodePrivateKey, discoPrivateKey]
}

/// A keychain that keeps everything in memory.
///
/// For tests, previews, and a session that deliberately does not want to
/// persist. It is a real implementation of the protocol, not a stub: the
/// semantics — replace on write, `nil` on a missing read, no error on a missing
/// delete — are the same as the Security framework's.
public final class InMemoryKeychain: Keychain, @unchecked Sendable {

    private let lock = NSLock()
    private var storage: [String: Data]

    /// Creates an empty keychain, optionally pre-populated.
    ///
    /// - Parameter storage: Values to start with.
    public init(storage: [String: Data] = [:]) {
        self.storage = storage
    }

    /// Stores data under an account name.
    ///
    /// - Parameters:
    ///   - data: The secret bytes.
    ///   - account: The account name.
    /// - Throws: Never.
    public func set(_ data: Data, for account: String) throws {
        lock.lock()
        storage[account] = data
        lock.unlock()
    }

    /// Reads data for an account.
    ///
    /// - Parameter account: The account name.
    /// - Throws: Never.
    /// - Returns: The stored bytes, or `nil`.
    public func get(_ account: String) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return storage[account]
    }

    /// Deletes data for an account.
    ///
    /// - Parameter account: The account name.
    /// - Throws: Never.
    public func remove(_ account: String) throws {
        lock.lock()
        storage.removeValue(forKey: account)
        lock.unlock()
    }

    /// Everything that is currently stored, for assertions in tests.
    public var snapshot: [String: Data] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }
}

// MARK: - Metadata

/// Where the non-secret state is kept.
///
/// Implementations must be safe to call from several tasks. A `nil` return from
/// ``load()`` means "nothing has been saved yet", which is the state of a fresh
/// install.
public protocol TailscaleMetadataStore: Sendable {

    /// Reads the saved state.
    ///
    /// - Throws: ``TailscaleStateError/metadataFailure(_:)`` when the store
    ///   fails.
    /// - Returns: The saved bytes, or `nil` when there are none.
    func load() throws -> Data?

    /// Replaces the saved state.
    ///
    /// - Parameter data: The bytes to save.
    /// - Throws: ``TailscaleStateError/metadataFailure(_:)`` when the store
    ///   fails.
    func save(_ data: Data) throws

    /// Deletes the saved state.
    ///
    /// - Throws: ``TailscaleStateError/metadataFailure(_:)`` when the store
    ///   fails.
    func clear() throws
}

/// A metadata store that keeps everything in memory.
public final class InMemoryMetadataStore: TailscaleMetadataStore, @unchecked Sendable {

    private let lock = NSLock()
    private var storage: Data?

    /// Creates an empty store, optionally pre-populated.
    ///
    /// - Parameter initialValue: Bytes to start with.
    public init(initialValue: Data? = nil) {
        self.storage = initialValue
    }

    /// Reads the saved state.
    ///
    /// - Throws: Never.
    /// - Returns: The saved bytes, or `nil`.
    public func load() throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    /// Replaces the saved state.
    ///
    /// - Parameter data: The bytes to save.
    /// - Throws: Never.
    public func save(_ data: Data) throws {
        lock.lock()
        storage = data
        lock.unlock()
    }

    /// Deletes the saved state.
    ///
    /// - Throws: Never.
    public func clear() throws {
        lock.lock()
        storage = nil
        lock.unlock()
    }
}

/// A metadata store backed by one JSON file.
///
/// The file holds public keys, tailnet addresses, hostnames and the last
/// netmap. It never holds a private key: those live in the ``Keychain``, and
/// that separation is the entire point of this file.
public struct FileMetadataStore: TailscaleMetadataStore, Sendable {

    /// The file to read and write.
    public let url: URL

    /// Creates a file-backed store.
    ///
    /// - Parameter url: The file to use. Its directory is created on first
    ///   write. A sensible location is
    ///   `Application Support/<bundle id>/tailscale-state.json`.
    public init(url: URL) {
        self.url = url
    }

    /// Creates a store in a directory, under the standard file name.
    ///
    /// - Parameter directory: The directory to write into.
    public init(directory: URL) {
        self.url = directory.appendingPathComponent("tailscale-state.json")
    }

    /// Reads the file.
    ///
    /// A missing file is not an error; a file that cannot be read is.
    ///
    /// - Throws: ``TailscaleStateError/metadataFailure(_:)`` when the file
    ///   exists but cannot be read.
    /// - Returns: The file contents, or `nil`.
    public func load() throws -> Data? {
        do {
            return try Data(contentsOf: url)
        } catch let error as NSError {
            if error.domain == NSCocoaErrorDomain, error.code == NSFileReadNoSuchFileError {
                return nil
            }
            throw TailscaleStateError.metadataFailure("could not read \(url.lastPathComponent): \(error.localizedDescription)")
        }
    }

    /// Writes the file, creating its directory when needed.
    ///
    /// - Parameter data: The bytes to save.
    /// - Throws: ``TailscaleStateError/metadataFailure(_:)`` when the write
    ///   fails.
    public func save(_ data: Data) throws {
        let directory = url.deletingLastPathComponent()
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try data.write(to: url, options: [.atomic])
        } catch {
            throw TailscaleStateError.metadataFailure("could not write \(url.lastPathComponent): \(error.localizedDescription)")
        }
    }

    /// Deletes the file, when it exists.
    ///
    /// - Throws: ``TailscaleStateError/metadataFailure(_:)`` when the file
    ///   cannot be removed.
    public func clear() throws {
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        do {
            try FileManager.default.removeItem(at: url)
        } catch {
            throw TailscaleStateError.metadataFailure("could not remove \(url.lastPathComponent): \(error.localizedDescription)")
        }
    }
}

// MARK: - Errors

/// Errors from persisting or restoring state.
public enum TailscaleStateError: Error, Equatable, Sendable {

    /// The keychain refused an operation.
    ///
    /// - Parameter reason: A human readable explanation.
    case keychainFailure(String)

    /// The metadata store refused an operation.
    ///
    /// - Parameter reason: A human readable explanation.
    case metadataFailure(String)

    /// Stored metadata was present but unreadable, for example because it was
    /// written by a newer version.
    ///
    /// - Parameter reason: A human readable explanation.
    case corruptState(String)

    /// A stored private key was not a valid key of its role.
    ///
    /// - Parameter account: The keychain account that held it.
    case corruptedKey(String)
}

// MARK: - Persisted state

/// The non-secret state that survives a relaunch.
///
/// Everything here is either a public key or derived from one, so it is safe in
/// a file. Note what is *absent*: private keys, the auth key, and anything else
/// that would let someone else join the tailnet as this node.
public struct TailscalePersistedState: Codable, Sendable, Equatable {

    /// The public machine key, as `mkey:<hex>`, so that the keychain entry can
    /// be checked against the metadata after a partial write.
    public var machineKey: String?

    /// The public node key, as `nodekey:<hex>`.
    public var nodeKey: String?

    /// The public disco key, as `discokey:<hex>`.
    public var discoKey: String?

    /// The node's stable ID (`tailcfg.Node.StableID`), once known.
    public var stableNodeID: String?

    /// When the node key expires, once known.
    ///
    /// Cached so the app can warn before a relaunch, and so a session that
    /// starts offline can decide whether it is likely to be expired.
    public var nodeKeyExpiry: Date?

    /// The last netmap the server sent.
    ///
    /// Restoring it means the tunnel can come up with working routes before the
    /// control connection finishes, which is the difference between a VPN that
    /// reconnects instantly and one that shows a spinner.
    public var netmap: TailscaleNetmap?

    /// How many times the node key has been rotated on this install.
    ///
    /// Diagnostic only, but it makes "why did my node key change" answerable
    /// from a log line.
    public var nodeKeyRotations: Int

    /// Creates a persisted state.
    ///
    /// - Parameters:
    ///   - machineKey: The public machine key text.
    ///   - nodeKey: The public node key text.
    ///   - discoKey: The public disco key text.
    ///   - stableNodeID: The node's stable ID.
    ///   - nodeKeyExpiry: When the node key expires.
    ///   - netmap: The last netmap.
    ///   - nodeKeyRotations: How many rotations have happened.
    public init(machineKey: String? = nil,
                nodeKey: String? = nil,
                discoKey: String? = nil,
                stableNodeID: String? = nil,
                nodeKeyExpiry: Date? = nil,
                netmap: TailscaleNetmap? = nil,
                nodeKeyRotations: Int = 0) {
        self.machineKey = machineKey
        self.nodeKey = nodeKey
        self.discoKey = discoKey
        self.stableNodeID = stableNodeID
        self.nodeKeyExpiry = nodeKeyExpiry
        self.netmap = netmap
        self.nodeKeyRotations = nodeKeyRotations
    }

    /// Decodes a state, defaulting the fields an older snapshot may not have.
    ///
    /// - Parameter decoder: The decoder to read from.
    /// - Throws: A decoding error when a present field is malformed.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.machineKey = try container.decodeIfPresent(String.self, forKey: .machineKey)
        self.nodeKey = try container.decodeIfPresent(String.self, forKey: .nodeKey)
        self.discoKey = try container.decodeIfPresent(String.self, forKey: .discoKey)
        self.stableNodeID = try container.decodeIfPresent(String.self, forKey: .stableNodeID)
        self.nodeKeyExpiry = try container.decodeIfPresent(Date.self, forKey: .nodeKeyExpiry)
        self.netmap = try container.decodeIfPresent(TailscaleNetmap.self, forKey: .netmap)
        self.nodeKeyRotations = try container.decodeIfPresent(Int.self, forKey: .nodeKeyRotations) ?? 0
    }

    /// The keys this file uses.
    enum CodingKeys: String, CodingKey {
        case machineKey, nodeKey, discoKey, stableNodeID, nodeKeyExpiry, netmap, nodeKeyRotations
    }
}

// MARK: - Store

/// Loads and saves a node's keys and its last netmap.
///
/// The store is the only place in this engine that knows where secrets go, and
/// it keeps that knowledge in one place: ``Keychain`` for private keys,
/// ``TailscaleMetadataStore`` for everything else.
public final class TailscaleStateStore: @unchecked Sendable {

    private let keychain: Keychain
    private let metadata: TailscaleMetadataStore
    private let log: @Sendable (String) -> Void
    private let lock = NSLock()
    private var cachedState: TailscalePersistedState

    /// Creates a store.
    ///
    /// - Parameters:
    ///   - keychain: Where private keys live. The app supplies the real one;
    ///     tests use ``InMemoryKeychain``.
    ///   - metadata: Where the rest lives. Defaults to memory, so a test that
    ///     forgets to pass one cannot write to the disk by accident.
    ///   - log: A diagnostic sink.
    public init(keychain: Keychain,
                metadata: TailscaleMetadataStore = InMemoryMetadataStore(),
                log: @escaping @Sendable (String) -> Void = { _ in }) {
        self.keychain = keychain
        self.metadata = metadata
        self.log = log
        self.cachedState = TailscalePersistedState()
    }

    // MARK: Keys

    /// Loads the node's keys, generating them if this is a fresh install.
    ///
    /// Whether the keys are new is available from ``isFreshInstall``, which is
    /// what makes the difference between "register this node" and "re-register
    /// this node" on the wire (a fresh node sends no `OldNodeKey`).
    ///
    /// - Throws: ``TailscaleStateError`` when the keychain fails or holds
    ///   something that is not a key.
    /// - Returns: The keys, which are persisted before this returns.
    public func loadOrCreateKeys() throws -> TailscaleKeys {
        if let existing = try loadKeys() {
            isFreshInstall = false
            return existing
        }
        let generated = try TailscaleKeys.generate()
        try saveKeys(generated)
        isFreshInstall = true
        totalNodeKeyRotations = 0
        log("state: generated a new machine, node and disco key")
        return generated
    }

    /// Whether the most recent ``loadOrCreateKeys()`` had to generate keys.
    ///
    /// `true` means this device has never registered with the coordination
    /// server (or the keychain was wiped), so the registration must not claim to
    /// be rotating an existing node key.
    public private(set) var isFreshInstall = false

    /// Reads the keys, when all three are present and well formed.
    ///
    /// A partial set is treated as no set at all: half a key set cannot
    /// register, and regenerating the missing half would produce a machine key
    /// that the coordination server does not know, which is worse than
    /// registering fresh.
    ///
    /// - Throws: ``TailscaleStateError`` when the keychain fails.
    /// - Returns: The keys, or `nil` when nothing is stored.
    public func loadKeys() throws -> TailscaleKeys? {
        var pairs: [TailscaleKeyRole: TailscaleKeyPair] = [:]
        var present = 0

        for (role, account) in TailscaleStateStore.accounts {
            let data = try readKeychain(account)
            guard let data else { continue }
            present += 1
            guard let text = String(data: data, encoding: .utf8),
                  let privateKey = TailscalePrivateKey(role: role, text: text) else {
                throw TailscaleStateError.corruptedKey(account)
            }
            do {
                pairs[role] = try TailscaleKeyPair(privateKey: privateKey)
            } catch {
                throw TailscaleStateError.corruptedKey(account)
            }
        }

        guard present > 0 else { return nil }
        guard let machine = pairs[.machine], let node = pairs[.node], let disco = pairs[.disco] else {
            log("state: the keychain holds only part of a key set; regenerating all three")
            try clearKeys()
            return nil
        }
        return TailscaleKeys(machine: machine, node: node, disco: disco)
    }

    /// Writes the keys to the keychain and their public halves to metadata.
    ///
    /// - Parameter keys: The keys to store.
    /// - Throws: ``TailscaleStateError`` when either store fails.
    public func saveKeys(_ keys: TailscaleKeys) throws {
        try writeKeychain(Data(keys.machine.privateKey.storageText.utf8), TailscaleAccount.machinePrivateKey)
        try writeKeychain(Data(keys.node.privateKey.storageText.utf8), TailscaleAccount.nodePrivateKey)
        try writeKeychain(Data(keys.disco.privateKey.storageText.utf8), TailscaleAccount.discoPrivateKey)

        var state = currentState()
        state.machineKey = keys.machine.publicKey.text
        state.nodeKey = keys.node.publicKey.text
        state.discoKey = keys.disco.publicKey.text
        try persist(state)
    }

    /// Deletes every key.
    ///
    /// This is a logout that cannot be undone: the node key is what identifies
    /// the device to the coordination server, and without it a re-registration
    /// looks like a brand new device. Callers should tell the user.
    ///
    /// - Throws: ``TailscaleStateError`` when a store fails.
    public func clearKeys() throws {
        for account in TailscaleAccount.all {
            try removeKeychain(account)
        }
        var state = currentState()
        state.machineKey = nil
        state.nodeKey = nil
        state.discoKey = nil
        state.stableNodeID = nil
        state.nodeKeyExpiry = nil
        try persist(state)
    }

    // MARK: Netmap

    /// The last netmap the server sent, if one was saved.
    ///
    /// - Returns: The netmap, or `nil`.
    public func loadNetmap() -> TailscaleNetmap? {
        currentState().netmap
    }

    /// Saves the last netmap.
    ///
    /// Called on every material netmap change. Netmaps are small (a few
    /// kilobytes for a large tailnet) and this is one atomic file write, so
    /// there is no throttling to get wrong.
    ///
    /// - Parameter netmap: The netmap to save.
    /// - Throws: ``TailscaleStateError/metadataFailure(_:)`` when the store
    ///   fails.
    public func saveNetmap(_ netmap: TailscaleNetmap) throws {
        var state = currentState()
        state.netmap = netmap
        if let selfNode = netmap.selfNode {
            state.stableNodeID = selfNode.id
            state.nodeKeyExpiry = selfNode.keyExpiry
        }
        try persist(state)
    }

    /// Forgets the saved netmap.
    ///
    /// - Throws: ``TailscaleStateError/metadataFailure(_:)`` when the store
    ///   fails.
    public func clearNetmap() throws {
        var state = currentState()
        state.netmap = nil
        try persist(state)
    }

    // MARK: Metadata

    /// The node's stable ID, once a netmap has been saved.
    public var stableNodeID: String? {
        currentState().stableNodeID
    }

    /// The node's key expiry, once a netmap has been saved.
    public var nodeKeyExpiry: Date? {
        currentState().nodeKeyExpiry
    }

    /// How many times the node key has been rotated on this install.
    public private(set) var totalNodeKeyRotations = 0

    /// Records a node key rotation and saves the new keys.
    ///
    /// Called by ``TailscaleSession`` when the server says the node key has
    /// expired. The machine key is preserved, which is what lets the server
    /// recognise the new node key as the same device.
    ///
    /// - Parameter keys: The keys after rotation.
    /// - Throws: ``TailscaleStateError`` when a store fails.
    public func recordNodeKeyRotation(_ keys: TailscaleKeys) throws {
        try saveKeys(keys)
        var state = currentState()
        state.nodeKeyRotations += 1
        totalNodeKeyRotations = state.nodeKeyRotations
        try persist(state)
    }

    /// The whole persisted state, for tests and diagnostics.
    ///
    /// - Returns: The state as it was last written.
    public func persistedState() -> TailscalePersistedState {
        currentState()
    }

    // MARK: Internals

    /// The keychain account for each key role.
    static let accounts: [TailscaleKeyRole: String] = [
        .machine: TailscaleAccount.machinePrivateKey,
        .node: TailscaleAccount.nodePrivateKey,
        .disco: TailscaleAccount.discoPrivateKey,
    ]

    /// Reads the cached state, loading it from the store on first use.
    ///
    /// A store that cannot be read, or holds something unreadable, is logged
    /// and treated as empty: a device that cannot restore its cached netmap can
    /// still register from scratch, and refusing to start would be worse.
    ///
    /// - Returns: The state.
    private func currentState() -> TailscalePersistedState {
        lock.lock()
        if hasLoaded {
            let state = cachedState
            lock.unlock()
            return state
        }
        hasLoaded = true
        var failure: String?
        var loaded: TailscalePersistedState?
        do {
            if let data = try metadata.load() {
                loaded = try TailcfgCoding.decoder().decode(TailscalePersistedState.self, from: data)
            }
        } catch {
            failure = String(describing: error)
        }
        let state = loaded ?? TailscalePersistedState()
        cachedState = state
        totalNodeKeyRotations = state.nodeKeyRotations
        lock.unlock()

        // Logged outside the lock: the sink is supplied by the caller and must
        // never be able to deadlock the store.
        if let failure {
            log("state: could not read saved metadata (\(failure)); starting from an empty state")
        }
        return state
    }

    /// Writes the state and caches it.
    ///
    /// The store may throw; the cache is updated either way, because the
    /// in-memory value is still what the session is working with.
    ///
    /// - Parameter state: The state to write.
    /// - Throws: ``TailscaleStateError/metadataFailure(_:)`` when the store
    ///   fails.
    private func persist(_ state: TailscalePersistedState) throws {
        lock.lock()
        cachedState = state
        hasLoaded = true
        lock.unlock()
        let encoder = TailcfgCoding.encoder()
        let data = try encoder.encode(state)
        do {
            try metadata.save(data)
        } catch {
            throw TailscaleStateError.metadataFailure(String(describing: error))
        }
    }

    /// Whether the metadata store has been read at least once.
    private var hasLoaded = false

    /// Reads a keychain entry, wrapping failures in a typed error.
    ///
    /// - Parameter account: The account to read.
    /// - Throws: ``TailscaleStateError/keychainFailure(_:)``.
    /// - Returns: The stored bytes, or `nil`.
    private func readKeychain(_ account: String) throws -> Data? {
        do {
            return try keychain.get(account)
        } catch {
            throw TailscaleStateError.keychainFailure(String(describing: error))
        }
    }

    /// Writes a keychain entry, wrapping failures in a typed error.
    ///
    /// - Parameters:
    ///   - data: The secret bytes.
    ///   - account: The account to write.
    /// - Throws: ``TailscaleStateError/keychainFailure(_:)``.
    private func writeKeychain(_ data: Data, _ account: String) throws {
        do {
            try keychain.set(data, for: account)
        } catch {
            throw TailscaleStateError.keychainFailure(String(describing: error))
        }
    }

    /// Removes a keychain entry, wrapping failures in a typed error.
    ///
    /// - Parameter account: The account to remove.
    /// - Throws: ``TailscaleStateError/keychainFailure(_:)``.
    private func removeKeychain(_ account: String) throws {
        do {
            try keychain.remove(account)
        } catch {
            throw TailscaleStateError.keychainFailure(String(describing: error))
        }
    }
}
