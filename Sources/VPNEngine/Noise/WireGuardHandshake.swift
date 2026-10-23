//
//  WireGuardHandshake.swift
//  VPNEngine
//
//  The Noise `IKpsk2` handshake of the WireGuard whitepaper, section 5.4.
//
//  A handshake object performs exactly one attempt: it is created, driven
//  through the message exchange, hands out the resulting session keys, and is
//  then discarded. Every attempt uses a fresh ephemeral key and a fresh local
//  index, which is what the protocol's forward secrecy relies on.
//
//  The transcript, expressed in the whitepaper's notation:
//
//      Ci = HASH(CONSTRUCTION)
//      Hi = HASH(Ci ‖ IDENTIFIER)
//
//      initiator                                    responder
//      ---------                                    ---------
//      Hi = HASH(Hi ‖ Spub_r)                       Hr = HASH(Hr ‖ Spub_r)
//      (e, Ei) = DH_GENERATE()
//      Ci = Kdf1(Ci, Epub_i)                        Cr = Kdf1(Cr, Epub_i)
//      Hi = HASH(Hi ‖ Epub_i)                       Hr = HASH(Hr ‖ Epub_i)
//      (Ci, κ) = Kdf2(Ci, DH(Ei, Spub_r))           (Cr, κ) = Kdf2(Cr, DH(Sr, Epub_i))
//      msg.static = AEAD(κ, 0, Spub_i, Hi)          Spub_i = AEAD⁻¹(...)
//      Hi = HASH(Hi ‖ msg.static)                   Hr = HASH(Hr ‖ msg.static)
//      (Ci, κ) = Kdf2(Ci, DH(Si, Spub_r))           (Cr, κ) = Kdf2(Cr, DH(Sr, Spub_i))
//      msg.timestamp = AEAD(κ, 0, TAI64N, Hi)       TAI64N = AEAD⁻¹(...)
//      Hi = HASH(Hi ‖ msg.timestamp)                Hr = HASH(Hr ‖ msg.timestamp)
//      --- message 2 ---
//      (e, Er) = DH_GENERATE()
//      Ci = Kdf1(Ci, Epub_r)                        Cr = Kdf1(Cr, Epub_r)
//      Hi = HASH(Hi ‖ Epub_r)                       Hr = HASH(Hr ‖ Epub_r)
//      Ci = Kdf1(Ci, DH(Ei, Er))                    Cr = Kdf1(Cr, DH(Er, Epub_i))
//      Ci = Kdf1(Ci, DH(Si, Er))                    Cr = Kdf1(Cr, DH(Er, Spub_i))
//      (Ci, τ, κ) = Kdf3(Ci, Q)                     (Cr, τ, κ) = Kdf3(Cr, Q)
//      Hi = HASH(Hi ‖ τ)                            Hr = HASH(Hr ‖ τ)
//      msg.empty = AEAD(κ, 0, ε, Hi)                (verify msg.empty)
//      (T_send, T_recv) = Kdf2(Ci, ε)               (T_recv, T_send) = Kdf2(Cr, ε)
//
//  `Q` is the preshared key, all zero bytes when none is configured. The
//  whitepaper and the reference implementation both mix it unconditionally.
//

import Foundation

#if canImport(CryptoKit)
import CryptoKit
#endif

/// One attempt at a WireGuard handshake.
///
/// Not thread safe by design: a session serialises access under its own lock,
/// and tests drive an instance from a single task.
public final class WireGuardHandshake {

    // MARK: - Types

    /// The session keys the handshake produces.
    ///
    /// The names are from the perspective of *this* handshake object, so the
    /// initiator's `sendKey` is the responder's `receiveKey` and vice versa;
    /// that is the property the tests assert.
    public struct Result: Sendable, Equatable {

        /// The key used to encrypt transport data messages.
        public let sendKey: [UInt8]

        /// The key used to decrypt transport data messages.
        public let receiveKey: [UInt8]

        /// The peer's index: the value to put in the `receiver` field of
        /// outbound transport messages.
        public let remoteIndex: UInt32

        /// Our index: the value to expect in the `receiver` field of inbound
        /// transport messages.
        public let localIndex: UInt32
    }

    /// Where a handshake attempt has got to.
    public enum State: Sendable, Equatable {

        /// Nothing has happened yet.
        case idle

        /// The initiator has built and sent a handshake initiation.
        case initiationCreated

        /// The responder has accepted an initiation.
        case initiationConsumed

        /// The responder has built a response; the session keys are available.
        case responseCreated

        /// The initiator has accepted a response; the session keys are available.
        case responseConsumed

        /// The handshake failed and this object must not be used again.
        case failed(String)
    }

    // MARK: - Constants

    /// The Noise protocol name, hashed to form the initial chaining key.
    public static let noiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"

    /// The WireGuard protocol identifier, hashed into the initial transcript.
    public static let identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"

    /// Label mixed with the responder's public key to build the `mac1` key.
    public static let labelMAC1 = "mac1----"

    /// Label mixed with the responder's public key to build the cookie key.
    public static let labelCookie = "cookie--"

    /// How long a received cookie stays valid (whitepaper, section 5.4.4: a
    /// cookie older than 120 seconds must not be used).
    public static let cookieLifetime: TimeInterval = 120

    /// `HASH(CONSTRUCTION)`.
    static let initialChainKey: [UInt8] = Blake2s.hash(Array(noiseConstruction.utf8))

    /// `HASH(initialChainKey ‖ IDENTIFIER)`.
    static let initialHash: [UInt8] = Blake2s.hash(initialChainKey + Array(identifier.utf8))

    // MARK: - Configuration

    /// Whether this side starts the handshake.
    public let isInitiator: Bool

    /// `HASH("mac1----" ‖ responder static public key)`.
    ///
    /// Both sides need the same value: the initiator uses it to authenticate
    /// messages it sends to the responder, and the responder uses it to check
    /// them.
    public let mac1Key: [UInt8]

    private let localStaticPrivate: [UInt8]
    private let localStaticPublic: Data
    private let remotePublic: Data
    private let presharedKey: Data?
    private let cookieKey: [UInt8]

    // MARK: - State

    /// Where this attempt has got to.
    public private(set) var state: State = .idle

    /// The session keys, available once the handshake completes.
    public private(set) var sessionKeys: Result?

    /// Our index for this attempt, available once we have sent a message.
    public var localIndex: UInt32? { index }

    /// The peer's index, available once we have accepted a message from it.
    public var remoteIndex: UInt32? { peerIndex }

    private var index: UInt32?
    private var peerIndex: UInt32?
    private var chainKey: [UInt8]
    private var transcriptHash: [UInt8]
    private var ephemeralPrivate: [UInt8]?
    private var remoteEphemeral: Data?
    private var cookie: [UInt8]?
    private var cookieReceivedAt: Date?
    private var lastSentMAC1: [UInt8]?
    private var lastSentMessage: Data?
    private var lastAcceptedTimestamp: [UInt8]?

    // MARK: - Test seams

    /// Supplies the ephemeral private key.
    ///
    /// Left unset (the default) the key comes from the system random number
    /// generator. Setting it makes a handshake reproducible, which is how the
    /// known-answer test pins the exact bytes of an initiation and a response.
    public var ephemeralKeyGenerator: (() -> [UInt8])?

    /// Supplies the local index.
    ///
    /// Left unset the index is random. A generator returning zero is corrected
    /// to one, because zero is not a usable index.
    public var indexGenerator: (() -> UInt32)?

    /// Supplies the TAI64N timestamp placed in a handshake initiation.
    ///
    /// Left unset (the default) the current time is used. Setting it makes a
    /// handshake reproducible, which is how the known-answer test pins the
    /// exact bytes of an initiation.
    public var timestampProvider: (() -> [UInt8])?

    // MARK: - Creation

    /// Creates a handshake.
    ///
    /// - Parameters:
    ///   - localStatic: Our private key: 32 raw bytes of X25519 scalar.
    ///   - remotePublic: The peer's public key: 32 raw bytes.
    ///   - presharedKey: The optional preshared key: exactly 32 raw bytes, or
    ///     `nil` for none. WireGuard mixes 32 zero bytes when there is none, so
    ///     `nil` and an all-zero key are equivalent on the wire.
    ///   - isInitiator: Whether we send the first message.
    public convenience init(localStatic: Data,
                            remotePublic: Data,
                            presharedKey: Data? = nil,
                            isInitiator: Bool) {
        self.init(localStatic: localStatic,
                  localStaticPublic: Data((try? X25519.publicKey(for: [UInt8](localStatic))) ?? []),
                  remotePublic: remotePublic,
                  presharedKey: presharedKey,
                  isInitiator: isInitiator)
    }

    /// Creates a handshake with an already known public key.
    ///
    /// A session caches its own public key, and passing it in saves a scalar
    /// multiplication for every inbound datagram, including ones that never
    /// authenticate.
    ///
    /// - Parameters:
    ///   - localStatic: Our private key: 32 raw bytes of X25519 scalar.
    ///   - localStaticPublic: The matching public key, already derived.
    ///   - remotePublic: The peer's public key: 32 raw bytes.
    ///   - presharedKey: The optional preshared key: exactly 32 raw bytes.
    ///   - isInitiator: Whether we send the first message.
    init(localStatic: Data,
         localStaticPublic: Data,
         remotePublic: Data,
         presharedKey: Data?,
         isInitiator: Bool) {
        self.localStaticPrivate = [UInt8](localStatic)
        self.localStaticPublic = localStaticPublic
        self.remotePublic = remotePublic
        self.presharedKey = presharedKey
        self.isInitiator = isInitiator
        self.chainKey = WireGuardHandshake.initialChainKey
        self.transcriptHash = WireGuardHandshake.initialHash

        // HASH(LABEL ‖ Spub_responder): the responder is the peer when we
        // initiate and ourselves when we respond.
        let responderPublic = isInitiator ? remotePublic : localStaticPublic
        self.mac1Key = Blake2s.hash(Array(WireGuardHandshake.labelMAC1.utf8) + [UInt8](responderPublic))
        self.cookieKey = Blake2s.hash(Array(WireGuardHandshake.labelCookie.utf8) + [UInt8](responderPublic))
    }

    #if canImport(CryptoKit)
    /// Creates a handshake from a CryptoKit private key.
    ///
    /// - Parameters:
    ///   - localStatic: Our private key.
    ///   - remotePublic: The peer's 32 byte public key.
    ///   - presharedKey: The optional 32 byte preshared key.
    ///   - isInitiator: Whether we send the first message.
    public convenience init(localStatic: Curve25519.KeyAgreement.PrivateKey,
                            remotePublic: Data,
                            presharedKey: Data? = nil,
                            isInitiator: Bool) {
        self.init(localStatic: Data(localStatic.rawRepresentation),
                  remotePublic: remotePublic,
                  presharedKey: presharedKey,
                  isInitiator: isInitiator)
    }

    /// Our public key, derived from the private key this handshake was given.
    public var localPublicKey: Data { localStaticPublic }
    #endif

    // MARK: - Initiator

    /// Builds and returns a handshake initiation message.
    ///
    /// The message is 148 bytes and carries freshly generated `mac1` (and, when
    /// a cookie is held, `mac2`) values. The same bytes are cached so that
    /// ``resendWithCookie()`` can retransmit them after a cookie reply.
    ///
    /// - Throws: ``VPNCryptoError`` when the configuration is unusable or the
    ///   attempt is not in a state to send an initiation.
    /// - Returns: The 148 byte message to send.
    public func createInitiation() throws -> Data {
        try validate()
        guard isInitiator else {
            throw VPNCryptoError.invalidState("this handshake is the responder's")
        }
        guard state == .idle else {
            throw VPNCryptoError.invalidState("the initiation has already been created")
        }

        chainKey = WireGuardHandshake.initialChainKey
        transcriptHash = WireGuardHandshake.initialHash

        // Hi = HASH(Hi ‖ Spub_r)
        mixHash(remotePublic)

        // (e, Ei) = DH_GENERATE()
        let ephemeral = generateEphemeralPrivateKey()
        guard let ephemeralPublic = try? X25519.publicKey(for: ephemeral),
              ephemeralPublic.count == WireGuardWireFormat.publicKeySize else {
            throw VPNCryptoError.invalidPublicKey
        }
        ephemeralPrivate = ephemeral
        mixKey(ephemeralPublic)
        mixHash(Data(ephemeralPublic))

        // (Ci, κ) = Kdf2(Ci, DH(Ei, Spub_r)); msg.static = AEAD(κ, 0, Spub_i, Hi)
        let ephemeralSecret = try X25519.sharedSecret(privateKey: ephemeral,
                                                     publicKey: [UInt8](remotePublic))
        var (updatedChainKey, key) = WireGuardKDF.kdf2(key: chainKey, input: ephemeralSecret)
        chainKey = updatedChainKey
        let encryptedStatic = try encryptAndHash([UInt8](localStaticPublic), key: key)

        // (Ci, κ) = Kdf2(Ci, DH(Si, Spub_r)); msg.timestamp = AEAD(κ, 0, TAI64N, Hi)
        let staticSecret = try X25519.sharedSecret(privateKey: localStaticPrivate,
                                                   publicKey: [UInt8](remotePublic))
        (updatedChainKey, key) = WireGuardKDF.kdf2(key: chainKey, input: staticSecret)
        chainKey = updatedChainKey
        let timestamp = timestampProvider?() ?? Tai64n.now()
        let encryptedTimestamp = try encryptAndHash(timestamp, key: key)

        let senderIndex = generateIndex()
        index = senderIndex

        let initiation = WireGuardInitiation(senderIndex: senderIndex,
                                             ephemeral: Data(ephemeralPublic),
                                             encryptedStatic: encryptedStatic,
                                             encryptedTimestamp: encryptedTimestamp,
                                             mac1: Data(repeating: 0, count: WireGuardWireFormat.macSize),
                                             mac2: Data(repeating: 0, count: WireGuardWireFormat.macSize))
        var bytes = [UInt8](initiation.serialized())
        applyMACs(to: &bytes,
                  mac1Offset: WireGuardWireFormat.initiationMAC1Offset,
                  mac2Offset: WireGuardWireFormat.initiationMAC2Offset)

        lastSentMessage = Data(bytes)
        state = .initiationCreated
        return Data(bytes)
    }

    /// Consumes a handshake response and derives the session keys.
    ///
    /// - Parameter message: The 92 byte response.
    /// - Throws: ``VPNCryptoError`` when the message is malformed, its `mac1`
    ///   does not verify, or the AEAD fails to authenticate.
    /// - Returns: The session keys.
    @discardableResult
    public func consumeResponse(_ message: Data) throws -> Result {
        try validate()
        guard isInitiator else {
            throw VPNCryptoError.invalidState("this handshake is the responder's")
        }
        guard state == .initiationCreated else {
            throw VPNCryptoError.invalidState("no initiation is outstanding")
        }
        guard let senderIndex = index, let ephemeral = ephemeralPrivate else {
            throw VPNCryptoError.invalidState("no initiation is outstanding")
        }
        guard let response = WireGuardResponse.parse(message) else {
            throw VPNCryptoError.malformedMessage("a handshake response must be 92 bytes")
        }
        guard response.receiverIndex == senderIndex else {
            throw VPNCryptoError.invalidState("the response is for a different handshake")
        }
        let bytes = [UInt8](message)
        guard verifyMAC1(bytes, mac1Offset: WireGuardWireFormat.responseMAC1Offset) else {
            throw VPNCryptoError.invalidMAC1
        }

        // Hi = HASH(Hi ‖ Epub_r); Ci = Kdf1(Ci, Epub_r)
        mixHash(response.ephemeral)
        mixKey([UInt8](response.ephemeral))

        // Ci = Kdf1(Ci, DH(Ei, Er))
        let ephemeralSecret = try X25519.sharedSecret(privateKey: ephemeral,
                                                     publicKey: [UInt8](response.ephemeral))
        mixKey(ephemeralSecret)

        // Ci = Kdf1(Ci, DH(Si, Er))
        let staticSecret = try X25519.sharedSecret(privateKey: localStaticPrivate,
                                                   publicKey: [UInt8](response.ephemeral))
        mixKey(staticSecret)

        // (Ci, τ, κ) = Kdf3(Ci, Q); msg.empty = AEAD(κ, 0, ε, Hi)
        let key = mixKeyAndHash(presharedKeyBytes())
        let empty = try decryptAndHash(response.encryptedEmpty, key: key)
        guard empty.isEmpty else {
            throw VPNCryptoError.malformedMessage("the response's empty field was not empty")
        }

        peerIndex = response.senderIndex

        // (T_send_i, T_recv_i) = Kdf2(Ci, ε)
        let (sendKey, receiveKey) = WireGuardKDF.kdf2(key: chainKey, input: [])
        let result = Result(sendKey: sendKey,
                            receiveKey: receiveKey,
                            remoteIndex: response.senderIndex,
                            localIndex: senderIndex)
        sessionKeys = result
        state = .responseConsumed
        wipeSecrets()
        return result
    }

    // MARK: - Responder

    /// Consumes a handshake initiation and returns the response to send.
    ///
    /// The responder is only useful to this engine for completeness and for the
    /// tests that prove a full round trip; a client tunnel always initiates.
    ///
    /// - Parameter message: The 148 byte initiation.
    /// - Throws: ``VPNCryptoError`` when the message is malformed, its `mac1`
    ///   does not verify, it names a different peer, or it is a replay of an
    ///   earlier initiation.
    /// - Returns: The 92 byte response to send.
    public func consumeInitiation(_ message: Data) throws -> Data {
        try validate()
        guard !isInitiator else {
            throw VPNCryptoError.invalidState("this handshake is the initiator's")
        }
        guard state == .idle else {
            throw VPNCryptoError.invalidState("an initiation has already been consumed")
        }
        guard let initiation = WireGuardInitiation.parse(message) else {
            throw VPNCryptoError.malformedMessage("a handshake initiation must be 148 bytes")
        }
        let bytes = [UInt8](message)
        guard verifyMAC1(bytes, mac1Offset: WireGuardWireFormat.initiationMAC1Offset) else {
            throw VPNCryptoError.invalidMAC1
        }

        chainKey = WireGuardHandshake.initialChainKey
        transcriptHash = WireGuardHandshake.initialHash

        // Hr = HASH(Hr ‖ Spub_r), with our own public key.
        mixHash(localStaticPublic)
        // Hr = HASH(Hr ‖ Epub_i); Cr = Kdf1(Cr, Epub_i)
        mixHash(initiation.ephemeral)
        mixKey([UInt8](initiation.ephemeral))

        // (Cr, κ) = Kdf2(Cr, DH(Sr, Epub_i)); Spub_i = AEAD⁻¹(κ, 0, msg.static, Hr)
        let ephemeralSecret = try X25519.sharedSecret(privateKey: localStaticPrivate,
                                                     publicKey: [UInt8](initiation.ephemeral))
        var (updatedChainKey, key) = WireGuardKDF.kdf2(key: chainKey, input: ephemeralSecret)
        chainKey = updatedChainKey
        let initiatorStatic = try decryptAndHash(initiation.encryptedStatic, key: key)
        guard initiatorStatic.count == WireGuardWireFormat.publicKeySize else {
            throw VPNCryptoError.malformedMessage("the initiation's static key is not 32 bytes")
        }
        // The decrypted static key must be the peer this handshake was built
        // for; otherwise the message is for somebody else and is dropped.
        guard initiatorStatic == remotePublic else {
            throw VPNCryptoError.invalidState("the initiation names an unexpected peer")
        }

        // (Cr, κ) = Kdf2(Cr, DH(Sr, Spub_i)); TAI64N = AEAD⁻¹(κ, 0, msg.timestamp, Hr)
        let staticSecret = try X25519.sharedSecret(privateKey: localStaticPrivate,
                                                   publicKey: [UInt8](initiatorStatic))
        (updatedChainKey, key) = WireGuardKDF.kdf2(key: chainKey, input: staticSecret)
        chainKey = updatedChainKey
        let timestamp = try decryptAndHash(initiation.encryptedTimestamp, key: key)
        guard timestamp.count == Tai64n.timestampSize else {
            throw VPNCryptoError.malformedMessage("the initiation's timestamp is not twelve bytes")
        }
        let timestampBytes = [UInt8](timestamp)

        // Replay protection: the timestamp must be strictly newer than the last
        // one this peer sent (whitepaper, section 5.1).
        if let last = lastAcceptedTimestamp, !Tai64n.isLater(timestampBytes, than: last) {
            throw VPNCryptoError.invalidState("the initiation is a replay")
        }
        lastAcceptedTimestamp = timestampBytes

        remoteEphemeral = initiation.ephemeral
        peerIndex = initiation.senderIndex
        state = .initiationConsumed

        return try createResponse()
    }

    /// Builds the handshake response after an initiation has been consumed.
    ///
    /// - Throws: ``VPNCryptoError`` when no initiation has been consumed.
    /// - Returns: The 92 byte response to send.
    private func createResponse() throws -> Data {
        guard let remoteEphemeral, let receiverIndex = peerIndex else {
            throw VPNCryptoError.invalidState("no initiation has been consumed")
        }

        // (e, Er) = DH_GENERATE()
        let ephemeral = generateEphemeralPrivateKey()
        guard let ephemeralPublic = try? X25519.publicKey(for: ephemeral),
              ephemeralPublic.count == WireGuardWireFormat.publicKeySize else {
            throw VPNCryptoError.invalidPublicKey
        }
        ephemeralPrivate = ephemeral

        // Hr = HASH(Hr ‖ Epub_r); Cr = Kdf1(Cr, Epub_r)
        mixHash(Data(ephemeralPublic))
        mixKey(ephemeralPublic)

        // Cr = Kdf1(Cr, DH(Er, Epub_i))
        let ephemeralSecret = try X25519.sharedSecret(privateKey: ephemeral,
                                                     publicKey: [UInt8](remoteEphemeral))
        mixKey(ephemeralSecret)

        // Cr = Kdf1(Cr, DH(Er, Spub_i))
        let staticSecret = try X25519.sharedSecret(privateKey: ephemeral,
                                                   publicKey: [UInt8](remotePublic))
        mixKey(staticSecret)

        // (Cr, τ, κ) = Kdf3(Cr, Q); Hr = HASH(Hr ‖ τ)
        let key = mixKeyAndHash(presharedKeyBytes())

        // msg.empty = AEAD(κ, 0, ε, Hr)
        let encryptedEmpty = try encryptAndHash([], key: key)

        let senderIndex = generateIndex()
        index = senderIndex

        let response = WireGuardResponse(senderIndex: senderIndex,
                                         receiverIndex: receiverIndex,
                                         ephemeral: Data(ephemeralPublic),
                                         encryptedEmpty: encryptedEmpty,
                                         mac1: Data(repeating: 0, count: WireGuardWireFormat.macSize),
                                         mac2: Data(repeating: 0, count: WireGuardWireFormat.macSize))
        var bytes = [UInt8](response.serialized())
        applyMACs(to: &bytes,
                  mac1Offset: WireGuardWireFormat.responseMAC1Offset,
                  mac2Offset: WireGuardWireFormat.responseMAC2Offset)

        lastSentMessage = Data(bytes)

        // (T_recv_r, T_send_r) = Kdf2(Cr, ε): the responder's sending key is
        // the second output, the initiator's is the first.
        let (receiveKey, sendKey) = WireGuardKDF.kdf2(key: chainKey, input: [])
        sessionKeys = Result(sendKey: sendKey,
                             receiveKey: receiveKey,
                             remoteIndex: receiverIndex,
                             localIndex: senderIndex)
        state = .responseCreated
        wipeSecrets()
        return Data(bytes)
    }

    // MARK: - Cookies

    /// Consumes a cookie reply and stores the cookie for the next message.
    ///
    /// - Parameters:
    ///   - message: The 64 byte cookie reply.
    ///   - triggeringMAC1: The `mac1` value of the message this reply answers.
    ///     Defaults to the `mac1` of the most recent message this handshake
    ///     sent, which is what the responder authenticated the reply with
    ///     (whitepaper, section 5.4.7).
    /// - Throws: ``VPNCryptoError/authenticationFailure`` when the reply does
    ///   not authenticate, which is also how a forged reply is rejected.
    /// - Returns: The stored cookie.
    @discardableResult
    public func consumeCookieReply(_ message: Data, triggeringMAC1: Data? = nil) throws -> [UInt8] {
        guard let reply = WireGuardCookieReply.parse(message) else {
            throw VPNCryptoError.malformedMessage("a cookie reply must be 64 bytes")
        }
        let associatedData = triggeringMAC1.map { [UInt8]($0) } ?? lastSentMAC1 ?? []
        let plaintext = try XChaCha20Poly1305.open(key: Data(cookieKey),
                                                   nonce24: reply.nonce,
                                                   ciphertext: reply.encryptedCookie,
                                                   authenticatedData: Data(associatedData))
        guard plaintext.count == WireGuardWireFormat.macSize else {
            throw VPNCryptoError.malformedMessage("a cookie must be sixteen bytes")
        }
        cookie = [UInt8](plaintext)
        cookieReceivedAt = Date()
        return [UInt8](plaintext)
    }

    /// Whether a cookie is currently held and still fresh.
    public var hasFreshCookie: Bool {
        guard cookie != nil, let received = cookieReceivedAt else { return false }
        return Date().timeIntervalSince(received) < WireGuardHandshake.cookieLifetime
    }

    /// Returns the last message again, with `mac2` recomputed from the cookie.
    ///
    /// A responder answers a message it will not process with a cookie reply,
    /// and the sender is expected to retransmit the same message with a valid
    /// `mac2` rather than start a new handshake, so that the responder's index
    /// and the timestamps stay consistent.
    ///
    /// - Throws: ``VPNCryptoError`` when there is nothing to resend.
    /// - Returns: The message to send, or `nil` when nothing has been sent yet.
    public func resendWithCookie() throws -> Data? {
        guard var bytes = lastSentMessage.map({ [UInt8]($0) }) else { return nil }
        let type = WireGuardMessageType(rawValue: LittleEndian.readUInt32(bytes, at: 0) ?? 0)
        let offsets: (mac1: Int, mac2: Int)
        switch type {
        case .handshakeInitiation:
            offsets = (WireGuardWireFormat.initiationMAC1Offset, WireGuardWireFormat.initiationMAC2Offset)
        case .handshakeResponse:
            offsets = (WireGuardWireFormat.responseMAC1Offset, WireGuardWireFormat.responseMAC2Offset)
        default:
            throw VPNCryptoError.invalidState("only handshake messages carry MACs")
        }
        applyMACs(to: &bytes, mac1Offset: offsets.mac1, mac2Offset: offsets.mac2)
        lastSentMessage = Data(bytes)
        return Data(bytes)
    }

    /// The `mac1` value of the most recent message this handshake sent.
    public var mostRecentMAC1: [UInt8]? { lastSentMAC1 }

    // MARK: - Matching

    /// Whether a message belongs to this handshake attempt.
    ///
    /// - Parameter message: A handshake message.
    /// - Returns: `true` when the message's indices match this attempt.
    public func matches(_ message: Data) -> Bool {
        let bytes = [UInt8](message)
        switch WireGuardMessageType(rawValue: LittleEndian.readUInt32(bytes, at: 0) ?? 0) {
        case .handshakeResponse:
            guard let response = WireGuardResponse.parse(message) else { return false }
            return response.receiverIndex == index
        case .cookieReply:
            guard let reply = WireGuardCookieReply.parse(message) else { return false }
            return reply.receiverIndex == index
        default:
            return false
        }
    }

    // MARK: - Internals

    /// Verifies the `mac1` field of a received message.
    ///
    /// - Parameters:
    ///   - bytes: The whole message.
    ///   - mac1Offset: Where `mac1` sits.
    /// - Returns: `true` when the MAC matches. The comparison is constant time.
    private func verifyMAC1(_ bytes: [UInt8], mac1Offset: Int) -> Bool {
        guard mac1Key.count == WireGuardWireFormat.publicKeySize else { return false }
        let end = mac1Offset + WireGuardWireFormat.macSize
        guard bytes.count >= end else { return false }
        let expected = Blake2s.mac(key: mac1Key,
                                  Array(bytes[0 ..< mac1Offset]),
                                  digestLength: WireGuardWireFormat.macSize)
        return constantTimeEquals(expected, Array(bytes[mac1Offset ..< end]))
    }

    /// Fills in `mac1` and `mac2`.
    ///
    /// `mac1` authenticates the message against the responder's public key;
    /// `mac2` is the cookie proof, or sixteen zero bytes when no fresh cookie is
    /// held (whitepaper, section 5.4.4).
    ///
    /// - Parameters:
    ///   - bytes: The message, modified in place.
    ///   - mac1Offset: Where `mac1` starts.
    ///   - mac2Offset: Where `mac2` starts.
    private func applyMACs(to bytes: inout [UInt8], mac1Offset: Int, mac2Offset: Int) {
        guard bytes.count >= mac2Offset + WireGuardWireFormat.macSize else { return }

        let mac1 = Blake2s.mac(key: mac1Key,
                               Array(bytes[0 ..< mac1Offset]),
                               digestLength: WireGuardWireFormat.macSize)
        for index in 0 ..< WireGuardWireFormat.macSize {
            bytes[mac1Offset + index] = mac1[index]
        }
        lastSentMAC1 = mac1

        if let cookie, hasFreshCookie {
            let mac2 = Blake2s.mac(key: cookie,
                                   Array(bytes[0 ..< mac2Offset]),
                                   digestLength: WireGuardWireFormat.macSize)
            for index in 0 ..< WireGuardWireFormat.macSize {
                bytes[mac2Offset + index] = mac2[index]
            }
        } else {
            for index in mac2Offset ..< mac2Offset + WireGuardWireFormat.macSize {
                bytes[index] = 0
            }
        }
    }

    /// `Ci = Kdf1(Ci, data)`.
    ///
    /// - Parameter data: The input key material.
    private func mixKey(_ data: [UInt8]) {
        chainKey = WireGuardKDF.kdf1(key: chainKey, input: data)
    }

    /// `Hi = HASH(Hi ‖ data)`.
    ///
    /// - Parameter data: The bytes to absorb.
    private func mixHash(_ data: Data) {
        transcriptHash = Blake2s.hash(transcriptHash + [UInt8](data))
    }

    /// `(Ci, τ, κ) = Kdf3(Ci, Q)` followed by `Hi = HASH(Hi ‖ τ)`.
    ///
    /// - Parameter input: The input key material, normally the preshared key.
    /// - Returns: The AEAD key `κ`.
    private func mixKeyAndHash(_ input: [UInt8]) -> [UInt8] {
        let (updatedChainKey, tau, key) = WireGuardKDF.kdf3(key: chainKey, input: input)
        chainKey = updatedChainKey
        transcriptHash = Blake2s.hash(transcriptHash + tau)
        return key
    }

    /// `EncryptAndHash`: seals with the transcript hash as associated data and
    /// absorbs the ciphertext.
    ///
    /// - Parameters:
    ///   - plaintext: The field to encrypt.
    ///   - key: The AEAD key from the preceding KDF.
    /// - Throws: ``VPNCryptoError`` when the AEAD fails.
    /// - Returns: Ciphertext followed by the tag.
    private func encryptAndHash(_ plaintext: [UInt8], key: [UInt8]) throws -> Data {
        let sealed = try ChaChaPolyAEAD.seal(key: key,
                                             nonce: WireGuardWireFormat.zeroNonce,
                                             plaintext: plaintext,
                                             authenticatedData: transcriptHash)
        transcriptHash = Blake2s.hash(transcriptHash + sealed)
        return Data(sealed)
    }

    /// `DecryptAndHash`: opens with the transcript hash as associated data and
    /// absorbs the ciphertext.
    ///
    /// - Parameters:
    ///   - ciphertext: The encrypted field, tag included.
    ///   - key: The AEAD key from the preceding KDF.
    /// - Throws: ``VPNCryptoError/authenticationFailure`` when the tag does not
    ///   verify.
    /// - Returns: The plaintext.
    private func decryptAndHash(_ ciphertext: Data, key: [UInt8]) throws -> Data {
        let plaintext = try ChaChaPolyAEAD.open(key: key,
                                               nonce: WireGuardWireFormat.zeroNonce,
                                               ciphertext: [UInt8](ciphertext),
                                               authenticatedData: transcriptHash)
        transcriptHash = Blake2s.hash(transcriptHash + [UInt8](ciphertext))
        return Data(plaintext)
    }

    /// The preshared key, or 32 zero bytes.
    ///
    /// - Returns: Exactly 32 bytes.
    private func presharedKeyBytes() -> [UInt8] {
        guard let presharedKey, presharedKey.count == WireGuardWireFormat.publicKeySize else {
            return [UInt8](repeating: 0, count: WireGuardWireFormat.publicKeySize)
        }
        return [UInt8](presharedKey)
    }

    /// Validates the keys this handshake was created with.
    ///
    /// - Throws: ``VPNCryptoError`` when a key has the wrong size.
    private func validate() throws {
        guard localStaticPrivate.count == WireGuardWireFormat.publicKeySize,
              localStaticPublic.count == WireGuardWireFormat.publicKeySize else {
            throw VPNCryptoError.invalidKeySize(expected: WireGuardWireFormat.publicKeySize,
                                                actual: localStaticPrivate.count)
        }
        guard remotePublic.count == WireGuardWireFormat.publicKeySize else {
            throw VPNCryptoError.invalidKeySize(expected: WireGuardWireFormat.publicKeySize,
                                                actual: remotePublic.count)
        }
        if let presharedKey, presharedKey.count != WireGuardWireFormat.publicKeySize {
            throw VPNCryptoError.invalidKeySize(expected: WireGuardWireFormat.publicKeySize,
                                                actual: presharedKey.count)
        }
    }

    /// Produces an ephemeral private key, honouring ``ephemeralKeyGenerator``.
    ///
    /// - Returns: 32 bytes of private scalar.
    private func generateEphemeralPrivateKey() -> [UInt8] {
        if let generator = ephemeralKeyGenerator {
            return generator()
        }
        return X25519.generatePrivateKey()
    }

    /// Produces a local index, honouring ``indexGenerator``.
    ///
    /// - Returns: A non-zero index.
    private func generateIndex() -> UInt32 {
        if let generator = indexGenerator {
            let value = generator()
            return value == 0 ? 1 : value
        }
        var value: UInt32 = 0
        while value == 0 {
            value = UInt32.random(in: .min ... .max)
        }
        return value
    }

    /// Zeroes the handshake secrets once the session keys exist.
    ///
    /// The whitepaper (section 5.4.5) calls for the chaining key and ephemeral
    /// private key to be discarded at this point.
    private func wipeSecrets() {
        chainKey = [UInt8](repeating: 0, count: 32)
        ephemeralPrivate = nil
    }
}
