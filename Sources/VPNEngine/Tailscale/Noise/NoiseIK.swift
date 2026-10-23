//
//  NoiseIK.swift
//  VPNEngine
//
//  The Noise `IK` handshake pattern (Noise Protocol Framework, revision 34,
//  section 9.2), written generically so that it can be instantiated for
//  Tailscale's control protocol rather than only for WireGuard.
//
//  `IK` means "the initiator knows the responder's static public key, and the
//  responder knows the initiator's", and it is the pattern Tailscale's ts2021
//  control protocol uses:
//
//      protocol_name = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
//
//  The transcript, in the spec's notation, with `e` and `s` the ephemeral and
//  static key pairs and `ee`, `es`, `se`, `ss` the Diffie-Hellman results:
//
//      initiator                                      responder
//      ---------                                      ---------
//      h  = HASH(protocol_name)                       h  = HASH(protocol_name)
//      ck = h                                         ck = h
//      h  = HASH(h ‖ prologue)                        h  = HASH(h ‖ prologue)
//      h  = HASH(h ‖ Spub_r)                          h  = HASH(h ‖ Spub_r)
//      --- message 1: e, es, s, ss ---
//      (e, Epub_i) = DH_GENERATE()
//      h  = HASH(h ‖ Epub_i)                          h  = HASH(h ‖ Epub_i)
//      ck, k = HKDF(ck, es)                           ck, k = HKDF(ck, es)
//      msg.s  = AEAD(k, 0, Spub_i, h)                 Spub_i = AEAD⁻¹(k, 0, msg.s, h)
//      h  = HASH(h ‖ msg.s)                           h  = HASH(h ‖ msg.s)
//      ck, k = HKDF(ck, ss)                           ck, k = HKDF(ck, ss)
//      msg.p  = AEAD(k, 0, payload, h)                payload = AEAD⁻¹(k, 0, msg.p, h)
//      h  = HASH(h ‖ msg.p)                           h  = HASH(h ‖ msg.p)
//      --- message 2: e, ee, se ---
//                                                     (e, Epub_r) = DH_GENERATE()
//      h  = HASH(h ‖ Epub_r)                          h  = HASH(h ‖ Epub_r)
//      ck, k = HKDF(ck, ee)                           ck, k = HKDF(ck, ee)
//      ck, k = HKDF(ck, se)                           ck, k = HKDF(ck, se)
//      payload = AEAD⁻¹(k, 0, msg.p, h)               msg.p = AEAD(k, 0, payload, h)
//      h  = HASH(h ‖ msg.p)                           h  = HASH(h ‖ msg.p)
//      --- split ---
//      k1, k2 = HKDF(ck, ε)                           k1, k2 = HKDF(ck, ε)
//      (send, receive) = (k1, k2)                     (send, receive) = (k2, k1)
//
//  Every Diffie-Hellman result is mixed with the Noise `HKDF` (RFC 5869's
//  extract-then-expand with HMAC-BLAKE2s-256), *not* with WireGuard's own
//  single-byte-counter KDF: the two constructions agree only when the chaining
//  key happens to be all zeros, which it never is.
//
//  References:
//   * Noise Protocol Framework, revision 34: https://noiseprotocol.org/noise.html
//   * Tailscale's control protocol: control/controlbase in
//     https://github.com/tailscale/tailscale (BSD-3-Clause)
//

import Foundation

/// The parameters one Noise `IK` handshake is instantiated with.
///
/// The defaults describe Tailscale's control protocol; a different protocol
/// name and prologue give a different instantiation without touching the state
/// machine.
public struct NoiseIKParameters: Sendable {

    /// The Noise protocol name, mixed into the initial hash.
    ///
    /// Its value is fixed by the Noise spec for a given choice of pattern, DH
    /// function, cipher and hash function.
    public var protocolName: String

    /// The prologue: arbitrary data both sides must agree on, mixed into the
    /// transcript before any key material.
    public var prologue: Data

    /// Our static private key: 32 raw bytes of X25519 scalar.
    public var localStatic: Data

    /// The peer's static public key: 32 raw bytes.
    ///
    /// The initiator must supply it. A *responder* may leave it empty, which
    /// means "I do not know who is connecting": the decrypted static key from
    /// message 1 is then accepted as-is. That is how Tailscale's control
    /// server works, because the handshake is unauthenticated at this layer
    /// and the node proves itself later.
    public var remoteStatic: Data

    /// Whether we send message 1.
    public var isInitiator: Bool

    /// Creates a set of handshake parameters.
    ///
    /// - Parameters:
    ///   - protocolName: The Noise protocol name.
    ///   - prologue: The prologue.
    ///   - localStatic: Our 32 byte static private key.
    ///   - remoteStatic: The peer's 32 byte static public key, or empty for a
    ///     responder that does not know it yet.
    ///   - isInitiator: Whether we send message 1.
    public init(protocolName: String = NoiseIKHandshake.protocolName,
                prologue: Data = Data(),
                localStatic: Data,
                remoteStatic: Data,
                isInitiator: Bool) {
        self.protocolName = protocolName
        self.prologue = prologue
        self.localStatic = localStatic
        self.remoteStatic = remoteStatic
        self.isInitiator = isInitiator
    }
}

/// One attempt at a Noise `IK` handshake.
///
/// A handshake object performs exactly one exchange: it is created, driven
/// through the two messages, and hands out the two ``NoiseCipherState``s that
/// follow. Every attempt uses a fresh ephemeral key, which is what the
/// pattern's forward secrecy rests on.
///
/// Not thread safe by design: the transport serialises access, and tests drive
/// an instance from one task.
public final class NoiseIKHandshake {

    // MARK: - Types

    /// Where a handshake attempt has got to.
    public enum State: Sendable, Equatable {

        /// Nothing has happened yet.
        case initial

        /// The initiator has written message 1.
        case message1Written

        /// The responder has read message 1.
        case message1Read

        /// The responder has written message 2, so its keys exist.
        case message2Written

        /// The initiator has read message 2, so its keys exist.
        case message2Read
    }

    // MARK: - Constants

    /// The Noise protocol name Tailscale's control protocol uses.
    ///
    /// `control/controlbase/handshake.go` in the Tailscale client pins this
    /// string, with the comment "This string's value is fixed by the Noise
    /// spec, and shouldn't be changed unless we're updating the control
    /// protocol to use a different Noise instance".
    public static let protocolName = "Noise_IK_25519_ChaChaPoly_BLAKE2s"

    /// Static and ephemeral public key size in bytes.
    public static let publicKeySize = X25519.keySize

    /// AEAD tag size in bytes.
    public static let tagSize = ChaCha20Poly1305.tagSize

    /// Size of the cleartext ephemeral public key that opens each message.
    public static let ephemeralSize = X25519.keySize

    /// Size of the encrypted static key field of message 1.
    public static let encryptedStaticSize = X25519.keySize + ChaCha20Poly1305.tagSize

    /// The smallest possible message 1: `e ‖ enc(s) ‖ tag` with an empty
    /// payload.
    public static let minimumMessage1Size = ephemeralSize + encryptedStaticSize + tagSize

    /// The smallest possible message 2: `e ‖ tag` with an empty payload.
    public static let minimumMessage2Size = ephemeralSize + tagSize

    // MARK: - Configuration

    /// The parameters this handshake was created with.
    public let parameters: NoiseIKParameters

    /// Whether this side starts the handshake.
    public var isInitiator: Bool { parameters.isInitiator }

    // MARK: - State

    /// Where this attempt has got to.
    public private(set) var state: State = .initial

    /// The final transcript hash, available once the handshake completes.
    ///
    /// Noise calls this `h` after the last `MixHash`; Tailscale calls it the
    /// handshake hash and uses it to bind other messages to the connection.
    public var handshakeHash: Data { Data(transcriptHash) }

    /// The chaining key, wiped once ``split()`` has run.
    private var chainingKey: [UInt8]

    /// The transcript hash, `h` in the spec.
    private var transcriptHash: [UInt8]

    /// Our ephemeral private key, wiped once the handshake completes.
    private var localEphemeral: [UInt8]?

    /// The peer's ephemeral public key.
    private var remoteEphemeral: Data?

    /// The static public key the responder learned from message 1.
    private var learnedInitiatorStatic: Data?

    /// The split keys, cached so ``split()`` cannot be called twice.
    private var splitKeys: (send: NoiseCipherState, receive: NoiseCipherState)?

    // MARK: - Test seams

    /// Supplies the ephemeral private key.
    ///
    /// Left unset (the default) the key comes from the system random number
    /// generator. Setting it makes a handshake reproducible, which is how the
    /// published Noise test vectors are replayed.
    public var ephemeralKeyGenerator: (() -> [UInt8])?

    // MARK: - Creation

    /// Creates a handshake.
    ///
    /// - Parameter parameters: The protocol name, prologue and keys.
    /// - Throws: ``VPNCryptoError`` when a key has the wrong size, or when the
    ///   local static key cannot produce a public key.
    public init(parameters: NoiseIKParameters) throws {
        guard parameters.localStatic.count == NoiseIKHandshake.publicKeySize else {
            throw VPNCryptoError.invalidKeySize(expected: NoiseIKHandshake.publicKeySize,
                                                actual: parameters.localStatic.count)
        }
        if parameters.isInitiator {
            guard parameters.remoteStatic.count == NoiseIKHandshake.publicKeySize else {
                throw VPNCryptoError.invalidKeySize(expected: NoiseIKHandshake.publicKeySize,
                                                    actual: parameters.remoteStatic.count)
            }
        } else if !parameters.remoteStatic.isEmpty,
                  parameters.remoteStatic.count != NoiseIKHandshake.publicKeySize {
            throw VPNCryptoError.invalidKeySize(expected: NoiseIKHandshake.publicKeySize,
                                                actual: parameters.remoteStatic.count)
        }

        self.parameters = parameters
        self.localStaticPublic = try NoiseIKHandshake.publicKey(for: parameters.localStatic)

        // InitializeSymmetric(protocol_name): ck = h = HASH(protocol_name).
        let initial = Blake2s.hash(Array(parameters.protocolName.utf8))
        self.chainingKey = initial
        self.transcriptHash = initial

        // MixHash(prologue), then the responder's static public key (`<- s`).
        // Both sides mix the *responder's* key, so the responder mixes its own.
        let responderStatic = parameters.isInitiator ? parameters.remoteStatic : localStaticPublic
        mixHash(parameters.prologue)
        mixHash(responderStatic)
    }

    // MARK: - Key helpers

    /// Our static public key, derived from the private key this handshake was
    /// given.
    public let localStaticPublic: Data

    /// Generates a new X25519 static key pair.
    ///
    /// - Returns: The 32 byte private key and its 32 byte public key.
    public static func generateStatic() -> (privateKey: Data, publicKey: Data) {
        let privateKey = X25519.generatePrivateKey()
        let publicKey = (try? X25519.publicKey(for: privateKey)) ?? []
        return (Data(privateKey), Data(publicKey))
    }

    /// Derives the public key for an X25519 private key.
    ///
    /// - Parameter privateKey: 32 bytes of private scalar.
    /// - Throws: ``VPNCryptoError`` when the key is the wrong size or the
    ///   platform has no X25519.
    /// - Returns: 32 bytes of public key.
    public static func publicKey(for privateKey: Data) throws -> Data {
        Data(try X25519.publicKey(for: [UInt8](privateKey)))
    }

    /// Derives the raw X25519 shared secret.
    ///
    /// - Parameters:
    ///   - privateKey: Our 32 byte private key.
    ///   - publicKey: The peer's 32 byte public key.
    /// - Throws: ``VPNCryptoError`` for bad sizes or a low order point.
    /// - Returns: 32 bytes of shared secret.
    private static func diffieHellman(_ privateKey: [UInt8], _ publicKey: Data) throws -> [UInt8] {
        try X25519.sharedSecret(privateKey: privateKey, publicKey: [UInt8](publicKey))
    }

    // MARK: - Initiator

    /// Builds message 1: `e, es, s, ss`.
    ///
    /// The message is `e ‖ AEAD(es, 0, Spub_i, h) ‖ AEAD(ss, 0, payload, h)`:
    /// a 32 byte cleartext ephemeral public key, the initiator's static public
    /// key encrypted with the `es` key, and the caller's payload encrypted with
    /// the `ss` key.
    ///
    /// - Parameter payload: The message payload, encrypted and authenticated
    ///   but not visible on the wire. Tailscale's control protocol sends an
    ///   empty payload here.
    /// - Throws: ``VPNCryptoError`` when the handshake is not in a state to
    ///   send message 1, or when a Diffie-Hellman or AEAD step fails.
    /// - Returns: The message to send.
    public func writeMessage1(payload: Data = Data()) throws -> Data {
        guard isInitiator else {
            throw VPNCryptoError.invalidState("this handshake is the responder's")
        }
        guard state == .initial else {
            throw VPNCryptoError.invalidState("message 1 has already been written")
        }

        // (e, Epub_i) = DH_GENERATE()
        let ephemeral = generateEphemeral()
        let ephemeralPublic = try NoiseIKHandshake.publicKey(for: Data(ephemeral))
        guard ephemeralPublic.count == NoiseIKHandshake.publicKeySize else {
            throw VPNCryptoError.invalidPublicKey
        }
        localEphemeral = ephemeral

        // h = HASH(h ‖ Epub_i)
        mixHash(ephemeralPublic)

        // ck, k = HKDF(ck, es); msg.s = AEAD(k, 0, Spub_i, h)
        let ephemeralSecret = try NoiseIKHandshake.diffieHellman(ephemeral, parameters.remoteStatic)
        var key = mixKey(ephemeralSecret)
        let encryptedStatic = try encryptAndHash(localStaticPublic, key: key)

        // ck, k = HKDF(ck, ss); msg.p = AEAD(k, 0, payload, h)
        let staticSecret = try NoiseIKHandshake.diffieHellman([UInt8](parameters.localStatic),
                                                              parameters.remoteStatic)
        key = mixKey(staticSecret)
        let encryptedPayload = try encryptAndHash(payload, key: key)

        state = .message1Written
        return ephemeralPublic + encryptedStatic + encryptedPayload
    }

    /// Consumes message 2 and derives the session keys.
    ///
    /// - Parameter message: The responder's message.
    /// - Throws: ``VPNCryptoError`` when the message is malformed or does not
    ///   authenticate.
    /// - Returns: The decrypted payload.
    @discardableResult
    public func readMessage2(_ message: Data) throws -> Data {
        guard isInitiator else {
            throw VPNCryptoError.invalidState("this handshake is the responder's")
        }
        guard state == .message1Written else {
            throw VPNCryptoError.invalidState("message 1 has not been written")
        }
        guard let ephemeral = localEphemeral else {
            throw VPNCryptoError.invalidState("message 1 has not been written")
        }
        guard message.count >= NoiseIKHandshake.minimumMessage2Size else {
            throw VPNCryptoError.malformedMessage(
                "a Noise IK message 2 is at least \(NoiseIKHandshake.minimumMessage2Size) bytes")
        }

        // <- e, ee, se
        let ephemeralPublic = Data(message.prefix(NoiseIKHandshake.ephemeralSize))
        let encryptedPayload = Data(message.dropFirst(NoiseIKHandshake.ephemeralSize))
        remoteEphemeral = ephemeralPublic

        // h = HASH(h ‖ Epub_r)
        mixHash(ephemeralPublic)

        // ck, k = HKDF(ck, ee)
        let ephemeralSecret = try NoiseIKHandshake.diffieHellman(ephemeral, ephemeralPublic)
        var key = mixKey(ephemeralSecret)

        // ck, k = HKDF(ck, se)
        let staticSecret = try NoiseIKHandshake.diffieHellman([UInt8](parameters.localStatic),
                                                              ephemeralPublic)
        key = mixKey(staticSecret)

        // payload = AEAD⁻¹(k, 0, msg.p, h)
        let payload = try decryptAndHash(encryptedPayload, key: key)

        state = .message2Read
        return payload
    }

    // MARK: - Responder

    /// Consumes message 1.
    ///
    /// - Parameter message: The initiator's message.
    /// - Throws: ``VPNCryptoError`` when the message is malformed, does not
    ///   authenticate, or names a static key this handshake was not built for
    ///   (only checked when ``NoiseIKParameters/remoteStatic`` was supplied).
    /// - Returns: The decrypted payload.
    @discardableResult
    public func readMessage1(_ message: Data) throws -> Data {
        guard !isInitiator else {
            throw VPNCryptoError.invalidState("this handshake is the initiator's")
        }
        guard state == .initial else {
            throw VPNCryptoError.invalidState("message 1 has already been read")
        }
        guard message.count >= NoiseIKHandshake.minimumMessage1Size else {
            throw VPNCryptoError.malformedMessage(
                "a Noise IK message 1 is at least \(NoiseIKHandshake.minimumMessage1Size) bytes")
        }

        // -> e, es, s, ss
        let ephemeralPublic = Data(message.prefix(NoiseIKHandshake.ephemeralSize))
        let staticStart = NoiseIKHandshake.ephemeralSize
        let staticEnd = staticStart + NoiseIKHandshake.encryptedStaticSize
        let encryptedStatic = Data(message[staticStart ..< staticEnd])
        let encryptedPayload = Data(message[staticEnd...])
        remoteEphemeral = ephemeralPublic

        // h = HASH(h ‖ Epub_i)
        mixHash(ephemeralPublic)

        // ck, k = HKDF(ck, es); Spub_i = AEAD⁻¹(k, 0, msg.s, h)
        let ephemeralSecret = try NoiseIKHandshake.diffieHellman([UInt8](parameters.localStatic),
                                                                 ephemeralPublic)
        var key = mixKey(ephemeralSecret)
        let initiatorStatic = try decryptAndHash(encryptedStatic, key: key)
        guard initiatorStatic.count == NoiseIKHandshake.publicKeySize else {
            throw VPNCryptoError.malformedMessage("the message's static key is not 32 bytes")
        }
        if !parameters.remoteStatic.isEmpty, initiatorStatic != parameters.remoteStatic {
            throw VPNCryptoError.invalidState("the message names an unexpected static key")
        }
        learnedInitiatorStatic = initiatorStatic

        // ck, k = HKDF(ck, ss); payload = AEAD⁻¹(k, 0, msg.p, h)
        let staticSecret = try NoiseIKHandshake.diffieHellman([UInt8](parameters.localStatic),
                                                              initiatorStatic)
        key = mixKey(staticSecret)
        let payload = try decryptAndHash(encryptedPayload, key: key)

        state = .message1Read
        return payload
    }

    /// Builds message 2: `e, ee, se`.
    ///
    /// The message is `e ‖ AEAD(se, 0, payload, h)`. After this call the
    /// responder's split keys exist, so ``split()`` may be used.
    ///
    /// - Parameter payload: The message payload. Tailscale's control protocol
    ///   sends an empty payload here.
    /// - Throws: ``VPNCryptoError`` when message 1 has not been read or a
    ///   Diffie-Hellman or AEAD step fails.
    /// - Returns: The message to send.
    public func writeMessage2(payload: Data = Data()) throws -> Data {
        guard !isInitiator else {
            throw VPNCryptoError.invalidState("this handshake is the initiator's")
        }
        guard state == .message1Read else {
            throw VPNCryptoError.invalidState("message 1 has not been read")
        }
        guard let remoteEphemeral, let initiatorStatic = learnedInitiatorStatic else {
            throw VPNCryptoError.invalidState("message 1 has not been read")
        }

        // (e, Epub_r) = DH_GENERATE()
        let ephemeral = generateEphemeral()
        let ephemeralPublic = try NoiseIKHandshake.publicKey(for: Data(ephemeral))
        guard ephemeralPublic.count == NoiseIKHandshake.publicKeySize else {
            throw VPNCryptoError.invalidPublicKey
        }
        localEphemeral = ephemeral

        // h = HASH(h ‖ Epub_r)
        mixHash(ephemeralPublic)

        // ck, k = HKDF(ck, ee)
        let ephemeralSecret = try NoiseIKHandshake.diffieHellman(ephemeral, remoteEphemeral)
        var key = mixKey(ephemeralSecret)

        // ck, k = HKDF(ck, se)
        let staticSecret = try NoiseIKHandshake.diffieHellman(ephemeral, initiatorStatic)
        key = mixKey(staticSecret)

        // msg.p = AEAD(k, 0, payload, h)
        let encryptedPayload = try encryptAndHash(payload, key: key)

        state = .message2Written
        return ephemeralPublic + encryptedPayload
    }

    // MARK: - Completion

    /// Whether the handshake has completed and ``split()`` may be called.
    public var isComplete: Bool {
        state == .message2Read || state == .message2Written
    }

    /// Splits the chaining key into the two transport keys.
    ///
    /// `k1, k2 = HKDF(ck, ε)`. The initiator sends with `k1` and receives with
    /// `k2`; the responder does the opposite. Calling this a second time
    /// returns the same two states, so a caller that loses the first result
    /// does not silently fork the connection.
    ///
    /// - Throws: ``VPNCryptoError/invalidState(_:)`` when the handshake has not
    ///   completed.
    /// - Returns: The states to seal outbound records with and to open inbound
    ///   records with.
    public func split() throws -> (send: NoiseCipherState, receive: NoiseCipherState) {
        if let splitKeys { return splitKeys }
        guard isComplete else {
            throw VPNCryptoError.invalidState("the handshake has not completed")
        }

        let material = NoiseHKDF.derive(salt: chainingKey,
                                        inputKeyMaterial: [],
                                        outputLength: NoiseCipherState.keySize * 2)
        let first = try NoiseCipherState(key: Data(material.prefix(NoiseCipherState.keySize)))
        let second = try NoiseCipherState(key: Data(material.suffix(NoiseCipherState.keySize)))

        let keys = isInitiator
            ? (send: first, receive: second)
            : (send: second, receive: first)
        splitKeys = keys

        // Section 5.3: the chaining key and the ephemeral private key are
        // discarded once the handshake is over.
        chainingKey = [UInt8](repeating: 0, count: Blake2s.maxDigestLength)
        localEphemeral = nil
        return keys
    }

    // MARK: - Internals

    /// `h = HASH(h ‖ data)` (Noise spec, section 5.2).
    private func mixHash(_ data: Data) {
        transcriptHash = Blake2s.hash(transcriptHash + [UInt8](data))
    }

    /// `ck, k = HKDF(ck, input)` (Noise spec, section 5.2, `MixKey`).
    ///
    /// - Parameter input: The input key material, normally a Diffie-Hellman
    ///   result.
    /// - Returns: The AEAD key `k`; `ck` is updated in place.
    private func mixKey(_ input: [UInt8]) -> [UInt8] {
        let material = NoiseHKDF.derive(salt: chainingKey,
                                        inputKeyMaterial: input,
                                        outputLength: NoiseCipherState.keySize * 2)
        chainingKey = Array(material.prefix(NoiseCipherState.keySize))
        return Array(material.suffix(NoiseCipherState.keySize))
    }

    /// `EncryptAndHash`: seals with the transcript hash as associated data,
    /// with a nonce of zero, and absorbs the ciphertext.
    ///
    /// Every handshake key is used for exactly one AEAD operation, which is why
    /// the nonce is always zero here.
    ///
    /// - Parameters:
    ///   - plaintext: The field to encrypt.
    ///   - key: The AEAD key from the preceding ``mixKey(_:)``.
    /// - Throws: ``VPNCryptoError`` when the AEAD fails.
    /// - Returns: Ciphertext followed by the tag.
    private func encryptAndHash(_ plaintext: Data, key: [UInt8]) throws -> Data {
        let sealed = try ChaChaPolyAEAD.seal(key: key,
                                             nonce: NoiseIKHandshake.zeroNonce,
                                             plaintext: [UInt8](plaintext),
                                             authenticatedData: transcriptHash)
        mixHash(Data(sealed))
        return Data(sealed)
    }

    /// `DecryptAndHash`: opens with the transcript hash as associated data and
    /// absorbs the ciphertext.
    ///
    /// - Parameters:
    ///   - ciphertext: The encrypted field, tag included.
    ///   - key: The AEAD key from the preceding ``mixKey(_:)``.
    /// - Throws: ``VPNCryptoError/authenticationFailure`` when the tag does not
    ///   verify.
    /// - Returns: The plaintext.
    private func decryptAndHash(_ ciphertext: Data, key: [UInt8]) throws -> Data {
        let plaintext = try ChaChaPolyAEAD.open(key: key,
                                                nonce: NoiseIKHandshake.zeroNonce,
                                                ciphertext: [UInt8](ciphertext),
                                                authenticatedData: transcriptHash)
        mixHash(ciphertext)
        return Data(plaintext)
    }

    /// The all-zero nonce every handshake AEAD operation uses.
    private static let zeroNonce = [UInt8](repeating: 0, count: ChaCha20Poly1305.nonceSize)

    /// Produces an ephemeral private key, honouring ``ephemeralKeyGenerator``.
    ///
    /// - Returns: 32 bytes of private scalar.
    private func generateEphemeral() -> [UInt8] {
        if let generator = ephemeralKeyGenerator {
            return generator()
        }
        return X25519.generatePrivateKey()
    }
}

/// HKDF (RFC 5869) with HMAC-BLAKE2s-256, the key derivation function the
/// Noise framework uses for `MixKey` and `Split`.
///
/// Noise deliberately uses a *different* construction from WireGuard's own KDF
/// even though both are built from HMAC-BLAKE2s: WireGuard's `Kdf_n` chains
/// `HMAC(tau_0, tau_(i-1) ‖ i)` over single byte counters, while Noise calls
/// RFC 5869 with an explicit salt. They are not interchangeable, which is why
/// this lives here rather than reusing ``WireGuardKDF`` wholesale. Only the
/// HMAC primitive itself is shared.
///
/// References:
///  * RFC 5869, sections 2.2 and 2.3
///  * Noise spec, section 4.2 (`HKDF`)
enum NoiseHKDF {

    /// The hash output size, which is also the HMAC block padding base.
    static let hashLength = Blake2s.maxDigestLength

    /// RFC 5869 section 2.2: `PRK = HMAC-Hash(salt, IKM)`.
    ///
    /// - Parameters:
    ///   - salt: The salt, or empty to use `hashLength` zero bytes.
    ///   - inputKeyMaterial: The input key material.
    /// - Returns: 32 bytes of pseudo random key.
    static func extract(salt: [UInt8], inputKeyMaterial: [UInt8]) -> [UInt8] {
        let effectiveSalt = salt.isEmpty
            ? [UInt8](repeating: 0, count: hashLength)
            : salt
        return WireGuardKDF.hmac(key: effectiveSalt, input: inputKeyMaterial)
    }

    /// RFC 5869 section 2.3: `T(i) = HMAC-Hash(PRK, T(i-1) ‖ info ‖ i)`.
    ///
    /// - Parameters:
    ///   - pseudoRandomKey: The output of ``extract(salt:inputKeyMaterial:)``.
    ///   - info: Optional context and application specific information.
    ///   - outputLength: How many bytes to produce, at most `255 * 32`.
    /// - Returns: `outputLength` bytes of output key material.
    static func expand(pseudoRandomKey: [UInt8], info: [UInt8], outputLength: Int) -> [UInt8] {
        guard outputLength > 0 else { return [] }
        let blocks = (outputLength + hashLength - 1) / hashLength
        guard blocks <= 255 else { return [] }

        var output: [UInt8] = []
        output.reserveCapacity(blocks * hashLength)
        var previous: [UInt8] = []
        for index in 1 ... blocks {
            previous = WireGuardKDF.hmac(key: pseudoRandomKey,
                                        input: previous + info + [UInt8(index)])
            output.append(contentsOf: previous)
        }
        return Array(output.prefix(outputLength))
    }

    /// The whole RFC 5869 construction.
    ///
    /// - Parameters:
    ///   - salt: The salt, or empty for none.
    ///   - inputKeyMaterial: The input key material.
    ///   - info: Optional context and application specific information.
    ///   - outputLength: How many bytes to produce.
    /// - Returns: `outputLength` bytes of output key material.
    static func derive(salt: [UInt8],
                       inputKeyMaterial: [UInt8],
                       info: [UInt8] = [],
                       outputLength: Int) -> [UInt8] {
        expand(pseudoRandomKey: extract(salt: salt, inputKeyMaterial: inputKeyMaterial),
               info: info,
               outputLength: outputLength)
    }
}
