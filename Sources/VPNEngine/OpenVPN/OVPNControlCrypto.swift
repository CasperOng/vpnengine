import Foundation

/// A control channel packet that has been unwrapped (decrypted and, with
/// tls-auth, authenticated).
public struct OVPNUnwrappedControlPacket: Sendable, Equatable {
    /// The first byte, `(opcode << 3) | key_id`.
    public var opcodeByte: UInt8
    /// The opcode carried by that byte.
    public var opcode: OVPNControlOpcode
    /// Key id carried by that byte.
    public var keyID: UInt8
    /// The sender's session id (bytes 1...8 of the packet).
    public var sessionID: OVPNSessionID
    /// The control channel packet id, when the packet carried one (tls-auth
    /// and tls-crypt only; plain control channels have no crypto packet id).
    public var packetID: OVPNPacketID?
    /// Everything after the header: `ack array || msg packet id || payload`
    /// for tls-auth/tls-crypt, or everything after the session id when the
    /// control channel is unprotected.
    public var plaintext: Data
    /// Bytes that follow the ciphertext, used by tls-crypt-v2 to carry the
    /// wrapped client key.
    public var appended: Data

    /// Create an unwrapped packet value.
    public init(
        opcodeByte: UInt8,
        opcode: OVPNControlOpcode,
        keyID: UInt8,
        sessionID: OVPNSessionID,
        packetID: OVPNPacketID?,
        plaintext: Data,
        appended: Data = Data()
    ) {
        self.opcodeByte = opcodeByte
        self.opcode = opcode
        self.keyID = keyID
        self.sessionID = sessionID
        self.packetID = packetID
        self.plaintext = plaintext
        self.appended = appended
    }
}

/// The control channel's packet authentication and encryption, selected by
/// `--tls-auth` or `--tls-crypt`.
///
/// ## Plain (`TLS_WRAP_NONE`)
///
/// ```
///  op / key_id (1) | session id (8) | ack array | msg packet id | payload
/// ```
///
/// ## `--tls-auth` (`TLS_WRAP_AUTH`, `tls_auth_wrap()` in `ssl_pkt.c`)
///
/// ```
///  op (1) | session id (8) | HMAC (n) | packet id (8) | ack array | msg pid | payload
/// ```
///
/// The HMAC is inserted *before* the packet id, and it covers the packet in
/// OpenVPN's internal byte order, which `swap_hmac()` in `ssl_pkt.c`
/// documents:
///
/// ```
///   "onwire"   [opcode, session id][hmac, packet id][remainder]
///   "internal" [hmac, packet id][opcode, session id][remainder]
/// ```
///
/// so the MAC input is `packet id || opcode || session id || remainder`.
/// The packet id is the long form (8 bytes) and is what the control channel
/// replays are checked against.
///
/// ## `--tls-crypt` (`TLS_WRAP_CRYPT`, `tls_crypt_wrap()` in `tls_crypt.c`)
///
/// ```
///   op (1) | session id (8) | packet id (8) | tag (32) | AES-256-CTR(payload)
///   \___________________  authenticated and used as the tag input ___________________/
/// ```
///
/// Offsets come straight from `tls_crypt.h`:
/// `TLS_CRYPT_OFF_PID = 1 + 8`, `TLS_CRYPT_OFF_TAG = 17`,
/// `TLS_CRYPT_OFF_CT = 49`. The 32-byte `tag` is
/// `HMAC-SHA256(hmac key, header || plaintext)` and the AES-CTR IV for the
/// payload is the **first 16 bytes of the tag** ("synthetic IV"). Nothing is
/// sent in the clear: the ack array, the message packet id and the TLS record
/// all live inside the ciphertext.
public struct OVPNControlCrypto: Sendable {

    /// Which wrapping scheme is active.
    public enum Mode: Sendable, Equatable {
        /// No control channel authentication (`TLS_WRAP_NONE`).
        case none
        /// `--tls-auth`: HMAC only.
        case tlsAuth
        /// `--tls-crypt` / `--tls-crypt-v2`: encrypted and authenticated.
        case tlsCrypt
    }

    /// Active mode.
    public let mode: Mode
    /// Digest used by ``Mode/tlsAuth``.
    public let digest: OVPNHMACAlgorithm
    /// HMAC key: `key.hmac[:digest_length]` for tls-auth, the full 64-byte
    /// `key.hmac` for tls-crypt.
    public let sendHMACKey: Data
    /// HMAC key for the receive direction.
    public let receiveHMACKey: Data
    /// AES-256-CTR key for tls-crypt.
    public let sendCipherKey: Data
    /// AES-256-CTR key for the receive direction.
    public let receiveCipherKey: Data

    /// Replay window for the control channel packet ids.
    private let replayWindow: OVPNReplayWindow

    /// Internal memberwise initialiser (also used by
    /// ``OVPNControlCrypto/unprotected``).
    init(
        mode: Mode,
        digest: OVPNHMACAlgorithm,
        sendHMACKey: Data,
        receiveHMACKey: Data,
        sendCipherKey: Data,
        receiveCipherKey: Data
    ) {
        self.mode = mode
        self.digest = digest
        self.sendHMACKey = sendHMACKey
        self.receiveHMACKey = receiveHMACKey
        self.sendCipherKey = sendCipherKey
        self.receiveCipherKey = receiveCipherKey
        self.replayWindow = OVPNReplayWindow(windowSize: 64, timeBacktrack: 15)
    }

    /// Build the control channel crypto from the configuration.
    ///
    /// - Parameters:
    ///   - tlsAuthKey: `--tls-auth` key file, if any.
    ///   - tlsCryptKey: `--tls-crypt` key file, if any.
    ///   - tlsCryptV2ClientKey: `--tls-crypt-v2` client key, if any (the
    ///     tls-crypt wrapping then uses the key from that file).
    ///   - digest: digest for tls-auth. OpenVPN 2.6 uses SHA-256; 2.5 and
    ///     earlier use SHA-1.
    /// - Throws: ``OVPNError/invalidStaticKey(_:)`` when key material is
    ///   missing or too short.
    public init(
        tlsAuthKey: OVPNStaticKeyFile?,
        tlsCryptKey: OVPNStaticKeyFile?,
        tlsCryptV2ClientKey: OVPNTlsCryptV2ClientKey? = nil,
        digest: OVPNHMACAlgorithm = .sha256
    ) throws {
        // tls-crypt wins if both are configured (OpenVPN rejects that
        // combination, but being permissive here costs nothing).
        if let tlsCryptV2ClientKey {
            // The client key file *is* a 128-byte key block: 64-byte cipher
            // field then 64-byte HMAC field. OpenVPN always uses it
            // bidirectionally (`tls_crypt_init_key` uses
            // KEY_DIRECTION_BIDIRECTIONAL).
            self.init(
                mode: .tlsCrypt,
                digest: digest,
                sendHMACKey: tlsCryptV2ClientKey.key.hmacKey,
                receiveHMACKey: tlsCryptV2ClientKey.key.hmacKey,
                sendCipherKey: try tlsCryptV2ClientKey.key.cipherKey(length: 32),
                receiveCipherKey: try tlsCryptV2ClientKey.key.cipherKey(length: 32)
            )
        } else if let tlsCryptKey {
            guard let keyBlock = try? OVPNKeyBlock(raw: tlsCryptKey.key.clientSendKey) else {
                throw OVPNError.invalidStaticKey("tls-crypt key block is not 128 bytes")
            }
            self.init(
                mode: .tlsCrypt,
                digest: digest,
                sendHMACKey: keyBlock.hmacKey,
                receiveHMACKey: keyBlock.hmacKey,
                sendCipherKey: try keyBlock.cipherKey(length: 32),
                receiveCipherKey: try keyBlock.cipherKey(length: 32)
            )
        } else if let tlsAuthKey {
            self.init(
                mode: .tlsAuth,
                digest: digest,
                sendHMACKey: try tlsAuthKey.sendKeyBlock.hmacKey(digestLength: digest.macLength),
                receiveHMACKey: try tlsAuthKey.recvKeyBlock.hmacKey(digestLength: digest.macLength),
                sendCipherKey: Data(),
                receiveCipherKey: Data()
            )
        } else {
            self.init(
                mode: .none,
                digest: digest,
                sendHMACKey: Data(),
                receiveHMACKey: Data(),
                sendCipherKey: Data(),
                receiveCipherKey: Data()
            )
        }
    }

    /// Bytes of overhead this scheme adds to a control packet, used to keep
    /// control packets inside the link MTU.
    public var overhead: Int {
        switch mode {
        case .none: return 0
        case .tlsAuth: return digest.macLength + 8
        case .tlsCrypt: return 8 + 32
        }
    }

    /// Wrap a reliable payload into a complete control channel datagram.
    ///
    /// - Parameters:
    ///   - opcodeByte: `(opcode << 3) | key_id`.
    ///   - sessionID: our session id.
    ///   - packetID: the crypto packet id for this transmission.
    ///   - payload: `ack array || msg packet id || TLS bytes`.
    ///   - appended: extra bytes after the ciphertext (the tls-crypt-v2
    ///     wrapped client key on reset packets).
    public func wrap(
        opcodeByte: UInt8,
        sessionID: OVPNSessionID,
        packetID: OVPNPacketID,
        payload: Data,
        appended: Data = Data()
    ) throws -> Data {
        switch mode {
        case .none:
            var out = Data([opcodeByte])
            out.append(sessionID.bytes)
            out.append(payload)
            return out
        case .tlsAuth:
            var macInput = Data()
            macInput.append(packetID.wireBytes)
            macInput.append(opcodeByte)
            macInput.append(sessionID.bytes)
            macInput.append(payload)
            let mac = digest.authenticate(key: sendHMACKey, data: macInput)

            var out = Data([opcodeByte])
            out.append(sessionID.bytes)
            out.append(mac)
            out.append(packetID.wireBytes)
            out.append(payload)
            return out
        case .tlsCrypt:
            // `packet_id_write(..., prepend: false)` in tls_crypt_wrap: the
            // header is opcode | session id | id | timestamp.
            var header = Data([opcodeByte])
            header.append(sessionID.bytes)
            header.append(packetID.wireBytes)

            var tagInput = header
            tagInput.append(payload)
            let tag = OVPNHMACAlgorithm.sha256.authenticate(key: sendHMACKey, data: tagInput)

            let iv = tag.prefix(16)
            let ciphertext = try OVPNAES.ctr(key: sendCipherKey, iv: iv, data: payload)

            var out = header
            out.append(tag)
            out.append(ciphertext)
            out.append(appended)
            return out
        }
    }

    /// Unwrap a received datagram.
    ///
    /// - Parameters:
    ///   - datagram: the raw UDP payload.
    ///   - trailingBytes: number of bytes at the end of the datagram that are
    ///     *not* ciphertext. Only tls-crypt-v2 needs this: a client appends its
    ///     wrapped client key after the ciphertext, and only the receiver can
    ///     know how long that blob is (it is length prefixed inside the blob,
    ///     which is what `tls_crypt_v2_unwrap()` reads). Passing 0 — the
    ///     default, and always right for a client — treats the whole datagram
    ///     after the tag as ciphertext.
    /// - Throws: ``OVPNError`` for truncated packets, failed authentication or
    ///   a replayed packet id. Malformed input never traps.
    public func unwrap(_ datagram: Data, trailingBytes: Int = 0) throws -> OVPNUnwrappedControlPacket {
        let headerLength = 1 + 8
        guard datagram.count >= headerLength else {
            throw OVPNError.packetTooShort(field: "control packet header", need: headerLength, have: datagram.count)
        }
        guard trailingBytes >= 0 else {
            throw OVPNError.malformedControlPacket("negative trailing byte count")
        }
        let opcodeByte = datagram[datagram.startIndex]
        guard let parsed = OVPNControlOpcode.parse(opcodeByte) else {
            throw OVPNError.unknownOpcode(opcodeByte >> OVPNControlOpcode.shift)
        }
        let sessionID = OVPNSessionID(unchecked: datagram.subdata(in: 1..<9))

        switch mode {
        case .none:
            let plaintext = try OVPNWire.readRemainder(datagram, after: headerLength, field: "control payload")
            return OVPNUnwrappedControlPacket(
                opcodeByte: opcodeByte,
                opcode: parsed.opcode,
                keyID: parsed.keyID,
                sessionID: sessionID,
                packetID: nil,
                plaintext: plaintext
            )

        case .tlsAuth:
            let macLength = digest.macLength
            let minimum = headerLength + macLength + 8
            guard datagram.count >= minimum else {
                throw OVPNError.packetTooShort(field: "tls-auth MAC and packet id", need: minimum, have: datagram.count)
            }
            let mac = datagram.subdata(in: headerLength..<(headerLength + macLength))
            let packetID = try OVPNPacketID.decode(datagram, at: headerLength + macLength, longForm: true).packetID
            let payload = try OVPNWire.readRemainder(datagram, after: minimum, field: "tls-auth payload")

            var macInput = packetID.wireBytes
            macInput.append(opcodeByte)
            macInput.append(sessionID.bytes)
            macInput.append(payload)
            guard digest.verify(key: receiveHMACKey, data: macInput, tag: mac) else {
                throw OVPNError.authenticationFailed
            }
            try checkReplay(packetID)
            return OVPNUnwrappedControlPacket(
                opcodeByte: opcodeByte,
                opcode: parsed.opcode,
                keyID: parsed.keyID,
                sessionID: sessionID,
                packetID: packetID,
                plaintext: payload
            )

        case .tlsCrypt:
            // tls_crypt.h: TLS_CRYPT_OFF_TAG = 1 + 8 + 8, TLS_CRYPT_OFF_CT =
            // that plus 32.
            let tagOffset = 1 + 8 + 8
            let ciphertextOffset = tagOffset + 32
            guard datagram.count >= ciphertextOffset else {
                throw OVPNError.packetTooShort(field: "tls-crypt tag", need: ciphertextOffset, have: datagram.count)
            }
            guard datagram.count - trailingBytes >= ciphertextOffset else {
                throw OVPNError.malformedControlPacket("trailing bytes overlap the tls-crypt header")
            }
            let header = datagram.subdata(in: 0..<tagOffset)
            let tag = datagram.subdata(in: tagOffset..<ciphertextOffset)
            let ciphertext = datagram.subdata(in: ciphertextOffset..<(datagram.count - trailingBytes))
            let appended = datagram.subdata(in: (datagram.count - trailingBytes)..<datagram.count)
            let packetID = try OVPNPacketID.decode(datagram, at: 9, longForm: true).packetID

            let iv = tag.prefix(16)
            let plaintext = try OVPNAES.ctr(key: receiveCipherKey, iv: iv, data: ciphertext)

            var tagInput = header
            tagInput.append(plaintext)
            guard OVPNHMACAlgorithm.sha256.verify(key: receiveHMACKey, data: tagInput, tag: tag) else {
                throw OVPNError.authenticationFailed
            }
            try checkReplay(packetID)
            return OVPNUnwrappedControlPacket(
                opcodeByte: opcodeByte,
                opcode: parsed.opcode,
                keyID: parsed.keyID,
                sessionID: sessionID,
                packetID: packetID,
                plaintext: plaintext,
                appended: appended
            )
        }
    }

    /// Replay check on the control channel packet id. Only tls-auth/tls-crypt
    /// packets carry one; plain control channels rely on the reliability layer.
    private func checkReplay(_ packetID: OVPNPacketID) throws {
        try replayWindow.testAndMark(sequence: packetID.sequence, timestamp: packetID.timestamp)
    }
}
