import CryptoKit
import Foundation

/// Key material for the OpenVPN data channel, one set per direction.
///
/// OpenVPN derives these from the TLS handshake (`key_method_2`, the
/// `OpenVPN key expansion` PRF) or loads them straight from a `--secret`
/// static key file. Either way the codec only needs the four keys and the two
/// implicit IVs.
public struct OVPNDataKeys: Sendable, Equatable {
    /// Key used to encrypt outbound packets.
    public var sendCipherKey: Data
    /// HMAC key used to authenticate outbound packets (CBC ciphers only).
    public var sendHMACKey: Data
    /// Key used to decrypt inbound packets.
    public var receiveCipherKey: Data
    /// HMAC key used to verify inbound packets (CBC ciphers only).
    public var receiveHMACKey: Data
    /// 12-byte implicit IV XORed into the AEAD nonce when sending.
    public var implicitIVSend: Data
    /// 12-byte implicit IV XORed into the AEAD nonce when receiving.
    public var implicitIVReceive: Data

    /// Create data channel keys.
    public init(
        sendCipherKey: Data,
        sendHMACKey: Data = Data(),
        receiveCipherKey: Data,
        receiveHMACKey: Data = Data(),
        implicitIVSend: Data = Data(repeating: 0, count: 12),
        implicitIVReceive: Data = Data(repeating: 0, count: 12)
    ) {
        self.sendCipherKey = sendCipherKey
        self.sendHMACKey = sendHMACKey
        self.receiveCipherKey = receiveCipherKey
        self.receiveHMACKey = receiveHMACKey
        self.implicitIVSend = implicitIVSend
        self.implicitIVReceive = implicitIVReceive
    }

    /// Bidirectional keys (both directions identical), as `--secret`
    /// static-key mode uses.
    public static func bidirectional(
        cipherKey: Data,
        hmacKey: Data = Data(),
        implicitIV: Data = Data(repeating: 0, count: 12)
    ) -> OVPNDataKeys {
        OVPNDataKeys(
            sendCipherKey: cipherKey,
            sendHMACKey: hmacKey,
            receiveCipherKey: cipherKey,
            receiveHMACKey: hmacKey,
            implicitIVSend: implicitIV,
            implicitIVReceive: implicitIV
        )
    }

    /// Build keys from a static key file, honouring `--key-direction`.
    ///
    /// Each 128-byte key block contributes a 64-byte cipher field (of which
    /// the cipher uses the first 16/24/32 bytes) and a 64-byte HMAC field.
    /// For AEAD ciphers the HMAC field is unused for the MAC and instead
    /// provides the implicit IV (see ``OVPNKeyBlock/implicitIV(ivLength:)``).
    public static func fromStaticKey(
        _ keyFile: OVPNStaticKeyFile,
        cipher: OVPNCipherSpec,
        hmac: OVPNHMACAlgorithm?
    ) throws -> OVPNDataKeys {
        let send = keyFile.sendKeyBlock
        let recv = keyFile.recvKeyBlock
        return try OVPNDataKeys(
            sendCipherKey: send.cipherKey(length: cipher.keyLength),
            sendHMACKey: hmac.flatMap { try? send.hmacKey(digestLength: $0.macLength) } ?? Data(),
            receiveCipherKey: recv.cipherKey(length: cipher.keyLength),
            receiveHMACKey: hmac.flatMap { try? recv.hmacKey(digestLength: $0.macLength) } ?? Data(),
            implicitIVSend: send.implicitIV(ivLength: cipher.ivLength),
            implicitIVReceive: recv.implicitIV(ivLength: cipher.ivLength)
        )
    }
}

/// The OpenVPN **data channel** codec: turns IP packets into the datagrams the
/// tun/tap link carries.
///
/// ## Wire formats
///
/// AES-CBC with a separate HMAC (`openvpn_encrypt_v1()`, `src/openvpn/crypto.c`):
///
/// ```
///  +--------+----------+---------+---------------------------+
///  | opcode |  HMAC    |   IV    |  AES-CBC(plaintext)       |
///  | 1 byte | n bytes  | 16 byte |  padded to 16 bytes       |
///  +--------+----------+---------+---------------------------+
///                     \___ covered by the HMAC ___/
/// ```
///
/// The plaintext is `packet-id || payload`; the packet id is *inside* the
/// ciphertext and is the first thing the receiver reads after decrypting.
/// The HMAC covers `IV || ciphertext`.
///
/// AES-GCM and ChaCha20-Poly1305 (`openvpn_encrypt_aead()`, same file):
///
/// ```
///  +--------+----------+----------+---------------------------+
///  | opcode | packet-id| auth tag |  AEAD(plaintext)          |
///  | 1 byte | 4 bytes  | 16 bytes |                           |
///  +--------+----------+----------+---------------------------+
///     \____________________/
///        additional data
/// ```
///
/// The 4-byte packet id is sent in the clear because it *is* the nonce: the
/// 12-byte nonce is `packet_id || 0 x 8` XORed with the implicit IV, and the
/// additional data is the literal byte prefix `opcode || packet-id` (plus the
/// 3-byte peer id for `P_DATA_V2`).
///
/// Reference: OpenVPN's data channel is described in `src/openvpn/crypto.c`
/// (`openvpn_encrypt`, `openvpn_decrypt`) and `src/openvpn/ssl_pkt.c` for the
/// control channel framing of the same primitives.
public struct OVPNPacketCodec: Sendable {

    /// Cipher families this engine implements.
    public enum Cipher: Sendable, Equatable {
        /// AES in CBC mode with a separate HMAC (`AES-256-CBC`). Associated
        /// value is the OpenVPN cipher name.
        case aesCBC(name: String)
        /// AES-GCM (`AES-256-GCM`, `AES-128-GCM`).
        case aesGCM(name: String)
        /// ChaCha20-Poly1305 (RFC 8439, 96-bit nonce, 128-bit tag).
        case chacha20Poly1305

        /// The OpenVPN name of this cipher.
        public var name: String {
            switch self {
            case let .aesCBC(name), let .aesGCM(name): return name
            case .chacha20Poly1305: return "CHACHA20-POLY1305"
            }
        }

        /// The matching ``OVPNCipherSpec``.
        var spec: OVPNCipherSpec? {
            OVPNCipherSpec.parse(name)
        }
    }

    /// Digests available for the CBC-and-HMAC format.
    public enum Digest: Sendable, Equatable {
        /// HMAC-SHA1.
        case sha1
        /// HMAC-SHA256.
        case sha256
        /// HMAC-SHA512.
        case sha512
        /// No HMAC (only valid with an AEAD cipher, or with `--auth none`).
        case none

        var algorithm: OVPNHMACAlgorithm? {
            switch self {
            case .sha1: return .sha1
            case .sha256: return .sha256
            case .sha512: return .sha512
            case .none: return nil
            }
        }

        var macLength: Int { algorithm?.macLength ?? 0 }
    }

    /// Whether the payload is an IP packet or an Ethernet frame. TAP mode
    /// never pads: the frame's own header carries its length.
    public enum PacketMode: Sendable, Equatable {
        /// Layer 3 payload, PKCS#7 padded for CBC ciphers.
        case tun
        /// Layer 2 payload, zero padded to the block size and never unpadded.
        case tap
    }

    /// Cipher in use.
    public let cipher: Cipher
    /// Digest in use (`.none` for AEAD ciphers).
    public let digest: Digest
    /// `true` when the codec drives a `--secret` tunnel (no TLS control
    /// channel); it only changes which key material is expected.
    public let staticKeyMode: Bool
    /// Key id placed in the low three bits of the opcode byte.
    public let senderKeyId: UInt8

    /// Layer 2 or layer 3.
    public var packetMode: PacketMode = .tun
    /// `--no-replay` disables the replay window.
    public var replayProtectionEnabled: Bool = true
    /// Size of the replay window (`--replay-window n`).
    public var replayWindowSize: Int = 64
    /// `--replay-window n t` timestamp backtrack, `nil` disables it.
    public var replayTimeBacktrack: Int? = 15
    /// Use the long-form packet id (4-byte sequence + 4-byte timestamp).
    /// OpenVPN uses it for every non-AEAD data channel cipher.
    public var longFormPacketID: Bool
    /// Emit `P_DATA_V2` (opcode 9) with a 3-byte peer id instead of
    /// `P_DATA_V1`. Requires ``peerID``.
    public var useDataV2: Bool = false
    /// The `--peer-id` the server assigned in its `PUSH_REPLY`.
    public var peerID: UInt32?
    /// Source of the timestamp half of a long-form packet id. Overridable so
    /// tests are deterministic.
    public var timestampSource: @Sendable () -> UInt32

    /// Installed key material, if any.
    public private(set) var keys: OVPNDataKeys?

    /// Replay protection state for inbound packets (kept in a class so
    /// ``decode(_:)`` can stay non-mutating).
    private let replayWindow: OVPNReplayWindow

    /// Outbound packet-id counter, shared through the codec value like the
    /// replay window is, so ``encodeNext(packet:)`` works on a `let` codec.
    private let sequenceCounter: OVPNSequenceCounter

    /// The resolved cipher parameters.
    private let spec: OVPNCipherSpec

    /// Create a data channel codec for a cipher name.
    ///
    /// - Parameters:
    ///   - cipher: OpenVPN cipher name (`AES-256-GCM`, `AES-256-CBC`, ...).
    ///   - digest: `--auth` digest name (`SHA1`, `SHA256`, `none`). Ignored
    ///     by AEAD ciphers.
    ///   - staticKeyMode: `true` for a `--secret` tunnel.
    ///   - senderKeyId: key id for the low bits of the opcode byte.
    /// - Throws: ``OVPNError/unsupportedCipher(_:)`` or
    ///   ``OVPNError/unsupportedDigest(_:)``.
    public init(cipher: String, digest: String?, staticKeyMode: Bool, senderKeyId: UInt8) throws {
        guard let spec = OVPNCipherSpec.parse(cipher) else {
            throw OVPNError.unsupportedCipher(cipher)
        }
        self.spec = spec
        self.cipher = spec.codecCipher
        self.staticKeyMode = staticKeyMode
        self.senderKeyId = senderKeyId

        let normalizedDigest = digest?.lowercased()
        if normalizedDigest == nil || normalizedDigest == "none" || normalizedDigest?.isEmpty == true {
            self.digest = .none
        } else if let algorithm = OVPNHMACAlgorithm.parse(digest) {
            switch algorithm {
            case .sha1: self.digest = .sha1
            case .sha256: self.digest = .sha256
            case .sha512: self.digest = .sha512
            }
        } else {
            throw OVPNError.unsupportedDigest(digest ?? "")
        }

        // Non-AEAD ciphers need an HMAC unless `--auth none` was requested.
        if !spec.isAEAD, self.digest == .none {
            throw OVPNError.unsupportedDigest("none (a CBC cipher requires an HMAC digest)")
        }

        self.longFormPacketID = !spec.isAEAD
        self.timestampSource = { UInt32(Date().timeIntervalSince1970) }
        self.replayWindow = OVPNReplayWindow()
        self.sequenceCounter = OVPNSequenceCounter()
    }

    /// The resolved cipher specification (name, key length, IV length, tag).
    public var cipherSpec: OVPNCipherSpec { spec }

    /// Install key material. Both directions must be supplied; in static key
    /// mode use ``OVPNDataKeys/bidirectional(cipherKey:hmacKey:implicitIV:)``.
    public mutating func installKeys(_ keys: OVPNDataKeys) {
        self.keys = keys
        let window = OVPNReplayWindow(
            windowSize: replayWindowSize,
            timeBacktrack: replayProtectionEnabled ? replayTimeBacktrack : nil
        )
        // The window is a class, so rebuild it in place instead of swapping the
        // reference: callers may already hold the codec by value.
        replayWindow.reset()
        _ = window
    }

    /// The next outbound packet id, incremented on every use.
    public func nextSequence() -> UInt32 {
        sequenceCounter.next()
    }

    /// Encode a payload using the codec's own counter.
    public func encodeNext(packet: Data) throws -> Data {
        try encode(packet: packet, sequence: sequenceCounter.next())
    }

    // MARK: - Encoding

    /// Encode one payload into a datagram.
    ///
    /// - Parameters:
    ///   - packet: the bare IP packet (TUN) or Ethernet frame (TAP). When
    ///     emitting `P_DATA_V2` the peer id is added automatically.
    ///   - sequence: the packet id to use. The caller owns the counter so the
    ///     value is reproducible in tests; ``nextSequence()`` and
    ///     ``encodeNext(packet:)`` provide a monotonic counter.
    /// - Returns: the datagram to hand to the transport.
    public func encode(packet: Data, sequence: UInt32) throws -> Data {
        guard let keys else { throw OVPNError.keyNotInstalled }

        switch cipher {
        case .aesCBC:
            return try encodeCBC(packet: packet, sequence: sequence, keys: keys)
        case .aesGCM, .chacha20Poly1305:
            return try encodeAEAD(packet: packet, sequence: sequence, keys: keys)
        }
    }

    /// `openvpn_encrypt_v1()`: `[opcode][HMAC][IV][ciphertext]`.
    private func encodeCBC(packet: Data, sequence: UInt32, keys: OVPNDataKeys) throws -> Data {
        guard let hmacAlgorithm = digest.algorithm else {
            throw OVPNError.unsupportedDigest("none")
        }
        guard keys.sendHMACKey.count == hmacAlgorithm.macLength || keys.sendHMACKey.count >= hmacAlgorithm.macLength else {
            throw OVPNError.keyNotInstalled
        }

        var plaintext = Data()
        OVPNWire.append(sequence, to: &plaintext)
        if longFormPacketID {
            OVPNWire.append(timestampSource(), to: &plaintext)
        }
        plaintext.append(packet)

        let padded: Data
        if packetMode == .tun {
            padded = OVPNPadding.pkcs7Pad(plaintext, blockSize: 16)
        } else {
            padded = OVPNPadding.zeroPad(plaintext, blockSize: 16)
        }

        let iv = OVPNWire.randomBytes(16)
        let ciphertext = try OVPNAES.cbc(key: keys.sendCipherKey, iv: iv, data: padded, encrypt: true)

        var authenticated = Data()
        authenticated.append(iv)
        authenticated.append(ciphertext)
        let mac = hmacAlgorithm.authenticate(key: keys.sendHMACKey, data: authenticated)

        var out = Data()
        out.append(opcodeByte(sequence: sequence))
        out.append(mac)
        out.append(authenticated)
        return out
    }

    /// `openvpn_encrypt_aead()`: `[opcode(+peer id)][packet id][tag][ciphertext]`.
    private func encodeAEAD(packet: Data, sequence: UInt32, keys: OVPNDataKeys) throws -> Data {
        var prefix = Data()
        prefix.append(opcodeByte(sequence: sequence))
        if useDataV2, let peerID {
            prefix.append(UInt8(truncatingIfNeeded: peerID >> 16))
            prefix.append(UInt8(truncatingIfNeeded: peerID >> 8))
            prefix.append(UInt8(truncatingIfNeeded: peerID))
        }
        OVPNWire.append(sequence, to: &prefix)

        let nonce = aeadNonce(sequence: sequence, implicitIV: keys.implicitIVSend)

        switch cipher {
        case .aesGCM:
            let box = try AES.GCM.seal(packet, using: SymmetricKey(data: keys.sendCipherKey), nonce: try AES.GCM.Nonce(data: nonce), authenticating: prefix)
            var out = prefix
            out.append(box.tag)
            out.append(box.ciphertext)
            return out
        case .chacha20Poly1305:
            let box = try ChaChaPoly.seal(packet, using: SymmetricKey(data: keys.sendCipherKey), nonce: try ChaChaPoly.Nonce(data: nonce), authenticating: prefix)
            var out = prefix
            out.append(box.tag)
            out.append(box.ciphertext)
            return out
        case .aesCBC:
            throw OVPNError.unsupportedCipher("AES-CBC is not an AEAD cipher")
        }
    }

    // MARK: - Decoding

    /// Decode a received datagram into its payload.
    ///
    /// - Throws: ``OVPNError`` for truncated packets, bad MACs/tags, bad
    ///   padding, replays, or payloads whose length cannot be trusted.
    public func decode(_ datagram: Data) throws -> Data {
        guard let keys else { throw OVPNError.keyNotInstalled }
        guard datagram.count >= 1 else {
            throw OVPNError.packetTooShort(field: "opcode", need: 1, have: datagram.count)
        }

        let opcodeValue = datagram[datagram.startIndex] >> OVPNControlOpcode.shift
        switch OVPNControlOpcode(rawValue: opcodeValue) {
        case .dataV1, .dataV2:
            break
        default:
            throw OVPNError.unknownOpcode(opcodeValue)
        }

        switch cipher {
        case .aesCBC:
            return try decodeCBC(datagram, keys: keys)
        case .aesGCM, .chacha20Poly1305:
            return try decodeAEAD(datagram, keys: keys)
        }
    }

    /// Decode a `P_DATA_V1`/`P_DATA_V2` datagram, returning the peer id too
    /// when the packet carries one.
    public func decodeAnnotated(_ datagram: Data) throws -> OVPNInboundDataPacket {
        guard datagram.count >= 1 else {
            throw OVPNError.packetTooShort(field: "opcode", need: 1, have: datagram.count)
        }
        let opcodeValue = datagram[datagram.startIndex] >> OVPNControlOpcode.shift
        guard let opcode = OVPNControlOpcode(rawValue: opcodeValue) else {
            throw OVPNError.unknownOpcode(opcodeValue)
        }
        var peerID: UInt32?
        var payload: Data
        if opcode == .dataV2 {
            guard datagram.count >= 4 else {
                throw OVPNError.packetTooShort(field: "peer id", need: 4, have: datagram.count)
            }
            let base = datagram.startIndex
            peerID = UInt32(datagram[base + 1]) << 16 | UInt32(datagram[base + 2]) << 8 | UInt32(datagram[base + 3])
            // The 3-byte peer id is part of the AEAD additional data, so the
            // generic decoder must see it. Strip it only after decoding.
            payload = try decode(datagram)
        } else {
            payload = try decode(datagram)
        }
        return OVPNInboundDataPacket(
            payload: payload,
            keyID: datagram[datagram.startIndex] & OVPNControlOpcode.keyIDMask,
            opcode: opcode,
            peerID: peerID
        )
    }

    /// `openvpn_decrypt_v1()`: verify the MAC, decrypt, unpad, read the packet
    /// id from the plaintext, then check it against the replay window.
    private func decodeCBC(_ datagram: Data, keys: OVPNDataKeys) throws -> Data {
        guard let hmacAlgorithm = digest.algorithm else {
            throw OVPNError.unsupportedDigest("none")
        }
        let macLength = hmacAlgorithm.macLength
        let headerLength = 1 + macLength + 16
        guard datagram.count > headerLength else {
            throw OVPNError.packetTooShort(field: "HMAC + IV + ciphertext", need: headerLength + 1, have: datagram.count)
        }
        let ciphertextLength = datagram.count - headerLength
        guard ciphertextLength % 16 == 0 else {
            throw OVPNError.malformedPacket("ciphertext is not block aligned (\(ciphertextLength) bytes)")
        }

        let mac = datagram.subdata(in: 1..<(1 + macLength))
        let iv = datagram.subdata(in: (1 + macLength)..<(1 + macLength + 16))
        let ciphertext = datagram.subdata(in: headerLength..<datagram.count)

        var authenticated = Data()
        authenticated.append(iv)
        authenticated.append(ciphertext)
        guard hmacAlgorithm.verify(key: keys.receiveHMACKey, data: authenticated, tag: mac) else {
            throw OVPNError.authenticationFailed
        }

        let plaintext = try OVPNAES.cbc(key: keys.receiveCipherKey, iv: iv, data: ciphertext, encrypt: false)

        let unpadded: Data
        switch packetMode {
        case .tun:
            unpadded = try OVPNPadding.pkcs7Unpad(plaintext, blockSize: 16)
        case .tap:
            unpadded = plaintext
        }

        let packetIDLength = longFormPacketID ? 8 : 4
        guard unpadded.count >= packetIDLength else {
            throw OVPNError.malformedPacket("decrypted packet shorter than its packet id")
        }
        let sequence = try OVPNWire.readUInt32(unpadded, at: 0, field: "packet id")
        if longFormPacketID, replayProtectionEnabled {
            let timestamp = try OVPNWire.readUInt32(unpadded, at: 4, field: "packet timestamp")
            try replayWindow.testAndMark(sequence: sequence, timestamp: timestamp)
        } else if replayProtectionEnabled {
            try replayWindow.testAndMark(sequence: sequence)
        }
        return unpadded.subdata(in: packetIDLength..<unpadded.count)
    }

    /// `openvpn_decrypt_aead()`: the packet id is the nonce and the additional
    /// data, so it is checked for replays before decryption.
    private func decodeAEAD(_ datagram: Data, keys: OVPNDataKeys) throws -> Data {
        let peerIDLength = (useDataV2 || (datagram[datagram.startIndex] >> OVPNControlOpcode.shift) == OVPNControlOpcode.dataV2.rawValue) ? 3 : 0
        let prefixLength = 1 + peerIDLength
        let tagLength = spec.tagLength
        guard datagram.count >= prefixLength + 4 + tagLength else {
            throw OVPNError.packetTooShort(field: "AEAD header", need: prefixLength + 4 + tagLength, have: datagram.count)
        }

        let prefix = datagram.subdata(in: 0..<(prefixLength + 4))
        let sequence = try OVPNWire.readUInt32(datagram, at: prefixLength, field: "packet id")
        if replayProtectionEnabled {
            try replayWindow.testAndMark(sequence: sequence)
        }

        let tag = datagram.subdata(in: (prefixLength + 4)..<(prefixLength + 4 + tagLength))
        let ciphertext = datagram.subdata(in: (prefixLength + 4 + tagLength)..<datagram.count)
        let nonce = aeadNonce(sequence: sequence, implicitIV: keys.implicitIVReceive)

        switch cipher {
        case .aesGCM:
            do {
                let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: nonce), ciphertext: ciphertext, tag: tag)
                return try AES.GCM.open(box, using: SymmetricKey(data: keys.receiveCipherKey), authenticating: prefix)
            } catch {
                throw OVPNError.authenticationFailed
            }
        case .chacha20Poly1305:
            do {
                let box = try ChaChaPoly.SealedBox(nonce: try ChaChaPoly.Nonce(data: nonce), ciphertext: ciphertext, tag: tag)
                return try ChaChaPoly.open(box, using: SymmetricKey(data: keys.receiveCipherKey), authenticating: prefix)
            } catch {
                throw OVPNError.authenticationFailed
            }
        case .aesCBC:
            throw OVPNError.unsupportedCipher("AES-CBC is not an AEAD cipher")
        }
    }

    // MARK: - Helpers

    /// `(key_id << 0) | (opcode << 3)`, the first byte of every OpenVPN packet.
    private func opcodeByte(sequence: UInt32) -> UInt8 {
        _ = sequence
        let opcode: OVPNControlOpcode = (useDataV2 && peerID != nil) ? .dataV2 : .dataV1
        return OVPNControlOpcode.opcodeByte(opcode, keyID: senderKeyId)
    }

    /// `nonce = (packet id, zero extended to 12 bytes) XOR implicit IV`.
    ///
    /// OpenVPN computes this with a plain byte-wise XOR over the full IV length
    /// (`crypto.c`, "This generates the IV by XORing the implicit part of the
    /// IV with the packet id"). In the legacy (non-epoch) format the implicit
    /// IV occupies bytes 4...12 of the 16-byte buffer and the rest is zero, so
    /// bytes 4...12 of the resulting 12-byte nonce are the implicit IV.
    private func aeadNonce(sequence: UInt32, implicitIV: Data) -> Data {
        var nonce = Data()
        OVPNWire.append(sequence, to: &nonce)
        nonce.append(Data(repeating: 0, count: max(0, spec.ivLength - 4)))
        for index in 0..<min(implicitIV.count, nonce.count) {
            nonce[nonce.startIndex + index] ^= implicitIV[implicitIV.startIndex + index]
        }
        return nonce
    }
}

/// An inbound data packet together with the header fields needed by the
/// session (key id and peer id).
public struct OVPNInboundDataPacket: Sendable, Equatable {
    /// The decrypted IP packet or Ethernet frame.
    public var payload: Data
    /// Key id from the low bits of the opcode byte.
    public var keyID: UInt8
    /// Opcode the packet used (`P_DATA_V1` or `P_DATA_V2`).
    public var opcode: OVPNControlOpcode
    /// 3-byte peer id carried by `P_DATA_V2`.
    public var peerID: UInt32?

    /// Create an inbound packet value.
    public init(payload: Data, keyID: UInt8, opcode: OVPNControlOpcode, peerID: UInt32? = nil) {
        self.payload = payload
        self.keyID = keyID
        self.opcode = opcode
        self.peerID = peerID
    }
}

/// Thread-safe `UInt32` counter for outbound packet ids.
///
/// Like ``OVPNReplayWindow`` this is a class so the codec can hand out
/// monotonically increasing sequence numbers from a non-mutating method.
final class OVPNSequenceCounter: @unchecked Sendable {
    private let lock = OVPNMutex()
    private var value: UInt32 = 0

    func next() -> UInt32 {
        lock.lock()
        defer { lock.unlock() }
        let current = value
        value &+= 1
        return current
    }

    func reset() {
        lock.lock()
        defer { lock.unlock() }
        value = 0
    }
}
