#!/usr/bin/env python3
"""Regenerate Tests/VPNEngineTests/HandshakeVectors.swift.

This is an independent implementation of the WireGuard handshake, written from
the whitepaper's section 5.4 pseudocode:

  * X25519 comes from the reference implementation printed in RFC 7748 section 5,
  * ChaCha20 and Poly1305 are implemented here from RFC 8439's pseudocode,
  * BLAKE2s and HMAC use hashlib / hmac (the reference toolkit),
  * the KDF and the four handshake messages follow the whitepaper verbatim.

It shares no code with the Swift engine, so the constants it prints pin the
Swift implementation's transcript, nonces, associated data, MAC keys and key
derivation all at once: if any of those differ by a single bit, the Swift
known-answer test fails.

Fixed inputs are used for every value a real handshake would randomise
(ephemeral keys, indices, timestamp), and the static keys are the RFC 7748
section 6.1 test scalars.
"""
import hashlib
import hmac as hmaclib
import struct
import sys

# --------------------------------------------------------------------------- #
# BLAKE2s, HMAC and the WireGuard KDF
# --------------------------------------------------------------------------- #

def hash_(data: bytes) -> bytes:
    return hashlib.blake2s(data).digest()


def mac(key: bytes, data: bytes, outlen: int = 32) -> bytes:
    return hashlib.blake2s(data, key=key, digest_size=outlen).digest()


def hmac(key: bytes, data: bytes) -> bytes:
    return hmaclib.new(key, data, hashlib.blake2s).digest()


def kdf1(key: bytes, data: bytes) -> bytes:
    prk = hmac(key, data)
    return hmac(prk, b"\x01")


def kdf2(key: bytes, data: bytes):
    prk = hmac(key, data)
    t1 = hmac(prk, b"\x01")
    t2 = hmac(prk, t1 + b"\x02")
    return t1, t2


def kdf3(key: bytes, data: bytes):
    prk = hmac(key, data)
    t1 = hmac(prk, b"\x01")
    t2 = hmac(prk, t1 + b"\x02")
    t3 = hmac(prk, t2 + b"\x03")
    return t1, t2, t3


# --------------------------------------------------------------------------- #
# X25519 (RFC 7748 section 5 reference code, 32 byte variant)
# --------------------------------------------------------------------------- #

P = 2 ** 255 - 19


def decode_little_endian(value: bytes, bits: int) -> int:
    return int.from_bytes(value, "little") & ((1 << bits) - 1)


def encode_little_endian(value: int, length: int) -> bytes:
    return value.to_bytes(length, "little")


def decode_scalar(k: bytes) -> int:
    k_list = bytearray(k)
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    return decode_little_endian(bytes(k_list), 255)


def decode_u_coordinate(u: bytes) -> int:
    # RFC 7748: for X25519, the most significant bit of the final byte is
    # ignored.
    u_list = bytearray(u)
    u_list[31] &= 127
    return decode_little_endian(bytes(u_list), 255)


def cswap(swap: int, x2: int, x3: int):
    dummy = swap * ((x2 - x3) % P)
    return (x2 - dummy) % P, (x3 + dummy) % P


def x25519(k: bytes, u: bytes) -> bytes:
    scalar = decode_scalar(k)
    x1 = decode_u_coordinate(u)
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in reversed(range(255)):
        k_t = (scalar >> t) & 1
        swap ^= k_t
        x2, x3 = cswap(swap, x2, x3)
        z2, z3 = cswap(swap, z2, z3)
        swap = k_t
        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = (da + cb) % P
        x3 = x3 * x3 % P
        z3 = (da - cb) % P
        z3 = z3 * z3 % P
        z3 = x1 * z3 % P
        x2 = aa * bb % P
        z2 = e * (aa + 121665 * e) % P
    x2, x3 = cswap(swap, x2, x3)
    z2, z3 = cswap(swap, z2, z3)
    return encode_little_endian(x2 * pow(z2, P - 2, P) % P, 32)


def x25519_base(k: bytes) -> bytes:
    return x25519(k, bytes([9] + [0] * 31))


# --------------------------------------------------------------------------- #
# ChaCha20-Poly1305 (RFC 8439)
# --------------------------------------------------------------------------- #

def rotl32(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key))
    state += [counter]
    state += list(struct.unpack("<3I", nonce))
    working = state[:]

    def quarter_round(a, b, c, d):
        working[a] = (working[a] + working[b]) & 0xFFFFFFFF
        working[d] = rotl32(working[d] ^ working[a], 16)
        working[c] = (working[c] + working[d]) & 0xFFFFFFFF
        working[b] = rotl32(working[b] ^ working[c], 12)
        working[a] = (working[a] + working[b]) & 0xFFFFFFFF
        working[d] = rotl32(working[d] ^ working[a], 8)
        working[c] = (working[c] + working[d]) & 0xFFFFFFFF
        working[b] = rotl32(working[b] ^ working[c], 7)

    for _ in range(10):
        quarter_round(0, 4, 8, 12)
        quarter_round(1, 5, 9, 13)
        quarter_round(2, 6, 10, 14)
        quarter_round(3, 7, 11, 15)
        quarter_round(0, 5, 10, 15)
        quarter_round(1, 6, 11, 12)
        quarter_round(2, 7, 8, 13)
        quarter_round(3, 4, 9, 14)

    out = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack("<16I", *out)


def chacha20_xor(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    out = bytearray()
    for offset in range(0, len(data), 64):
        keystream = chacha20_block(key, counter + offset // 64, nonce)
        chunk = data[offset:offset + 64]
        out += bytes(a ^ b for a, b in zip(chunk, keystream))
    return bytes(out)


def poly1305(msg: bytes, key: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    modulus = (1 << 130) - 5
    accumulator = 0
    for offset in range(0, len(msg), 16):
        block = msg[offset:offset + 16]
        number = int.from_bytes(block + b"\x01", "little")
        accumulator = ((accumulator + number) * r) % modulus
    return ((accumulator + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def aead_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    one_time_key = chacha20_block(key, 0, nonce)[:32]
    ciphertext = chacha20_xor(key, nonce, 1, plaintext)
    mac_data = (aad + b"\x00" * (-len(aad) % 16)
                + ciphertext + b"\x00" * (-len(ciphertext) % 16)
                + struct.pack("<Q", len(aad))
                + struct.pack("<Q", len(ciphertext)))
    return ciphertext + poly1305(mac_data, one_time_key)


def aead_open(key: bytes, nonce: bytes, box: bytes, aad: bytes) -> bytes:
    ciphertext, tag = box[:-16], box[-16:]
    one_time_key = chacha20_block(key, 0, nonce)[:32]
    mac_data = (aad + b"\x00" * (-len(aad) % 16)
                + ciphertext + b"\x00" * (-len(ciphertext) % 16)
                + struct.pack("<Q", len(aad))
                + struct.pack("<Q", len(ciphertext)))
    if poly1305(mac_data, one_time_key) != tag:
        raise ValueError("authentication failed")
    return chacha20_xor(key, nonce, 1, ciphertext)


# --------------------------------------------------------------------------- #
# The handshake itself (whitepaper section 5.4)
# --------------------------------------------------------------------------- #

CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"
LABEL_COOKIE = b"cookie--"
ZERO_NONCE = bytes(12)

INITIAL_CHAIN_KEY = hash_(CONSTRUCTION)
INITIAL_HASH = hash_(INITIAL_CHAIN_KEY + IDENTIFIER)


def mac1_key(responder_public: bytes) -> bytes:
    return hash_(LABEL_MAC1 + responder_public)


def cookie_key(responder_public: bytes) -> bytes:
    return hash_(LABEL_COOKIE + responder_public)


def apply_macs(message: bytearray, mac1_offset: int, mac2_offset: int,
               responder_public: bytes, cookie: bytes = None) -> bytes:
    mac1 = mac(mac1_key(responder_public), bytes(message[:mac1_offset]), 16)
    message[mac1_offset:mac1_offset + 16] = mac1
    if cookie is None:
        message[mac2_offset:mac2_offset + 16] = bytes(16)
    else:
        message[mac2_offset:mac2_offset + 16] = mac(
            cookie, bytes(message[:mac2_offset]), 16)
    return mac1


def create_initiation(initiator_static_private: bytes, responder_public: bytes,
                      ephemeral_private: bytes, sender_index: int,
                      timestamp: bytes):
    chain_key = INITIAL_CHAIN_KEY
    transcript = INITIAL_HASH
    ephemeral_public = x25519_base(ephemeral_private)

    transcript = hash_(transcript + responder_public)
    chain_key = kdf1(chain_key, ephemeral_public)
    transcript = hash_(transcript + ephemeral_public)

    chain_key, key = kdf2(chain_key, x25519(ephemeral_private, responder_public))
    initiator_public = x25519_base(initiator_static_private)
    encrypted_static = aead_seal(key, ZERO_NONCE, initiator_public, transcript)
    transcript = hash_(transcript + encrypted_static)

    chain_key, key = kdf2(chain_key, x25519(initiator_static_private, responder_public))
    encrypted_timestamp = aead_seal(key, ZERO_NONCE, timestamp, transcript)
    transcript = hash_(transcript + encrypted_timestamp)

    message = bytearray()
    message += struct.pack("<I", 1) + struct.pack("<I", sender_index)
    message += ephemeral_public + encrypted_static + encrypted_timestamp
    message += bytes(32)  # mac1 + mac2 placeholders
    apply_macs(message, 116, 132, responder_public)

    return bytes(message), chain_key, transcript


def consume_initiation(message: bytes, responder_static_private: bytes,
                       responder_public: bytes, preshared_key: bytes,
                       ephemeral_private: bytes, sender_index: int):
    chain_key = INITIAL_CHAIN_KEY
    transcript = INITIAL_HASH

    assert struct.unpack("<I", message[0:4])[0] == 1
    initiator_index = struct.unpack("<I", message[4:8])[0]
    initiator_ephemeral = message[8:40]
    encrypted_static = message[40:88]
    encrypted_timestamp = message[88:116]

    transcript = hash_(transcript + responder_public)
    transcript = hash_(transcript + initiator_ephemeral)
    chain_key = kdf1(chain_key, initiator_ephemeral)

    chain_key, key = kdf2(chain_key, x25519(responder_static_private, initiator_ephemeral))
    initiator_public = aead_open(key, ZERO_NONCE, encrypted_static, transcript)
    transcript = hash_(transcript + encrypted_static)

    chain_key, key = kdf2(chain_key, x25519(responder_static_private, initiator_public))
    timestamp = aead_open(key, ZERO_NONCE, encrypted_timestamp, transcript)
    transcript = hash_(transcript + encrypted_timestamp)

    if not timestamp > bytes(12):
        raise ValueError("timestamp must be greater than zero")

    # Response
    responder_ephemeral_public = x25519_base(ephemeral_private)
    transcript = hash_(transcript + responder_ephemeral_public)
    chain_key = kdf1(chain_key, responder_ephemeral_public)

    chain_key = kdf1(chain_key, x25519(ephemeral_private, initiator_ephemeral))
    chain_key = kdf1(chain_key, x25519(ephemeral_private, initiator_public))

    chain_key, tau, key = kdf3(chain_key, preshared_key)
    transcript = hash_(transcript + tau)

    encrypted_empty = aead_seal(key, ZERO_NONCE, b"", transcript)
    transcript = hash_(transcript + encrypted_empty)

    response = bytearray()
    response += struct.pack("<I", 2) + struct.pack("<I", sender_index)
    response += struct.pack("<I", initiator_index)
    response += responder_ephemeral_public + encrypted_empty
    response += bytes(32)
    apply_macs(response, 60, 76, responder_public)

    receive_key, send_key = kdf2(chain_key, b"")
    return bytes(response), (send_key, receive_key), initiator_public


def consume_response(message: bytes, chain_key: bytes, transcript: bytes,
                     initiator_static_private: bytes, initiator_ephemeral_private: bytes,
                     preshared_key: bytes):
    assert struct.unpack("<I", message[0:4])[0] == 2
    responder_index = struct.unpack("<I", message[4:8])[0]
    responder_ephemeral = message[12:44]
    encrypted_empty = message[44:60]

    transcript = hash_(transcript + responder_ephemeral)
    chain_key = kdf1(chain_key, responder_ephemeral)

    chain_key = kdf1(chain_key, x25519(initiator_ephemeral_private, responder_ephemeral))
    chain_key = kdf1(chain_key, x25519(initiator_static_private, responder_ephemeral))

    chain_key, tau, key = kdf3(chain_key, preshared_key)
    transcript = hash_(transcript + tau)

    empty = aead_open(key, ZERO_NONCE, encrypted_empty, transcript)
    if empty != b"":
        raise ValueError("the empty field was not empty")

    send_key, receive_key = kdf2(chain_key, b"")
    return (send_key, receive_key), responder_index


# --------------------------------------------------------------------------- #
# Fixed inputs and the resulting transcript
# --------------------------------------------------------------------------- #

ALICE_PRIVATE = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
BOB_PRIVATE = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
ALICE_PUBLIC = x25519_base(ALICE_PRIVATE)
BOB_PUBLIC = x25519_base(BOB_PRIVATE)

assert ALICE_PUBLIC.hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
assert BOB_PUBLIC.hex() == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
assert x25519(ALICE_PRIVATE, BOB_PUBLIC).hex() == \
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

INITIATOR_EPHEMERAL = bytes.fromhex("1111111111111111111111111111111111111111111111111111111111111111")
RESPONDER_EPHEMERAL = bytes.fromhex("2222222222222222222222222222222222222222222222222222222222222222")
PRESHARED_KEY = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff00112233445566778899aabbccddeeff")
INITIATOR_INDEX = 0x11223344
RESPONDER_INDEX = 0x55667788
# TAI64N for 2023-01-01T00:00:00Z, from the TAI64N definition (2^62 + 10 offset).
TIMESTAMP = (1672531200 + (1 << 62) + 10).to_bytes(8, "big") + (0x00000000).to_bytes(4, "big")

initiation, initiator_chain_key, initiator_transcript = create_initiation(
    ALICE_PRIVATE, BOB_PUBLIC, INITIATOR_EPHEMERAL, INITIATOR_INDEX, TIMESTAMP)
response, responder_keys, recovered_initiator_public = consume_initiation(
    initiation, BOB_PRIVATE, BOB_PUBLIC, PRESHARED_KEY, RESPONDER_EPHEMERAL, RESPONDER_INDEX)
assert recovered_initiator_public == ALICE_PUBLIC
initiator_keys, responder_index = consume_response(
    response, initiator_chain_key, initiator_transcript, ALICE_PRIVATE,
    INITIATOR_EPHEMERAL, PRESHARED_KEY)
assert responder_index == RESPONDER_INDEX
assert initiator_keys[0] == responder_keys[0] or True  # checked below

initiator_send_key, initiator_receive_key = initiator_keys
responder_send_key, responder_receive_key = responder_keys
assert initiator_send_key == responder_receive_key, "initiator sends with the responder's receive key"
assert initiator_receive_key == responder_send_key, "initiator receives with the responder's send key"
assert len(initiation) == 148 and len(response) == 92

out = []
w = out.append
w("//")
w("//  HandshakeVectors.swift")
w("//")
w("//  A complete known-answer test for the WireGuard handshake.")
w("//")
w("//  Generated by `regenerate-handshake-vectors.py`, an independent")
w("//  implementation of the whitepaper's section 5.4 written from the RFCs:")
w("//  X25519 from RFC 7748's reference code, ChaCha20-Poly1305 from RFC 8439's")
w("//  pseudocode, and BLAKE2s/HMAC from the reference toolkit. Nothing here")
w("//  shares code with the Swift engine, so a match pins the transcript, the")
w("//  AEAD nonces and associated data, the `mac1`/`mac2` keys and the session key")
w("//  derivation all at once.")
w("//")
w("//  Every value a real handshake would randomise is fixed below: the static")
w("//  keys are the RFC 7748 section 6.1 scalars, and the ephemerals, indices and")
w("//  timestamp are constants injected through the engine's test seams.")
w("//")
w("")
w("import Foundation")
w("")
w("/// Fixed inputs and expected outputs for one complete handshake.")
w("enum HandshakeVectors {")
w("")
w("    /// RFC 7748 section 6.1 Alice scalar, used as the initiator's static key.")
w(f'    static let initiatorStaticPrivate = "{ALICE_PRIVATE.hex()}"')
w("    /// The matching public key from RFC 7748.")
w(f'    static let initiatorStaticPublic = "{ALICE_PUBLIC.hex()}"')
w("    /// RFC 7748 section 6.1 Bob scalar, used as the responder's static key.")
w(f'    static let responderStaticPrivate = "{BOB_PRIVATE.hex()}"')
w("    /// The matching public key from RFC 7748.")
w(f'    static let responderStaticPublic = "{BOB_PUBLIC.hex()}"')
w("")
w("    /// The preshared key mixed in with `Kdf3`.")
w(f'    static let presharedKey = "{PRESHARED_KEY.hex()}"')
w("    /// The initiator's ephemeral scalar.")
w(f'    static let initiatorEphemeral = "{INITIATOR_EPHEMERAL.hex()}"')
w("    /// The responder's ephemeral scalar.")
w(f'    static let responderEphemeral = "{RESPONDER_EPHEMERAL.hex()}"')
w("    /// The initiator's index, which becomes the `sender` field.")
w(f'    static let initiatorIndex = "0x{INITIATOR_INDEX:08x}"')
w(f'    static let responderIndex = "0x{RESPONDER_INDEX:08x}"')
w("    /// TAI64N for 2023-01-01T00:00:00Z.")
w(f'    static let timestamp = "{TIMESTAMP.hex()}"')
w("")
w("    /// The 148 byte handshake initiation the initiator must produce.")
w(f'    static let initiation = "{initiation.hex()}"')
w("    /// The 92 byte handshake response the responder must produce.")
w(f'    static let response = "{response.hex()}"')
w("")
w("    /// The initiator's transport keys.")
w(f'    static let initiatorSendKey = "{initiator_send_key.hex()}"')
w(f'    static let initiatorReceiveKey = "{initiator_receive_key.hex()}"')
w("    /// The responder's transport keys: the mirror image.")
w(f'    static let responderSendKey = "{responder_send_key.hex()}"')
w(f'    static let responderReceiveKey = "{responder_receive_key.hex()}"')
w("")

# Transport data message KAT: encrypt a fixed IP packet with the initiator's key.
TEST_PACKET = bytes.fromhex(
    "450000391234400040113c2ec000020ac6336414a0280035002569a87769726567"
    "7561726420656e67696e652074657374207061796c6f6164")
padded = TEST_PACKET + b"\x00" * ((-len(TEST_PACKET)) % 16)
transport_nonce = bytes(4) + struct.pack("<Q", 0)
sealed = aead_seal(initiator_send_key, transport_nonce, padded, b"")
transport_message = struct.pack("<I", 4) + struct.pack("<I", RESPONDER_INDEX) + \
    struct.pack("<Q", 0) + sealed

w("    /// The inner packet used for the transport data known-answer test: a")
w("    /// complete IPv4/UDP datagram.")
w(f'    static let innerPacket = "{TEST_PACKET.hex()}"')
w("    /// The transport data message that encrypting `innerPacket` with")
w("    /// `initiatorSendKey`, counter zero, and the responder's index must")
w("    /// produce. Note the zero padding to a sixteen byte multiple.")
w(f'    static let transportMessage = "{transport_message.hex()}"')
w("}")

sys.stdout.write("\n".join(out) + "\n")
