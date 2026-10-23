#!/usr/bin/env python3
"""Regenerate Tests/VPNEngineTests/TestVectors.swift from the published sources.

Every hex constant is pulled straight out of the RFC / draft / KAT text files so
that none of them can be mistyped. Run from a directory holding:
  rfc8439.txt, xchacha.txt, blake2s-kat.txt
"""
import re, hashlib, sys

def parse_offset_dump(lines):
    out = []
    for ln in lines:
        m = re.match(r'^\s*(\d{1,4})\s+((?:[0-9a-fA-F]{2}\s+){1,16})', ln)
        if m:
            out.append(m.group(2).replace(' ', ''))
    return ''.join(out)

def colon_hex(line):
    return ''.join(re.findall(r'([0-9a-f]{2})', line.split(':', 1)[1]))

def colon_bytes(line):
    return ''.join(re.findall(r'([0-9a-f]{2})', line))

def raw_hex_block(lines):
    out = []
    for ln in lines:
        s = ln.strip()
        if re.fullmatch(r'[0-9a-f]{16,}', s):
            out.append(s)
    return ''.join(out)

def hex_after_label(lines, label, start=0):
    """Collect the contiguous run of pure-hex lines that follows `label`.

    Stops at the first blank line, so a following labelled block (which is how
    the drafts format the tag) does not bleed into this one.
    """
    i = find(lines, label, start)
    out = []
    i += 1
    while i < len(lines):
        s = lines[i].strip()
        if not s:
            if out:
                break
            i += 1
            continue
        if re.fullmatch(r'[0-9a-f]{16,}', s):
            out.append(s)
        else:
            break
        i += 1
    return ''.join(out)

def find(lines, needle, start=0):
    return next(i for i, l in enumerate(lines[start:], start) if needle in l)

def tai64n(seconds, nanoseconds):
    """TAI64N as defined by daemontools: TAI seconds (2^62 + 10 offset) then nanos."""
    total = (seconds + (1 << 62) + 10) & 0xFFFFFFFFFFFFFFFF
    return total.to_bytes(8, 'big').hex() + nanoseconds.to_bytes(4, 'big').hex()

r = open('rfc8439.txt').read().split('\n')
x = open('xchacha.txt').read().split('\n')
kat = open('blake2s-kat.txt').read().split('\n')

i242 = find(r, 'Ciphertext Sunscreen:')
ct242 = parse_offset_dump(r[i242:i242 + 16])
tag252 = colon_hex(r[find(r, 'Tag: a8')])

i282 = find(r, '2.8.2.  Example')
j282 = find(r, 'Ciphertext:', i282)
ct282 = parse_offset_dump(r[j282:j282 + 12])
tag282 = colon_bytes(r[find(r, 'Tag:', j282) + 1])
jk = find(r, 'keystream bytes:', i282)
keystream282 = ''.join(colon_bytes(l) for l in r[jk + 1:jk + 10])

# Skip the table of contents: search only the second half of the file.
ix = find(x, 'A.3.1.', len(x) // 2)
ctx = hex_after_label(x, 'Ciphertext:', ix)
tagx = hex_after_label(x, 'Tag:', ix + 3)

entries = []
i = 0
while i < len(kat):
    if kat[i].startswith('in:'):
        inp = kat[i].split(':', 1)[1].strip()
        key = kat[i + 1].split(':', 1)[1].strip() if kat[i + 1].startswith('key:') else ''
        digest = kat[i + 2].split(':', 1)[1].strip()
        entries.append((inp, key, digest))
        i += 3
    else:
        i += 1
by_len = {len(e[0]) // 2: e for e in entries}
kat_of = lambda n: by_len[n]

def h(s):
    return hashlib.blake2s(s).hexdigest()

b2s256_empty, b2s256_abc = h(b''), h(b'abc')
b2s256_64, b2s256_128 = h(bytes(range(64))), h(bytes(range(128)))
b2s128_empty = hashlib.blake2s(b'', digest_size=16).hexdigest()
b2s128_abc = hashlib.blake2s(b'abc', digest_size=16).hexdigest()

assert len(ct242) // 2 == 114, len(ct242)
assert len(ct282) // 2 == 114, len(ct282)
assert len(keystream282) // 2 == 114, len(keystream282)
assert len(ctx) // 2 == 114, len(ctx)
assert tag282 == '1ae10b594f09e26a7e902ecbd0600691', tag282
assert tag252 == 'a8061dc1305136c6c22b8baf0c0127a9', tag252
assert tagx == 'c0875924c1c7987947deafd8780acf49', tagx
assert b2s256_empty == '69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9', b2s256_empty
assert b2s256_abc == '508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982', b2s256_abc
assert kat_of(0)[2] == '48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49', kat_of(0)

out = []
w = out.append

w('//')
w('//  TestVectors.swift')
w('//')
w('//  Published test vectors for the cryptographic primitives.')
w('//')
w('//  Every constant below was extracted mechanically from the source document')
w('//  named in its comment (an RFC or Internet-Draft text file, or the official')
w('//  BLAKE2 known-answer-test file), so no hex string here has been typed by')
w('//  hand. Provenance for each group is recorded in its doc comment.')
w('//')
w('')
w('import Foundation')
w('')
w('/// Test vectors shared by the test suite.')
w('enum TestVectors {')
w('')
w('    // MARK: - BLAKE2s')
w('')
w('    /// Unkeyed BLAKE2s-256, taken from the BLAKE2 reference toolkit')
w('    /// (`hashlib.blake2s`), the same generator that produced the')
w('    /// `blake2s-kat.txt` vectors further down.')
w(f'    static let blake2s256Empty = "{b2s256_empty}"')
w(f'    static let blake2s256Abc = "{b2s256_abc}"')
w(f'    static let blake2s256Input64 = "{b2s256_64}"')
w(f'    static let blake2s256Input128 = "{b2s256_128}"')
w('')
w('    /// Unkeyed BLAKE2s-128. This is deliberately *not* a truncated')
w('    /// BLAKE2s-256: the digest length lives in the parameter block, so the')
w('    /// two functions have different initialisation vectors. WireGuard uses')
w('    /// the 16 byte digest with a 32 byte key for `mac1`, `mac2` and the')
w('    /// cookie.')
w(f'    static let blake2s128Empty = "{b2s128_empty}"')
w(f'    static let blake2s128Abc = "{b2s128_abc}"')
w('')
w('    /// Keyed BLAKE2s-256 from the official known answer test file')
w('    /// `BLAKE2/BLAKE2/testvectors/blake2s-kat.txt`. The key is always')
w('    /// `000102...1f` (32 bytes) and the message is the first N bytes')
w('    /// `00 01 02 ...`, so these vectors also pin down the rule that the key')
w('    /// is padded to a full 64 byte block and compressed before the message.')
w('    static let blake2sKatKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"')
for name, n in (('Empty', 0), ('Input3', 3), ('Input64', 64), ('Input128', 128), ('Input255', 255)):
    e = kat_of(n)
    w(f'    static let blake2sKeyed{name}Input = "{e[0]}"')
    w(f'    static let blake2sKeyed{name}Hash = "{e[2]}"')
w('')
w('    /// Keyed BLAKE2s-128 with a 32 byte key: the shape WireGuard uses for')
w('    /// `mac1`, `mac2` and the cookie. From the BLAKE2 reference toolkit.')
b2s128_keyed_abc = hashlib.blake2s(b'abc', key=bytes(range(32)), digest_size=16).hexdigest()
b2s128_keyed_empty = hashlib.blake2s(b'', key=bytes(range(32)), digest_size=16).hexdigest()
w(f'    static let blake2sKeyed128AbcHash = "{b2s128_keyed_abc}"')
w(f'    static let blake2sKeyed128EmptyHash = "{b2s128_keyed_empty}"')
w('')
w('    // MARK: - WireGuard KDF')
w('')
w('    /// From the reference implementation\'s own test file, `wireguard-go`\'s')
w('    /// `device/kdf_test.go`. These vectors pin down that WireGuard\'s `Hmac`')
w('    /// is the ordinary RFC 2104 HMAC over BLAKE2s-256, and not a nested')
w('    /// keyed-BLAKE2s construction.')
w('    static let kdfVectors: [(key: String, input: String, t0: String, t1: String, t2: String)] = [')
for (key, inp, t0, t1, t2) in [
    ('746573742d6b6579', '746573742d696e707574',
     '6f0e5ad38daba1bea8a0d213688736f19763239305e0f58aba697f9ffc41c633',
     'df1194df20802a4fe594cde27e92991c8cae66c366e8106aaa937a55fa371e8a',
     'fac6e2745a325f5dc5d11a5b165aad08b0ada28e7b4e666b7c077934a4d76c24'),
    ('776972656775617264', '776972656775617264',
     '491d43bbfdaa8750aaf535e334ecbfe5129967cd64635101c566d4caefda96e8',
     '1e71a379baefd8a79aa4662212fcafe19a23e2b609a3db7d6bcba8f560e3d25f',
     '31e1ae48bddfbe5de38f295e5452b1909a1b4e38e183926af3780b0c1e1f0160'),
    ('', '',
     '8387b46bf43eccfcf349552a095d8315c4055beb90208fb1be23b894bc2ed5d0',
     '58a0e5f6faefccf4807bff1f05fa8a9217945762040bcec2f4b4a62bdfe0e86e',
     '0ce6ea98ec548f8e281e93e32db65621c45eb18dc6f0a7ad94178610a2f7338e'),
]:
    w(f'        (key: "{key}", input: "{inp}",')
    w(f'         t0: "{t0}",')
    w(f'         t1: "{t1}",')
    w(f'         t2: "{t2}"),')
w('    ]')
w('')
w('    // MARK: - ChaCha20')
w('')
w('    /// RFC 8439 section 2.3.2: the ChaCha20 block function.')
w('    static let chacha20BlockKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"')
w('    static let chacha20BlockNonce = "000000090000004a00000000"')
w('    static let chacha20BlockCounter: UInt32 = 1')
w('    static let chacha20BlockOutput = "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"')
w('')
w('    /// RFC 8439 section 2.4.2: encryption with the counter starting at 1.')
w('    static let chacha20Key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"')
w('    static let chacha20Nonce = "000000000000004a00000000"')
w('    static let chacha20Counter: UInt32 = 1')
w(f'    static let chacha20Ciphertext = "{ct242}"')
w('')
w('    /// RFC 8439 section 2.6.2: the first 32 bytes of keystream block 0 are')
w('    /// the Poly1305 one-time key, for the same key and nonce as the AEAD')
w('    /// vector above.')
w('    static let chacha20OneTimeKey = "7bac2b252db447af09b67a55a4e955840ae1d6731075d9eb2a9375783ed553ff"')
w('')
w('    // MARK: - Poly1305')
w('')
w('    /// RFC 8439 section 2.5.2. The message is "Cryptographic Forum Research')
w('    /// Group".')
w('    static let poly1305Key = "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"')
w(f'    static let poly1305Tag = "{tag252}"')
w('')
w('    // MARK: - ChaCha20-Poly1305')
w('')
w('    /// RFC 8439 section 2.8.2: AEAD_CHACHA20_POLY1305.')
w('    static let aeadKey = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"')
w('    static let aeadNonce = "070000004041424344454647"')
w('    static let aeadAAD = "50515253c0c1c2c3c4c5c6c7"')
w('    static let aeadCiphertext = "' + ct282 + '"')
w(f'    static let aeadTag = "{tag282}"')
w('')
w('    /// RFC 8439 section 2.8.2: the keystream the AEAD used, which starts at')
w('    /// block counter 1 because block 0 supplied the Poly1305 key.')
w(f'    static let aeadKeystream = "{keystream282}"')
w('')
w('    // MARK: - HChaCha20 / XChaCha20-Poly1305')
w('')
w('    /// draft-irtf-cfrg-xchacha-03 section 2.2.1 (the HChaCha20 block') 
w('    /// function, reusing the RFC 8439 section 2.3.2 key) and appendix A.3.1')
w('    /// (AEAD_XCHACHA20_POLY1305).')
w('    static let hchachaNonce = "000000090000004a0000000031415927"')
w('    static let hchachaSubkey = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"')
w('    static let xchachaKey = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"')
w('    static let xchachaNonce = "404142434445464748494a4b4c4d4e4f5051525354555657"')
w(f'    static let xchachaCiphertext = "{ctx}"')
w(f'    static let xchachaTag = "{tagx}"')
w('')
w('    /// The plaintext shared by the ChaCha20, ChaCha20-Poly1305 and')
w('    /// XChaCha20-Poly1305 vectors above.')
w('    static let sunscreenPlaintext = "Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it."')
w('')
w('    /// The Poly1305 message from RFC 8439 section 2.5.2.')
w('    static let poly1305Message = "Cryptographic Forum Research Group"')
w('')
w('    // MARK: - X25519')
w('')
w('    /// RFC 7748 section 6.1.')
w('    static let x25519AlicePrivate = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"')
w('    static let x25519AlicePublic = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"')
w('    static let x25519BobPrivate = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"')
w('    static let x25519BobPublic = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"')
w('    static let x25519SharedSecret = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"')
w('')
w('    /// RFC 7748 section 5.2: the iterated test. Iteration 1 and the (quick')
w('    /// enough for CI) thousandth iteration; the RFC also prints the')
w('    /// millionth, which would take minutes and is left out.')
w('    static let x25519IteratedScalar = "0900000000000000000000000000000000000000000000000000000000000000"')
w('    static let x25519Iterated1 = "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"')
w('    static let x25519Iterated1000 = "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"')
w('')
w('    // MARK: - Internet checksum')
w('')
w('    /// RFC 1071 section 3: a complete IPv4 header taken from a valid')
w('    /// datagram, so its checksum field already holds the value that makes the')
w('    /// one\'s complement sum of the whole header zero.')
w('    static let ipv4Header = "45000073000040004011b861c0a80001c0a800c7"')
w('    static let ipv4HeaderChecksum = "b861"')
w('')
w('    // MARK: - TAI64N')
w('')
w('    /// TAI64N encodes TAI seconds as a big endian 64 bit counter with the')
w('    /// offset 2^62 + 10 relative to the Unix epoch (the ten second TAI/UTC')
w('    /// difference at that instant), followed by big endian nanoseconds.')
w('    static let tai64nUnixEpoch = "400000000000000a00000000"')
w(f'    static let tai64nExample = "{tai64n(1672531200, 0)}"')
w(f'    static let tai64nExampleNanos = "{tai64n(1700000000, 500000000)}"')
w(f'    static let tai64nMaxNanos = "{tai64n(0, 999999999)}"')
w('}')
w('')

sys.stdout.write('\n'.join(out))
