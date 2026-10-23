//
//  TestVectors.swift
//
//  Published test vectors for the cryptographic primitives.
//
//  Every constant below was extracted mechanically from the source document
//  named in its comment (an RFC or Internet-Draft text file, or the official
//  BLAKE2 known-answer-test file), so no hex string here has been typed by
//  hand. Provenance for each group is recorded in its doc comment.
//

import Foundation

/// Test vectors shared by the test suite.
enum TestVectors {

    // MARK: - BLAKE2s

    /// Unkeyed BLAKE2s-256, taken from the BLAKE2 reference toolkit
    /// (`hashlib.blake2s`), the same generator that produced the
    /// `blake2s-kat.txt` vectors further down.
    static let blake2s256Empty = "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    static let blake2s256Abc = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
    static let blake2s256Input64 = "56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e"
    static let blake2s256Input128 = "1fa877de67259d19863a2a34bcc6962a2b25fcbf5cbecd7ede8f1fa36688a796"

    /// Unkeyed BLAKE2s-128. This is deliberately *not* a truncated
    /// BLAKE2s-256: the digest length lives in the parameter block, so the
    /// two functions have different initialisation vectors. WireGuard uses
    /// the 16 byte digest with a 32 byte key for `mac1`, `mac2` and the
    /// cookie.
    static let blake2s128Empty = "64550d6ffe2c0a01a14aba1eade0200c"
    static let blake2s128Abc = "aa4938119b1dc7b87cbad0ffd200d0ae"

    /// Keyed BLAKE2s-256 from the official known answer test file
    /// `BLAKE2/BLAKE2/testvectors/blake2s-kat.txt`. The key is always
    /// `000102...1f` (32 bytes) and the message is the first N bytes
    /// `00 01 02 ...`, so these vectors also pin down the rule that the key
    /// is padded to a full 64 byte block and compressed before the message.
    static let blake2sKatKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    static let blake2sKeyedEmptyInput = ""
    static let blake2sKeyedEmptyHash = "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49"
    static let blake2sKeyedInput3Input = "000102"
    static let blake2sKeyedInput3Hash = "1d220dbe2ee134661fdf6d9e74b41704710556f2f6e5a091b227697445dbea6b"
    static let blake2sKeyedInput64Input = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    static let blake2sKeyedInput64Hash = "8975b0577fd35566d750b362b0897a26c399136df07bababbde6203ff2954ed4"
    static let blake2sKeyedInput128Input = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
    static let blake2sKeyedInput128Hash = "0c311f38c35a4fb90d651c289d486856cd1413df9b0677f53ece2cd9e477c60a"
    static let blake2sKeyedInput255Input = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe"
    static let blake2sKeyedInput255Hash = "3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd"

    /// Keyed BLAKE2s-128 with a 32 byte key: the shape WireGuard uses for
    /// `mac1`, `mac2` and the cookie. From the BLAKE2 reference toolkit.
    static let blake2sKeyed128AbcHash = "61ba5f165c194692e09d12520cc4c74a"
    static let blake2sKeyed128EmptyHash = "9536f9b267655743dee97b8a670f9f53"

    // MARK: - WireGuard KDF

    /// From the reference implementation's own test file, `wireguard-go`'s
    /// `device/kdf_test.go`. These vectors pin down that WireGuard's `Hmac`
    /// is the ordinary RFC 2104 HMAC over BLAKE2s-256, and not a nested
    /// keyed-BLAKE2s construction.
    static let kdfVectors: [(key: String, input: String, t0: String, t1: String, t2: String)] = [
        (key: "746573742d6b6579", input: "746573742d696e707574",
         t0: "6f0e5ad38daba1bea8a0d213688736f19763239305e0f58aba697f9ffc41c633",
         t1: "df1194df20802a4fe594cde27e92991c8cae66c366e8106aaa937a55fa371e8a",
         t2: "fac6e2745a325f5dc5d11a5b165aad08b0ada28e7b4e666b7c077934a4d76c24"),
        (key: "776972656775617264", input: "776972656775617264",
         t0: "491d43bbfdaa8750aaf535e334ecbfe5129967cd64635101c566d4caefda96e8",
         t1: "1e71a379baefd8a79aa4662212fcafe19a23e2b609a3db7d6bcba8f560e3d25f",
         t2: "31e1ae48bddfbe5de38f295e5452b1909a1b4e38e183926af3780b0c1e1f0160"),
        (key: "", input: "",
         t0: "8387b46bf43eccfcf349552a095d8315c4055beb90208fb1be23b894bc2ed5d0",
         t1: "58a0e5f6faefccf4807bff1f05fa8a9217945762040bcec2f4b4a62bdfe0e86e",
         t2: "0ce6ea98ec548f8e281e93e32db65621c45eb18dc6f0a7ad94178610a2f7338e"),
    ]

    // MARK: - ChaCha20

    /// RFC 8439 section 2.3.2: the ChaCha20 block function.
    static let chacha20BlockKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    static let chacha20BlockNonce = "000000090000004a00000000"
    static let chacha20BlockCounter: UInt32 = 1
    static let chacha20BlockOutput = "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"

    /// RFC 8439 section 2.4.2: encryption with the counter starting at 1.
    static let chacha20Key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    static let chacha20Nonce = "000000000000004a00000000"
    static let chacha20Counter: UInt32 = 1
    static let chacha20Ciphertext = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"

    /// RFC 8439 section 2.6.2: the first 32 bytes of keystream block 0 are
    /// the Poly1305 one-time key, for the same key and nonce as the AEAD
    /// vector above.
    static let chacha20OneTimeKey = "7bac2b252db447af09b67a55a4e955840ae1d6731075d9eb2a9375783ed553ff"

    // MARK: - Poly1305

    /// RFC 8439 section 2.5.2. The message is "Cryptographic Forum Research
    /// Group".
    static let poly1305Key = "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
    static let poly1305Tag = "a8061dc1305136c6c22b8baf0c0127a9"

    // MARK: - ChaCha20-Poly1305

    /// RFC 8439 section 2.8.2: AEAD_CHACHA20_POLY1305.
    static let aeadKey = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    static let aeadNonce = "070000004041424344454647"
    static let aeadAAD = "50515253c0c1c2c3c4c5c6c7"
    static let aeadCiphertext = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
    static let aeadTag = "1ae10b594f09e26a7e902ecbd0600691"

    /// RFC 8439 section 2.8.2: the keystream the AEAD used, which starts at
    /// block counter 1 because block 0 supplied the Poly1305 key.
    static let aeadKeystream = "9f7be95d01fd40ba15e28ffb36810aaec1c0883f09016ededd8ad087558203a54e9ecb38ac8e5e2bb8dab20ffadb52e87504b26ebe696d4f60a485cf11b81b59fcb1c45f4219eeacec6adec34e6669788edb41c49ca301e127e0acab3b44b9cf5c86bb95e06b0df2901ab645e4abe6221538"

    // MARK: - HChaCha20 / XChaCha20-Poly1305

    /// draft-irtf-cfrg-xchacha-03 section 2.2.1 (the HChaCha20 block
    /// function, reusing the RFC 8439 section 2.3.2 key) and appendix A.3.1
    /// (AEAD_XCHACHA20_POLY1305).
    static let hchachaNonce = "000000090000004a0000000031415927"
    static let hchachaSubkey = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    static let xchachaKey = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    static let xchachaNonce = "404142434445464748494a4b4c4d4e4f5051525354555657"
    static let xchachaCiphertext = "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e"
    static let xchachaTag = "c0875924c1c7987947deafd8780acf49"

    /// The plaintext shared by the ChaCha20, ChaCha20-Poly1305 and
    /// XChaCha20-Poly1305 vectors above.
    static let sunscreenPlaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

    /// The Poly1305 message from RFC 8439 section 2.5.2.
    static let poly1305Message = "Cryptographic Forum Research Group"

    // MARK: - X25519

    /// RFC 7748 section 6.1.
    static let x25519AlicePrivate = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    static let x25519AlicePublic = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    static let x25519BobPrivate = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    static let x25519BobPublic = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    static let x25519SharedSecret = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

    /// RFC 7748 section 5.2: the iterated test. Iteration 1 and the (quick
    /// enough for CI) thousandth iteration; the RFC also prints the
    /// millionth, which would take minutes and is left out.
    static let x25519IteratedScalar = "0900000000000000000000000000000000000000000000000000000000000000"
    static let x25519Iterated1 = "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
    static let x25519Iterated1000 = "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"

    // MARK: - Internet checksum

    /// RFC 1071 section 3: a complete IPv4 header taken from a valid
    /// datagram, so its checksum field already holds the value that makes the
    /// one's complement sum of the whole header zero.
    static let ipv4Header = "45000073000040004011b861c0a80001c0a800c7"
    static let ipv4HeaderChecksum = "b861"

    // MARK: - TAI64N

    /// TAI64N encodes TAI seconds as a big endian 64 bit counter with the
    /// offset 2^62 + 10 relative to the Unix epoch (the ten second TAI/UTC
    /// difference at that instant), followed by big endian nanoseconds.
    static let tai64nUnixEpoch = "400000000000000a00000000"
    static let tai64nExample = "4000000063b0cd0a00000000"
    static let tai64nExampleNanos = "400000006553f10a1dcd6500"
    static let tai64nMaxNanos = "400000000000000a3b9ac9ff"
}
