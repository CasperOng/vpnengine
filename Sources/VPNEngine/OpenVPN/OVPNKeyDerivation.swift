import Foundation

/// Turns OpenVPN key material into the directional keys the data channel uses.
///
/// OpenVPN always works with 256 bytes of material that has the shape of
///
/// ```c
/// struct key2 { int n; struct key keys[2]; };
/// struct key  { uint8_t cipher[64]; uint8_t hmac[64]; };
/// ```
///
/// * `keys[0]` are the *client's* outgoing keys,
/// * `keys[1]` are the *server's* outgoing keys.
///
/// `key_direction_state_init()` is then called with
/// `KEY_DIRECTION_NORMAL` on the client and `KEY_DIRECTION_INVERSE` on the
/// server, so both sides agree on which block is a send key and which is a
/// receive key.
public enum OVPNKeyDerivation {

    /// Split 256 bytes of key material into send/receive keys.
    ///
    /// - Parameters:
    ///   - material: 256 bytes (`keys[0] || keys[1]`).
    ///   - isServer: `true` when the local side is the server.
    ///   - cipher: negotiated cipher (decides key and IV lengths).
    ///   - hmac: negotiated HMAC digest, `nil` for AEAD ciphers.
    public static func dataKeys(
        fromKeyMaterial material: Data,
        isServer: Bool,
        cipher: OVPNCipherSpec,
        hmac: OVPNHMACAlgorithm?
    ) throws -> OVPNDataKeys {
        guard let key = try? OVPNStaticKey(raw: material) else {
            throw OVPNError.invalidStaticKey("key material must be 256 bytes, got \(material.count)")
        }
        // KEY_DIRECTION_NORMAL on the client, KEY_DIRECTION_INVERSE on the
        // server.
        let keyFile = OVPNStaticKeyFile(direction: isServer ? 1 : 0, key: key)
        return try OVPNDataKeys.fromStaticKey(keyFile, cipher: cipher, hmac: hmac)
    }

    /// Directional keys from a `--secret` static key file (bidirectional
    /// unless the file carries a direction).
    public static func dataKeys(
        fromStaticKeyFile keyFile: OVPNStaticKeyFile,
        cipher: OVPNCipherSpec,
        hmac: OVPNHMACAlgorithm?
    ) throws -> OVPNDataKeys {
        try OVPNDataKeys.fromStaticKey(keyFile, cipher: cipher, hmac: hmac)
    }

    /// The cipher and digest a configuration asks for, with OpenVPN's defaults
    /// applied.
    ///
    /// OpenVPN 2.6 defaults to `AES-256-GCM` for NCP-capable connections and
    /// keeps `--auth` at `SHA256`; a `--secret` connection still needs an
    /// explicit `cipher`/`auth` pair because there is no negotiation.
    public static func negotiatedCipher(
        configuration: OVPNConfiguration,
        pushedCipher: String? = nil
    ) throws -> (cipher: OVPNCipherSpec, hmac: OVPNHMACAlgorithm?) {
        let name = pushedCipher
            ?? configuration.cipher
            ?? configuration.negotiationCiphers.first
            ?? "AES-256-GCM"
        guard let cipher = OVPNCipherSpec.parse(name) else {
            throw OVPNError.unsupportedCipher(name)
        }
        if cipher.isAEAD { return (cipher, nil) }
        let digestName = configuration.auth ?? "SHA256"
        guard let hmac = OVPNHMACAlgorithm.parse(digestName) else {
            throw OVPNError.unsupportedDigest(digestName)
        }
        return (cipher, hmac)
    }
}
