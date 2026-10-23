//
//  CryptoError.swift
//  VPNEngine
//
//  Errors shared by the cryptographic primitives.
//

import Foundation

/// Errors thrown by the cryptographic layer.
///
/// None of these cases are ever produced from a code path where a `fatalError`
/// would otherwise have been used: malformed network input always surfaces as
/// an error value that callers can drop silently, as the WireGuard protocol
/// requires.
public enum VPNCryptoError: Error, Equatable, Sendable {

    /// A key was not the size the algorithm requires.
    case invalidKeySize(expected: Int, actual: Int)

    /// A nonce was not the size the algorithm requires.
    case invalidNonceSize(expected: Int, actual: Int)

    /// A public key was not usable (wrong size, or a low order point).
    case invalidPublicKey

    /// AEAD authentication failed: the message was forged or corrupted.
    case authenticationFailure

    /// A message did not have a valid structure for its type.
    case malformedMessage(String)

    /// The operation is not valid in the current state.
    case invalidState(String)

    /// The message did not authenticate against the expected `mac1` value.
    case invalidMAC1

    /// The running platform cannot perform this operation (no CryptoKit).
    case unsupportedPlatform(String)
}
