//
//  DatagramTransport.swift
//  VPNEngine
//
//  The socket the session talks through.
//
//  WireGuard runs over UDP, and a tunnel only ever needs "send this datagram"
//  and "give me the next datagram", so the session is written against this
//  protocol rather than against Network.framework directly. A NetworkExtension
//  can plug in an `NWConnection` in UDP mode; a test plugs in
//  ``InMemoryDatagramTransport``.
//

import Foundation

/// Errors a transport can produce.
public enum DatagramTransportError: Error, Equatable, Sendable {

    /// The transport was closed, locally or by the peer.
    case closed

    /// No peer is attached to this transport.
    case noPeer

    /// The underlying socket failed.
    case failed(String)
}

/// A connected datagram (UDP) socket.
///
/// Implementations must be safe to call from several tasks: the session sends
/// from its timer loop and from its outbound queue while a dedicated task
/// receives.
public protocol DatagramTransport: AnyObject, Sendable {

    /// Sends one datagram.
    ///
    /// - Parameter datagram: The bytes to send. Datagram boundaries are
    ///   preserved; the receiver sees exactly one call to ``receive()``.
    /// - Throws: ``DatagramTransportError`` when the transport is closed or the
    ///   socket fails.
    func send(_ datagram: Data) async throws

    /// Waits for the next datagram.
    ///
    /// - Throws: ``DatagramTransportError/closed`` when the transport is closed
    ///   while waiting.
    /// - Returns: Exactly the bytes of one ``send(_:)`` call.
    func receive() async throws -> Data

    /// Closes the transport.
    ///
    /// Any pending ``receive()`` fails with ``DatagramTransportError/closed``.
    /// Calling this more than once is harmless.
    func close() async
}
