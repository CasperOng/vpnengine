// swift-tools-version: 5.9
import PackageDescription

// This package holds the tunnel protocol engines used by the Connect app.
//
//   * `Crypto/`, `Noise/`, `Session/`, `Net/` and `Config/` implement the
//     WireGuard protocol (whitepaper: https://www.wireguard.com/protocol/).
//   * `OpenVPN/` implements the OpenVPN protocol.
//
// Both engines live in one target, so they share the cryptographic primitives
// in `Crypto/` and the IP helpers in `Net/`.
//
// The three `regenerate-*.py` scripts under Tests are the generators for the
// test vector files next to them; they are not build inputs.
let package = Package(
    name: "VPNEngine",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "VPNEngine", targets: ["VPNEngine"]),
    ],
    targets: [
        .target(
            name: "VPNEngine",
            path: "Sources/VPNEngine"
        ),
        .testTarget(
            name: "VPNEngineTests",
            dependencies: ["VPNEngine"],
            path: "Tests/VPNEngineTests",
            exclude: [
                "regenerate-test-vectors.py",
                "regenerate-packet-vectors.py",
                "regenerate-handshake-vectors.py",
            ]
        ),
    ]
)
