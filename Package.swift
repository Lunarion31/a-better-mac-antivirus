// swift-tools-version: 6.0
import PackageDescription
let package = Package(
    name: "ABAMac", platforms: [.macOS(.v13)],
    products: [.executable(name: "aba", targets: ["ABA"])],
    targets: [
        .target(name: "ABACore"),
        .target(name: "CEndpoint", linkerSettings: [.linkedLibrary("EndpointSecurity"), .linkedLibrary("bsm")]),
        .executableTarget(name: "ABA", dependencies: ["ABACore", "CEndpoint"]),
        .testTarget(name: "ABACoreTests", dependencies: ["ABACore"])
    ], swiftLanguageModes: [.v5]
)
