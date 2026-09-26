// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "PayphoneKit",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "PayphoneKit", targets: ["PayphoneKit"]),
    ],
    targets: [
        .target(name: "PayphoneKit"),
        .testTarget(name: "PayphoneKitTests", dependencies: ["PayphoneKit"]),
    ]
)
