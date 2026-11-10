// swift-tools-version:5.9
import PackageDescription
import Foundation

let nativePath = "Native/CPayphoneNative.xcframework"
let hasNative = FileManager.default.fileExists(atPath:
    URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent(nativePath).path)
var targets: [Target] = [
    .target(name: "PayphoneKit", dependencies: hasNative ? [.target(name: "CPayphoneNative")] : [],
            linkerSettings: hasNative ? [.linkedFramework("Security"), .linkedFramework("SystemConfiguration"), .linkedLibrary("resolv")] : []),
    .testTarget(name: "PayphoneKitTests", dependencies: ["PayphoneKit"]),
]
if hasNative { targets.append(.binaryTarget(name: "CPayphoneNative", path: nativePath)) }

let package = Package(
    name: "PayphoneKit",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "PayphoneKit", targets: ["PayphoneKit"]),
    ],
    targets: targets
)
