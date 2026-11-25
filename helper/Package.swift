// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "nod",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(name: "nod", path: "Sources/nod")
    ]
)
