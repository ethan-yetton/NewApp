// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "NewApp",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(name: "NewApp")
    ]
)
