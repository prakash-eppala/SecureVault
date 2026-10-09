// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SecureVault",
    platforms: [
        .iOS(.v15),
        .macCatalyst(.v15),
        .macOS(.v12),
    ],
    products: [
        // One product for Swift, Objective-C and SwiftUI: `import SecureVault` / `@import SecureVault;`.
        .library(name: "SecureVault", targets: ["SecureVault"]),
    ],
    targets: [
        .target(
            name: "SecureVaultCore",
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("LocalAuthentication"),
            ]
        ),
        .target(name: "SecureVaultKeychain", dependencies: ["SecureVaultCore"]),
        .target(name: "SecureVaultCrypto", dependencies: ["SecureVaultCore"]),
        .target(name: "SecureVaultBiometrics", dependencies: ["SecureVaultCore"]),
        .target(
            name: "SecureVaultDatabase",
            dependencies: ["SecureVaultCore", "SecureVaultCrypto"],
            linkerSettings: [.linkedLibrary("sqlite3")]
        ),
        .target(name: "SecureVaultFiles", dependencies: ["SecureVaultCore", "SecureVaultCrypto"]),
        .target(name: "SecureVaultDiagnostics", dependencies: ["SecureVaultCore"]),
        .target(
            name: "SecureVault",
            dependencies: [
                "SecureVaultCore",
                "SecureVaultKeychain",
                "SecureVaultCrypto",
                "SecureVaultBiometrics",
                "SecureVaultDatabase",
                "SecureVaultFiles",
                "SecureVaultDiagnostics",
            ],
            resources: [.copy("PrivacyInfo.xcprivacy")]
        ),
        .testTarget(name: "SecureVaultTests", dependencies: ["SecureVault"]),
        .testTarget(name: "SecureVaultObjCTests", dependencies: ["SecureVault"]),
    ],
    swiftLanguageModes: [.v6]
)
