//
//  MigrationDemo.swift
//  SecureVaultExample
//
//  Created by Prakash on 09/10/26.
//

import SecureVault
import SwiftUI

/// Moves values an older app version kept in UserDefaults and the Keychain into the vault.
struct MigrationDemo: View {
    @Environment(\.secureVault) private var vault
    @State private var log = DemoLog()
    private let legacyKeychain = SystemKeychain()

    var body: some View {
        Form {
            Section {
                Text("Each source is deleted only after the copy in the vault is read back and matches. Running it again skips what was already moved.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            Section("1. Pretend to be the old app") {
                ActionRow("Write legacy values", systemImage: "tray.and.arrow.down", log: log) {
                    UserDefaults.standard.set("legacy-access-token", forKey: "legacy.authToken")
                    UserDefaults.standard.set(12, forKey: "legacy.launchCount")
                    try await legacyKeychain.set(Data("legacy-refresh-token".utf8), service: "legacy.auth", account: "refresh",
                                                 options: KeychainWriteOptions(accessibility: .afterFirstUnlock, deviceOnly: false))
                    return "UserDefaults: authToken, launchCount\nKeychain: legacy.auth/refresh"
                }
            }
            Section("2. Migrate") {
                ActionRow("Run migration", systemImage: "arrow.right.circle", log: log) {
                    let report = await vault.migrate([
                        .userDefaults("legacy.authToken", as: String.self, to: "accessToken", namespace: .auth, policy: .accessToken),
                        .userDefaults("legacy.launchCount", as: Int.self, to: "launchCount", namespace: .preferences, policy: .preference),
                        .keychain(service: "legacy.auth", account: "refresh", to: "refreshToken", namespace: .auth, policy: .refreshToken),
                    ])
                    let failed = report.failed.map { "\($0.label): \($0.error.localizedDescription)" }
                    return (["Migrated \(report.migrated.count), skipped \(report.skipped.count), failed \(report.failed.count)"]
                            + report.migrated.map { "✓ \($0)" } + report.skipped.map { "– \($0)" } + failed).joined(separator: "\n")
                }
            }
            Section("3. Check") {
                ActionRow("Are the old values gone?", systemImage: "checklist", log: log) {
                    let defaults = UserDefaults.standard.object(forKey: "legacy.authToken") == nil
                    let keychain = try await legacyKeychain.info(service: "legacy.auth", account: "refresh") == nil
                    let migrated = try await vault.value(String.self, forKey: "refreshToken", namespace: .auth) ?? "–"
                    return "UserDefaults cleared: \(defaults)\nLegacy Keychain cleared: \(keychain)\nVault refresh token: \(migrated)"
                }
            }
            DemoLogSection(log: log)
        }
        .navigationTitle("Migration")
    }
}
