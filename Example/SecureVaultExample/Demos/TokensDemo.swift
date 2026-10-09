//
//  TokensDemo.swift
//  SecureVaultExample
//
//  Created by Prakash on 09/10/26.
//

import SecureVault
import SwiftUI

struct Profile: Codable, Sendable {
    var name: String
    var email: String
}

/// Stores the same kinds of values a real app does, each with the policy it should use.
struct TokensDemo: View {
    @Environment(\.secureVault) private var vault
    @State private var log = DemoLog()

    var body: some View {
        Form {
            Section {
                Text("Each value names how sensitive it is. SecureVault picks the Keychain or an encrypted file and the protection class.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            Section("Store") {
                ActionRow("Access token (.accessToken)", systemImage: "key", log: log) {
                    try await vault.store("at_\(UUID().uuidString.prefix(8))", forKey: "accessToken", namespace: .auth, policy: .accessToken)
                    return "Keychain, after first unlock, this device only"
                }
                ActionRow("Refresh token (.refreshToken)", systemImage: "arrow.triangle.2.circlepath", log: log) {
                    try await vault.store("rt_\(UUID().uuidString.prefix(8))", forKey: "refreshToken", namespace: .auth, policy: .refreshToken)
                    return "Keychain, readable in the background for token refresh"
                }
                ActionRow("Password (.credential)", systemImage: "lock", log: log) {
                    try await vault.store("correct horse battery staple", forKey: "password", namespace: .auth, policy: .credential)
                    return "Keychain, readable only while unlocked"
                }
                ActionRow("Profile (.sensitive)", systemImage: "person", log: log) {
                    try await vault.store(Profile(name: "Asha Rao", email: "asha@example.com"), forKey: "profile", namespace: .user)
                    return "Encrypted file, this device only"
                }
                ActionRow("Theme (.preference)", systemImage: "paintpalette", log: log) {
                    try await vault.store("dark", forKey: "theme", namespace: .preferences, policy: .preference)
                    return "Encrypted file, included in device backups"
                }
                ActionRow("Medical note (.highlySensitive)", systemImage: "cross.case", log: log) {
                    try await vault.store("Allergic to penicillin", forKey: "note", namespace: .medical, policy: .highlySensitive)
                    return "Encrypted file, readable only while unlocked, passcode required"
                }
            }
            Section("Read") {
                ActionRow("Read everything", systemImage: "eye", log: log) {
                    let token = try await vault.value(String.self, forKey: "accessToken", namespace: .auth) ?? "–"
                    let profile = try await vault.value(Profile.self, forKey: "profile", namespace: .user)
                    let theme = try await vault.value(String.self, forKey: "theme", namespace: .preferences) ?? "–"
                    let note = try await vault.value(String.self, forKey: "note", namespace: .medical) ?? "–"
                    return "token: \(token)\nprofile: \(profile.map { "\($0.name) <\($0.email)>" } ?? "–")\ntheme: \(theme)\nnote: \(note)"
                }
                ActionRow("Read the token as the wrong type", systemImage: "exclamationmark.triangle", log: log) {
                    let number = try await vault.retrieve(Int.self, forKey: "accessToken", namespace: .auth)
                    return "\(number)"
                }
                ActionRow("Does the token exist?", systemImage: "questionmark.circle", log: log) {
                    try await vault.exists(forKey: "accessToken", namespace: .auth) ? "Yes" : "No"
                }
                ActionRow("Delete the token", systemImage: "trash", log: log) {
                    try await vault.delete(forKey: "accessToken", namespace: .auth)
                    return "Deleted"
                }
            }
            Section("Fail closed") {
                ActionRow("Highly sensitive data in backups", systemImage: "nosign", log: log) {
                    try await vault.store("x", forKey: "rejected", policy: .highlySensitive.allowingBackup())
                    return "Stored (unexpected)"
                }
            }
            DemoLogSection(log: log)
        }
        .navigationTitle("Tokens and policies")
    }
}
