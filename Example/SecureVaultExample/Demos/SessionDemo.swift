//
//  SessionDemo.swift
//  SecureVaultExample
//
//  Created by Prakash on 09/10/26.
//

import SecureVault
import SwiftUI

/// Namespaces keep data apart so logout clears the session and leaves preferences alone.
struct SessionDemo: View {
    @Environment(\.secureVault) private var vault
    @State private var log = DemoLog()
    @State private var confirmReset = false

    var body: some View {
        Form {
            Section("Set up") {
                ActionRow("Sign in two accounts", systemImage: "person.2", log: log) {
                    try await vault.store("token-alice", forKey: "accessToken", namespace: .auth, policy: .accessToken)
                    try await vault.store("Alice's draft", forKey: "draft", namespace: .user(id: "alice"))
                    try await vault.store("Bob's draft", forKey: "draft", namespace: .user(id: "bob"))
                    try await vault.store("dark", forKey: "theme", namespace: .preferences, policy: .preference)
                    try await vault.store("cached feed", forKey: "feed", namespace: .cache)
                    return "auth, user.alice, user.bob, preferences, cache"
                }
                ActionRow("Show what is stored", systemImage: "list.bullet", log: log) { try await snapshot() }
            }
            Section("Clean up") {
                ActionRow("Log out (auth, session, cache)", systemImage: "rectangle.portrait.and.arrow.right", log: log) {
                    try await vault.logout()
                    return try await snapshot()
                }
                ActionRow("Remove Alice's account", systemImage: "person.badge.minus", log: log) {
                    try await vault.clear(namespace: .user(id: "alice"))
                    return try await snapshot()
                }
                ActionRow("Lock (drop cached keys)", systemImage: "lock", log: log) {
                    await vault.lock()
                    return "Keys are reloaded from the Keychain on next use"
                }
                Button("Reset the vault…", role: .destructive) { confirmReset = true }
            }
            DemoLogSection(log: log)
        }
        .navigationTitle("Namespaces and logout")
        .confirmationDialog("Destroy every key, value, file and database?", isPresented: $confirmReset, titleVisibility: .visible) {
            Button("Reset the vault", role: .destructive) {
                log.run("Reset") {
                    try await vault.reset()
                    return "Everything crypto-shredded"
                }
            }
        }
    }

    private func snapshot() async throws -> String {
        func has(_ key: String, _ namespace: VaultNamespace) async throws -> String {
            try await vault.exists(forKey: key, namespace: namespace) ? "✓" : "–"
        }
        return """
        auth/accessToken  \(try await has("accessToken", .auth))
        user.alice/draft  \(try await has("draft", .user(id: "alice")))
        user.bob/draft    \(try await has("draft", .user(id: "bob")))
        preferences/theme \(try await has("theme", .preferences))
        cache/feed        \(try await has("feed", .cache))
        """
    }
}
