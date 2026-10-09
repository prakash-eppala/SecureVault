//
//  MigrationTests.swift
//  SecureVaultTests
//
//  Created by Prakash on 09/10/26.
//

import Foundation
import Testing
@testable import SecureVault

@Suite("Migration (PRD §24)")
struct MigrationTests {
    @Test("UserDefaults values move in and the source is deleted after verification")
    func userDefaults() async throws {
        let suite = "svtest.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set("legacy-token", forKey: "authToken")
        defaults.set(7, forKey: "launches")
        defaults.set(try JSONEncoder().encode(Profile(name: "N", email: "e", age: 9)), forKey: "profile")

        let h = Harness()
        let report = await h.vault.migrate([
            .userDefaults("authToken", suiteName: suite, as: String.self, to: "accessToken", namespace: .auth, policy: .accessToken),
            .userDefaults("launches", suiteName: suite, as: Int.self, to: "launches", policy: .preference),
            .userDefaults("profile", suiteName: suite, as: Profile.self, to: "profile", namespace: .user, policy: .sensitive),
            .userDefaults("absent", suiteName: suite, as: String.self, to: "absent", policy: .sensitive),
        ])
        #expect(report.migrated.count == 3)
        #expect(report.skipped.count == 1)
        #expect(report.isComplete)
        #expect(defaults.object(forKey: "authToken") == nil)
        #expect(try await h.vault.retrieve(String.self, forKey: "accessToken", namespace: .auth) == "legacy-token")
        #expect(try await h.vault.retrieve(Int.self, forKey: "launches") == 7)
        #expect(try await h.vault.retrieve(Profile.self, forKey: "profile", namespace: .user).age == 9)

        // Running again is harmless.
        let again = await h.vault.migrate([.userDefaults("authToken", suiteName: suite, as: String.self, to: "accessToken", namespace: .auth, policy: .accessToken)])
        #expect(again.skipped.count == 1)
    }

    @Test("a failed store leaves the source intact")
    func failureKeepsSource() async throws {
        let suite = "svtest.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set("x", forKey: "k")
        let h = Harness(capabilities: FixedDeviceCapabilities(passcodeSet: false))
        let report = await h.vault.migrate([.userDefaults("k", suiteName: suite, as: String.self, to: "k", policy: .highlySensitive)])
        #expect(report.failed.count == 1)
        #expect(defaults.string(forKey: "k") == "x")
    }

    @Test("legacy Keychain items move in")
    func keychain() async throws {
        let legacy = InMemoryKeychain()
        try await legacy.set(Data("old-refresh".utf8), service: "com.acme.legacy", account: "refresh",
                             options: KeychainWriteOptions(accessibility: .afterFirstUnlock, deviceOnly: false))
        let h = Harness()
        let report = await h.vault.migrate([
            .keychain(service: "com.acme.legacy", account: "refresh", to: "refreshToken", namespace: .auth, policy: .refreshToken, source: legacy),
        ])
        #expect(report.migrated.count == 1)
        #expect(try await legacy.info(service: "com.acme.legacy", account: "refresh") == nil)
        #expect(try await h.vault.retrieve(String.self, forKey: "refreshToken", namespace: .auth) == "old-refresh")
    }
}
