//
//  RealKeychainTests.swift
//  SecureVaultExampleTests
//
//  Created by Prakash on 09/10/26.
//

import Foundation
import Testing
import SecureVault
@testable import SecureVaultExample

/// Runs inside the example app, so SecureVault uses the real data-protection Keychain and Data Protection.
@Suite("Example app on the real Keychain", .serialized)
struct RealKeychainTests {
    let vault: SecureVault

    init() {
        vault = SecureVault(configuration: .init(identifier: "example.tests.\(UUID().uuidString)",
                                                 directory: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)))
    }

    @Test("tokens, profiles and failing closed")
    func keyValues() async throws {
        defer { Task { try? await vault.reset() } }
        try await vault.store("at", forKey: "accessToken", namespace: .auth, policy: .accessToken)
        try await vault.store("pw", forKey: "password", namespace: .auth, policy: .credential)
        try await vault.store(Profile(name: "Asha", email: "a@x.y"), forKey: "profile", namespace: .user)
        try await vault.store("note", forKey: "note", namespace: .medical, policy: .highlySensitive)
        await vault.lock()
        #expect(try await vault.retrieve(String.self, forKey: "accessToken", namespace: .auth) == "at")
        #expect(try await vault.retrieve(String.self, forKey: "password", namespace: .auth) == "pw")
        #expect(try await vault.retrieve(Profile.self, forKey: "profile", namespace: .user).name == "Asha")
        #expect(try await vault.retrieve(String.self, forKey: "note", namespace: .medical) == "note")
        await #expect(throws: SecureVaultError.typeMismatch(expected: "Int")) {
            try await vault.retrieve(Int.self, forKey: "accessToken", namespace: .auth)
        }
        await #expect(throws: SecureVaultError.self) { try await vault.store("x", forKey: "k", policy: .highlySensitive.allowingBackup()) }
    }

    @Test("biometric items need enrolled biometry")
    func biometric() async throws {
        defer { Task { try? await vault.reset() } }
        if BiometricAuthenticator().isBiometryAvailable {
            try await vault.store("4821", forKey: "pin", namespace: .financial, policy: .biometric)
            #expect(try await vault.exists(forKey: "pin", namespace: .financial))
        } else {
            await #expect(throws: SecureVaultError.biometryNotAvailable) {
                try await vault.store("4821", forKey: "pin", namespace: .financial, policy: .biometric)
            }
        }
    }

    @Test("expiry, namespaces, logout and reset")
    func lifecycle() async throws {
        try await vault.store("s", forKey: "session", namespace: .session, policy: .session.expiring(after: 1))
        try await vault.store("dark", forKey: "theme", namespace: .preferences, policy: .preference)
        try await vault.store("alice", forKey: "draft", namespace: .user(id: "alice"))
        try await Task.sleep(nanoseconds: 1_200_000_000)
        await #expect(throws: SecureVaultError.expired) { try await vault.retrieve(String.self, forKey: "session", namespace: .session) }
        try await vault.logout()
        #expect(try await vault.exists(forKey: "theme", namespace: .preferences))
        try await vault.clear(namespace: .user(id: "alice"))
        #expect(try await vault.exists(forKey: "draft", namespace: .user(id: "alice")) == false)
        try await vault.reset()
        #expect(try await vault.exists(forKey: "theme", namespace: .preferences) == false)
    }

    @Test("database, files, rotation and the security report")
    func recordsAndFiles() async throws {
        defer { Task { try? await vault.reset() } }
        let db = try await vault.database("medical", policy: .highlySensitive)
        let patients = (0..<3).map { _ in Patient.random() }
        try await db.insert(contentsOf: patients)
        #expect(try await db.count(Patient.self) == 3)
        try await vault.files.write(Data(repeating: 7, count: 200_000), named: "scan.bin", namespace: .medical, policy: .highlySensitive)
        try await vault.store("t", forKey: "token", namespace: .auth, policy: .accessToken)

        let report = try await vault.rotateKeys(databases: ["medical"])
        #expect(report.reencryptedRecords == 3)
        #expect(report.reencryptedFiles == 1)
        #expect(report.reencryptedItems == 1)
        await vault.lock()
        #expect(try await db.get(Patient.self, id: patients[0].id) == patients[0])
        #expect(try await vault.files.read(named: "scan.bin", namespace: .medical).count == 200_000)

        let posture = await vault.securityReport()
        #expect(!posture.findings.contains { $0.code == "keychain.in-memory" })
    }

    @Test("migration from UserDefaults and a legacy Keychain item")
    func migration() async throws {
        defer { Task { try? await vault.reset() } }
        let legacy = SystemKeychain()
        let service = "example.legacy.\(UUID().uuidString)"
        UserDefaults.standard.set("legacy-token", forKey: service)
        try await legacy.set(Data("legacy-refresh".utf8), service: service, account: "refresh",
                             options: KeychainWriteOptions(accessibility: .afterFirstUnlock, deviceOnly: false))
        let report = await vault.migrate([
            .userDefaults(service, as: String.self, to: "accessToken", namespace: .auth, policy: .accessToken),
            .keychain(service: service, account: "refresh", to: "refreshToken", namespace: .auth, policy: .refreshToken),
        ])
        #expect(report.migrated.count == 2)
        #expect(UserDefaults.standard.object(forKey: service) == nil)
        #expect(try await legacy.info(service: service, account: "refresh") == nil)
        #expect(try await vault.retrieve(String.self, forKey: "refreshToken", namespace: .auth) == "legacy-refresh")
    }

    @Test("the Objective-C demo runs end to end")
    @MainActor
    func objectiveC() async {
        let lines: [String] = await withCheckedContinuation { continuation in
            ObjCDemo.run { continuation.resume(returning: $0) }
        }
        #expect(lines.count == 8)
        #expect(lines.contains("Stored a token with a one-hour lifetime"))
        #expect(lines.contains("Missing key reports SVErrorCodeItemNotFound"))
        #expect(lines.contains { $0.hasPrefix("Files: ") && $0.contains("objc-note.txt") })
    }
}
