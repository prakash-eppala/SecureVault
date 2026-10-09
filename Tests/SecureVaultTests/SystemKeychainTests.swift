//
//  SystemKeychainTests.swift
//  SecureVaultTests
//
//  Created by Prakash on 09/10/26.
//

import Foundation
import Security
import Testing
@testable import SecureVault

/// Runs against the real data-protection Keychain. It needs a Keychain entitlement, which a test host app has
/// and a hostless SPM test bundle (macOS or iOS Simulator) does not, so it is skipped where the Keychain is unavailable.
enum RealKeychain {
    static let isAvailable: Bool = {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain: true,
            kSecAttrService: "securevault.probe",
            kSecAttrAccount: UUID().uuidString,
            kSecValueData: Data([1]),
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecSuccess {
            SecItemDelete([kSecClass: kSecClassGenericPassword, kSecUseDataProtectionKeychain: true,
                           kSecAttrService: "securevault.probe"] as CFDictionary)
        }
        return status == errSecSuccess
    }()
}

@Suite("System Keychain integration", .enabled(if: RealKeychain.isAvailable, "needs a Keychain entitlement: run from a host app"))
struct SystemKeychainTests {
    @Test("set, update, info, get, list, delete")
    func backend() async throws {
        let keychain = SystemKeychain()
        let service = "securevault.it.\(UUID().uuidString)"
        defer { Task { try? await keychain.deleteAll(service: service) } }
        let options = KeychainWriteOptions(accessibility: .afterFirstUnlock, deviceOnly: true)
        try await keychain.set(Data("one".utf8), service: service, account: "a", options: options)
        try await keychain.set(Data("two".utf8), service: service, account: "a", options: options)
        #expect(try await keychain.get(service: service, account: "a", authentication: nil) == Data("two".utf8))

        let info = try #require(try await keychain.info(service: service, account: "a"))
        #expect(info.accessibility == .afterFirstUnlock)
        #expect(info.deviceOnly)
        #expect(!info.requiresUserAuthentication)

        await #expect(throws: SecureVaultError.keychainFailure(status: KeychainStatus.duplicateItem)) {
            try await keychain.set(Data(), service: service, account: "a", options: KeychainWriteOptions(accessibility: .afterFirstUnlock, deviceOnly: true, overwrite: false))
        }
        try await keychain.updateData(Data("three".utf8), service: service, account: "a")
        #expect(try await keychain.get(service: service, account: "a", authentication: nil) == Data("three".utf8))
        #expect(try await keychain.accounts(service: service) == ["a"])
        #expect(try await keychain.services(withPrefix: service) == [service])
        try await keychain.delete(service: service, account: "a")
        #expect(try await keychain.info(service: service, account: "a") == nil)
        await #expect(throws: SecureVaultError.itemNotFound) { try await keychain.get(service: service, account: "a", authentication: nil) }
    }

    @Test("a full vault on the real Keychain")
    func vault() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("svit-\(UUID().uuidString)")
        let vault = SecureVault(configuration: .init(identifier: "svit.\(UUID().uuidString)", directory: directory, secureEnclave: .whenAvailable))
        defer { Task { try? await vault.reset() } }

        try await vault.store("tok", forKey: "accessToken", namespace: .auth, policy: .accessToken)
        try await vault.store(Profile(name: "R", email: "r@x.y", age: 30), forKey: "profile", namespace: .user)
        await vault.lock()
        #expect(try await vault.retrieve(String.self, forKey: "accessToken", namespace: .auth) == "tok")
        #expect(try await vault.retrieve(Profile.self, forKey: "profile", namespace: .user).age == 30)

        let report = try await vault.rotateKeys()
        #expect(report.reencryptedItems == 2)
        await vault.lock()
        #expect(try await vault.retrieve(String.self, forKey: "accessToken", namespace: .auth) == "tok")

        try await vault.logout()
        #expect(try await vault.exists(forKey: "accessToken", namespace: .auth) == false)
        #expect(try await vault.exists(forKey: "profile", namespace: .user))
    }
}
