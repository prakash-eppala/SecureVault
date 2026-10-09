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
@testable import SecureVaultKeychain

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

#if os(macOS)
/// The same `SystemKeychain` code against the macOS login keychain, which unsigned test bundles may use.
/// Every item lives under a unique `securevault.test.` service and is deleted afterwards.
@Suite("System Keychain on the login keychain", .serialized)
struct LoginKeychainTests {
    let keychain = SystemKeychain(usesDataProtectionKeychain: false)
    let options = KeychainWriteOptions(accessibility: .afterFirstUnlock, deviceOnly: true)

    func withService(_ body: (String) async throws -> Void) async throws {
        let service = "securevault.test.\(UUID().uuidString)"
        do {
            try await body(service)
        } catch {
            try? await keychain.deleteAll(service: service)
            throw error
        }
        try await keychain.deleteAll(service: service)
        #expect(try await keychain.accounts(service: service).isEmpty)
    }

    @Test("set, overwrite, update, get, info, list, delete")
    func lifecycle() async throws {
        try await withService { service in
            #expect(keychain.accessGroup == nil)
            #expect(!keychain.isEphemeral)
            try await keychain.set(Data("one".utf8), service: service, account: "a", options: options)
            try await keychain.set(Data("two".utf8), service: service, account: "a", options: options)
            #expect(try await keychain.get(service: service, account: "a", authentication: nil) == Data("two".utf8))

            let info = try #require(try await keychain.info(service: service, account: "a"))
            #expect(info.service == service && info.account == "a")
            #expect(!info.requiresUserAuthentication)

            await #expect(throws: SecureVaultError.keychainFailure(status: KeychainStatus.duplicateItem)) {
                try await keychain.set(Data(), service: service, account: "a",
                                       options: KeychainWriteOptions(accessibility: .afterFirstUnlock, deviceOnly: true, overwrite: false))
            }
            try await keychain.updateData(Data("three".utf8), service: service, account: "a")
            #expect(try await keychain.get(service: service, account: "a", authentication: AuthenticationContext(reason: "test")) == Data("three".utf8))

            try await keychain.set(Data("b".utf8), service: service, account: "b", options: options)
            #expect(try await keychain.accounts(service: service) == ["a", "b"])
            #expect(try await keychain.services(withPrefix: service) == [service])

            try await keychain.delete(service: service, account: "a")
            try await keychain.delete(service: service, account: "a") // absent: no error
            #expect(try await keychain.info(service: service, account: "a") == nil)
            await #expect(throws: SecureVaultError.itemNotFound) { try await keychain.get(service: service, account: "a", authentication: nil) }
            await #expect(throws: SecureVaultError.itemNotFound) { try await keychain.updateData(Data(), service: service, account: "a") }
        }
    }

    @Test("an item marked as needing authentication is replaced, not updated")
    func replacesAccessControlledItem() async throws {
        try await withService { service in
            try await keychain.set(Data("old".utf8), service: service, account: "a", options: options)
            // Mark the item the way SecureVault marks access-controlled items.
            let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: "a"]
            let status = SecItemUpdate(query as CFDictionary, [kSecAttrGeneric: SystemKeychain.userAuthenticationMarker] as CFDictionary)
            #expect(status == errSecSuccess)
            #expect(try await keychain.info(service: service, account: "a")?.requiresUserAuthentication == true)

            try await keychain.set(Data("new".utf8), service: service, account: "a", options: options)
            #expect(try await keychain.get(service: service, account: "a", authentication: nil) == Data("new".utf8))
            #expect(try await keychain.info(service: service, account: "a")?.requiresUserAuthentication == false)
        }
    }

    @Test("deleting an empty service is not an error")
    func deleteEmpty() async throws {
        try await keychain.deleteAll(service: "securevault.test.empty.\(UUID().uuidString)")
        #expect(try await keychain.services(withPrefix: "securevault.test.none.\(UUID().uuidString)").isEmpty)
    }

    @Test("a cancelled task never reaches the Keychain")
    func cancelled() async {
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await keychain.get(service: "securevault.test.x", account: "x", authentication: nil)
        }
        await #expect(throws: CancellationError.self) { try await task.value }
    }

    @Test("a full vault on the login keychain")
    func vault() async throws {
        let identifier = "securevault.test.vault.\(UUID().uuidString)"
        var configuration = SecureVault.Configuration(
            identifier: identifier,
            directory: FileManager.default.temporaryDirectory.appendingPathComponent(identifier),
            secureEnclave: .never
        )
        configuration.keychain = keychain
        configuration.capabilities = FixedDeviceCapabilities()
        let vault = SecureVault(configuration: configuration)

        try await vault.store("tok", forKey: "accessToken", namespace: .auth, policy: .accessToken)
        try await vault.store(Profile(name: "R", email: "r@x.y", age: 30), forKey: "profile", namespace: .user)
        await vault.lock()
        #expect(try await vault.retrieve(String.self, forKey: "accessToken", namespace: .auth) == "tok")
        let report = try await vault.rotateKeys()
        #expect(report.reencryptedItems == 2, "\(report)")
        try await vault.logout()
        #expect(try await vault.exists(forKey: "accessToken", namespace: .auth) == false)
        try await vault.reset()
        #expect(try await keychain.services(withPrefix: identifier).isEmpty)
    }
}
#endif

@Suite("Keychain attribute mapping")
struct KeychainMappingTests {
    @Test("accessibility maps to the matching kSecAttrAccessible value and back")
    func accessibility() {
        let cases: [(Accessibility, Bool, CFString)] = [
            (.whenUnlocked, true, kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
            (.whenUnlocked, false, kSecAttrAccessibleWhenUnlocked),
            (.afterFirstUnlock, true, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
            (.afterFirstUnlock, false, kSecAttrAccessibleAfterFirstUnlock),
            (.whenPasscodeSet, true, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly),
            (.whenPasscodeSet, false, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly),
        ]
        for (accessibility, deviceOnly, expected) in cases {
            let value = SystemKeychain.accessibleValue(accessibility, deviceOnly: deviceOnly)
            #expect(value == expected)
            let decoded = SystemKeychain.decodeAccessible(value as String)
            #expect(decoded.0 == accessibility)
            #expect(decoded.1 == (accessibility == .whenPasscodeSet ? true : deviceOnly))
        }
        #expect(SystemKeychain.decodeAccessible(nil).0 == nil)
        #expect(SystemKeychain.decodeAccessible("unknown").0 == nil)
    }

    @Test("user authentication becomes a SecAccessControl with the marker", arguments: UserAuthentication.allCases)
    func accessControl(_ authentication: UserAuthentication) throws {
        let attributes = try SystemKeychain.accessAttributes(
            KeychainWriteOptions(accessibility: .whenPasscodeSet, deviceOnly: true, userAuthentication: authentication)
        )
        #expect(attributes[kSecAttrAccessControl] != nil)
        #expect(attributes[kSecAttrGeneric] as? Data == SystemKeychain.userAuthenticationMarker)
    }

    @Test("plain items carry the no-authentication marker")
    func plain() throws {
        let attributes = try SystemKeychain.accessAttributes(KeychainWriteOptions(accessibility: .whenUnlocked, deviceOnly: false))
        #expect(attributes[kSecAttrAccessible] as? String == kSecAttrAccessibleWhenUnlocked as String)
        #expect(attributes[kSecAttrGeneric] as? Data == SystemKeychain.noAuthenticationMarker)
    }

    @Test("OSStatus values map to SecureVault errors")
    func statuses() throws {
        try SystemKeychain.check(errSecSuccess)
        let cases: [(OSStatus, SecureVaultError)] = [
            (errSecItemNotFound, .itemNotFound),
            (errSecUserCanceled, .userCancelled),
            (errSecAuthFailed, .authenticationFailed),
            (errSecInteractionNotAllowed, .protectedDataUnavailable),
            (errSecMissingEntitlement, .accessDenied),
            (errSecNotAvailable, .accessDenied),
            (errSecDuplicateItem, .keychainFailure(status: errSecDuplicateItem)),
            (errSecParam, .keychainFailure(status: errSecParam)),
        ]
        for (status, expected) in cases {
            #expect(throws: expected) { try SystemKeychain.check(status) }
        }
    }
}
