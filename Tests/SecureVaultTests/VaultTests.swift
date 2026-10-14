//
//  VaultTests.swift
//  SecureVaultTests
//
//  Created by Prakash on 09/10/26.
//

import Foundation
import Testing
@testable import SecureVault

@Suite("Key-value storage (PRD §11, §21–23, §31)")
struct VaultTests {
    @Test("Codable values round-trip")
    func roundTrip() async throws {
        let h = Harness()
        let profile = Profile(name: "Asha Rao", email: "asha@example.com", age: 41)
        try await h.vault.store(profile, forKey: "profile", namespace: .user)
        try await h.vault.store("tok_123", forKey: "accessToken", namespace: .auth, policy: .accessToken)
        try await h.vault.store(Data([1, 2, 3]), forKey: "blob")
        try await h.vault.store(42, forKey: "answer", policy: .preference)

        #expect(try await h.vault.retrieve(Profile.self, forKey: "profile", namespace: .user) == profile)
        #expect(try await h.vault.retrieve(String.self, forKey: "accessToken", namespace: .auth) == "tok_123")
        #expect(try await h.vault.retrieve(Data.self, forKey: "blob") == Data([1, 2, 3]))
        #expect(try await h.vault.retrieve(Int.self, forKey: "answer") == 42)
    }

    @Test("tokens go to the Keychain, profiles to encrypted files")
    func routing() async throws {
        let h = Harness()
        try await h.vault.store("tok", forKey: "accessToken", namespace: .auth, policy: .accessToken)
        try await h.vault.store(Profile(name: "A", email: "a@b.c", age: 1), forKey: "profile", namespace: .user)

        let tokenOptions = h.keychain.options(service: h.kvService(.auth), account: "accessToken")
        #expect(tokenOptions?.accessibility == .afterFirstUnlock)
        #expect(tokenOptions?.deviceOnly == true)
        #expect(h.keychain.options(service: h.kvService(.user), account: "profile") == nil)
        #expect(await h.vault.objects.exists(namespace: "user", key: "profile"))
    }

    @Test("changing the policy moves the value between backends")
    func moveBetweenBackends() async throws {
        let h = Harness()
        try await h.vault.store("v1", forKey: "k", policy: .secret)
        #expect(h.keychain.options(service: h.kvService(.default), account: "k") != nil)
        try await h.vault.store("v2", forKey: "k", policy: .sensitive)
        #expect(h.keychain.options(service: h.kvService(.default), account: "k") == nil)
        #expect(try await h.vault.retrieve(String.self, forKey: "k") == "v2")
    }

    @Test("no plaintext values or key names reach the disk")
    func noPlaintextOnDisk() async throws {
        let h = Harness()
        try await h.vault.store(Profile(name: "Zebediah Quill", email: "zq@example.com", age: 77), forKey: "medicalHistoryKey", namespace: .medical, policy: .highlySensitive)
        let disk = h.allBytesOnDisk()
        #expect(!disk.isEmpty)
        #expect(!disk.contains("Zebediah"))
        #expect(!disk.contains("zq@example.com"))
        #expect(!disk.contains("medicalHistoryKey"))
    }

    @Test("missing values, value() and exists()")
    func missing() async throws {
        let h = Harness()
        await expectError(.itemNotFound) { try await h.vault.retrieve(String.self, forKey: "nope") }
        #expect(try await h.vault.value(String.self, forKey: "nope") == nil)
        #expect(try await h.vault.exists(forKey: "nope") == false)
        try await h.vault.store("x", forKey: "yes")
        #expect(try await h.vault.exists(forKey: "yes"))
        try await h.vault.delete(forKey: "yes")
        #expect(try await h.vault.exists(forKey: "yes") == false)
    }

    @Test("reading as the wrong type is a typeMismatch")
    func typeMismatch() async throws {
        let h = Harness()
        try await h.vault.store("text", forKey: "k")
        await expectError(.typeMismatch(expected: "Int")) { try await h.vault.retrieve(Int.self, forKey: "k") }
    }

    @Test("tampered Keychain and file values fail closed")
    func tampering() async throws {
        let h = Harness()
        try await h.vault.store("tok", forKey: "t", namespace: .auth, policy: .accessToken)
        h.keychain.tamper(service: h.kvService(.auth), account: "t") { $0[$0.count - 2] ^= 0xFF }
        await expectError(.decryptionFailed) { try await h.vault.retrieve(String.self, forKey: "t", namespace: .auth) }

        try await h.vault.store("p", forKey: "f")
        let file = await h.vault.objects.allFiles().first!.url
        var bytes = try Data(contentsOf: file)
        bytes[bytes.count - 1] ^= 0x01
        try bytes.write(to: file)
        await expectError(.decryptionFailed) { try await h.vault.retrieve(String.self, forKey: "f") }
    }

    @Test("a value copied to another key is rejected")
    func swappedFiles() async throws {
        let h = Harness()
        try await h.vault.store("alice-secret", forKey: "alice")
        try await h.vault.store("bob-secret", forKey: "bob")
        let files = await h.vault.objects.allFiles()
        #expect(files.count == 2)
        let a = try Data(contentsOf: files[0].url)
        try a.write(to: files[1].url)
        var failures = 0
        for key in ["alice", "bob"] {
            do { _ = try await h.vault.retrieve(String.self, forKey: key) } catch SecureVaultError.decryptionFailed { failures += 1 }
        }
        #expect(failures == 1)
    }

    @Test("expiry is enforced and expired values are deleted (PRD §21)")
    func expiry() async throws {
        let h = Harness()
        try await h.vault.store("123456", forKey: "otp", namespace: .session, policy: .otp)
        #expect(try await h.vault.retrieve(String.self, forKey: "otp", namespace: .session) == "123456")
        h.clock.advance(301)
        #expect(try await h.vault.exists(forKey: "otp", namespace: .session) == false)
        await expectError(.expired) { try await h.vault.retrieve(String.self, forKey: "otp", namespace: .session) }
        #expect(h.keychain.options(service: h.kvService(.session), account: "otp") == nil)
        #expect(try await h.vault.value(String.self, forKey: "otp", namespace: .session) == nil)
    }

    @Test("purgeExpired removes only expired items")
    func purgeExpired() async throws {
        let h = Harness()
        try await h.vault.store("a", forKey: "short", policy: .sensitive.expiring(after: 10))
        try await h.vault.store("b", forKey: "long", policy: .sensitive.expiring(after: 1_000))
        try await h.vault.store("c", forKey: "never")
        h.clock.advance(60)
        #expect(try await h.vault.purgeExpired() == 1)
        #expect(try await h.vault.exists(forKey: "long"))
        #expect(try await h.vault.exists(forKey: "never"))
    }

    @Test("namespaces are isolated and logout keeps preferences (PRD §22–23)")
    func logout() async throws {
        let h = Harness()
        try await h.vault.store("tok", forKey: "accessToken", namespace: .auth, policy: .accessToken)
        try await h.vault.store("refresh", forKey: "refreshToken", namespace: .auth, policy: .refreshToken)
        try await h.vault.store("s", forKey: "session", namespace: .session, policy: .session)
        try await h.vault.store("dark", forKey: "theme", namespace: .preferences, policy: .preference)
        try await h.vault.store("same-key-other-ns", forKey: "accessToken", namespace: .user)

        try await h.vault.logout()

        #expect(try await h.vault.exists(forKey: "accessToken", namespace: .auth) == false)
        #expect(try await h.vault.exists(forKey: "refreshToken", namespace: .auth) == false)
        #expect(try await h.vault.exists(forKey: "session", namespace: .session) == false)
        #expect(try await h.vault.retrieve(String.self, forKey: "theme", namespace: .preferences) == "dark")
        #expect(try await h.vault.retrieve(String.self, forKey: "accessToken", namespace: .user) == "same-key-other-ns")
    }

    @Test("per-user namespaces")
    func perUser() async throws {
        let h = Harness()
        try await h.vault.store("a", forKey: "k", namespace: .user(id: "1"))
        try await h.vault.store("b", forKey: "k", namespace: .user(id: "2"))
        try await h.vault.clear(namespace: .user(id: "1"))
        #expect(try await h.vault.value(String.self, forKey: "k", namespace: .user(id: "1")) == nil)
        #expect(try await h.vault.retrieve(String.self, forKey: "k", namespace: .user(id: "2")) == "b")
    }

    @Test("fail closed: no passcode means no highly sensitive storage")
    func failClosed() async throws {
        let h = Harness(capabilities: FixedDeviceCapabilities(passcodeSet: false))
        await expectPolicyViolation { try await h.vault.store("x", forKey: "k", policy: .highlySensitive) }
        #expect(try await h.vault.exists(forKey: "k") == false)
    }

    @Test("biometric items are Keychain items with access control")
    func biometric() async throws {
        let h = Harness()
        try await h.vault.store("pin", forKey: "cardPIN", namespace: .financial, policy: .biometric)
        let options = h.keychain.options(service: h.kvService(.financial), account: "cardPIN")
        #expect(options?.userAuthentication == .biometryCurrentSet)
        #expect(options?.accessibility == .whenPasscodeSet)
        // exists() never prompts and reports true for access-controlled items.
        #expect(try await h.vault.exists(forKey: "cardPIN", namespace: .financial))
    }

    @Test("reinstall wipes Keychain items left by a previous install (PRD §31)")
    func reinstall() async throws {
        let keychain = InMemoryKeychain()
        let first = Harness(keychain: keychain)
        try await first.vault.store("old-token", forKey: "accessToken", namespace: .auth, policy: .accessToken)

        // Simulate uninstall: the directory is gone, the Keychain survives.
        try FileManager.default.removeItem(at: first.directory)
        let second = Harness(keychain: keychain, directory: first.directory)
        #expect(try await second.vault.value(String.self, forKey: "accessToken", namespace: .auth) == nil)
        #expect(try await keychain.services(withPrefix: "test.").isEmpty)
    }

    @Test("an extension sharing the access group does not wipe the app's Keychain items")
    func sharedAccessGroupSkipsReinstallWipe() async throws {
        let keychain = InMemoryKeychain()
        let app = Harness(keychain: keychain)
        try await app.vault.store("token", forKey: "accessToken", namespace: .auth, policy: .accessToken)

        // The extension has its own container, so it never sees the app's install marker.
        var configuration = SecureVault.Configuration.testing(keychain: keychain)
        configuration.keychainAccessGroup = "group.test"
        let extensionVault = SecureVault(configuration: configuration)
        #expect(try await extensionVault.value(String.self, forKey: "accessToken", namespace: .auth) == "token")
        #expect(try await app.vault.retrieve(String.self, forKey: "accessToken", namespace: .auth) == "token")
    }

    @Test("restore without device-only keys: keyUnavailable, then explicit purge")
    func restoreToNewDevice() async throws {
        let h = Harness()
        try await h.vault.store("device-only", forKey: "a", policy: .sensitive)
        try await h.vault.store("portable", forKey: "b", policy: .standard)
        // The new device has the backed-up files and portable keys, but not device-only keys.
        for account in try await h.keychain.accounts(service: "test.keys") where account.contains(".local") {
            try await h.keychain.delete(service: "test.keys", account: account)
        }
        await h.vault.lock()
        await expectError(.keyUnavailable) { try await h.vault.retrieve(String.self, forKey: "a") }
        #expect(try await h.vault.retrieve(String.self, forKey: "b") == "portable")
        #expect(try await h.vault.purgeUnreadableItems() == 1)
        #expect(try await h.vault.exists(forKey: "a") == false)
    }

    @Test("reset crypto-shreds everything")
    func reset() async throws {
        let h = Harness()
        try await h.vault.store("x", forKey: "a", namespace: .auth, policy: .accessToken)
        try await h.vault.store("y", forKey: "b")
        try await h.vault.reset()
        #expect(try await h.keychain.services(withPrefix: "test.").isEmpty)
        #expect(try await h.vault.exists(forKey: "a", namespace: .auth) == false)
        try await h.vault.store("z", forKey: "c")
        #expect(try await h.vault.retrieve(String.self, forKey: "c") == "z")
    }

    @Test("Secure Enclave-style wrapping stores no raw device-only keys")
    func wrappedKeys() async throws {
        let h = Harness(protector: SoftwareKeyProtector())
        try await h.vault.store("tok", forKey: "t", namespace: .auth, policy: .accessToken)
        try await h.vault.store("pref", forKey: "p", policy: .standard)
        let local = try await h.keychain.get(service: "test.keys", account: "kv|afu.local|v1", authentication: nil)
        let portable = try await h.keychain.get(service: "test.keys", account: "kv|afu.portable|v1", authentication: nil)
        #expect(local.first == 0x01)     // wrapped
        #expect(portable.first == 0x00)  // portable keys are never wrapped
        await h.vault.lock()
        #expect(try await h.vault.retrieve(String.self, forKey: "t", namespace: .auth) == "tok")
    }

    @Test("version and build")
    func version() {
        #expect(SecureVault.version == "1.0.2")
        #expect(SecureVault.build == 3)
    }

    @Test("errors bridge to NSError with stable codes")
    func nsError() {
        let error = SecureVaultError.expired as NSError
        #expect(error.domain == "com.securevault.error")
        #expect(error.code == 15)
        #expect(SecureVaultError.cancelled.code == 21)
    }

    @Test("security report flags the in-memory Keychain and never includes values")
    func report() async throws {
        let h = Harness(capabilities: FixedDeviceCapabilities(passcodeSet: false))
        try await h.vault.store("super-secret-value", forKey: "very-private-key", policy: .standard)
        let report = await h.vault.securityReport()
        let codes = report.findings.map(\.code)
        #expect(codes.contains("keychain.in-memory"))
        #expect(codes.contains("device.no-passcode"))
        #expect(report.highestSeverity == .critical)
        let json = try JSONEncoder().encode(report)
        #expect(!json.contains("super-secret-value"))
        #expect(!json.contains("very-private-key"))
    }
}
