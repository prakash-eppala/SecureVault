//
//  EdgeCaseTests.swift
//  SecureVaultTests
//
//  Created by Prakash on 09/10/26.
//

import CryptoKit
import Foundation
import Testing
@testable import SecureVault
@testable import SecureVaultCore
@testable import SecureVaultCrypto
@testable import SecureVaultDatabase
@testable import SecureVaultFiles
@testable import SecureVaultKeychain

/// A Keychain double that can misbehave in specific ways.
final class FaultyKeychain: KeychainBackend, @unchecked Sendable {
    enum Mode {
        /// Accepts writes but stores nothing.
        case dropWrites
        /// Keeps the first value written to an item and ignores later writes.
        case keepFirstWrite
        /// Before an add-only write (to `account`, or to any account when nil), stores `winner`
        /// as if another process got there first.
        case loseAddRace(winner: Data, account: String? = nil)
    }

    let inner = InMemoryKeychain()
    let mode: Mode
    init(_ mode: Mode) { self.mode = mode }

    func set(_ data: Data, service: String, account: String, options: KeychainWriteOptions) async throws {
        switch mode {
        case .dropWrites:
            return
        case .keepFirstWrite:
            if try await inner.info(service: service, account: account) != nil { return }
            try await inner.set(data, service: service, account: account, options: options)
        case .loseAddRace(let winner, let target):
            if !options.overwrite, target == nil || target == account,
               try await inner.info(service: service, account: account) == nil {
                try await inner.set(winner, service: service, account: account, options: options)
            }
            try await inner.set(data, service: service, account: account, options: options)
        }
    }
    func updateData(_ data: Data, service: String, account: String) async throws { try await inner.updateData(data, service: service, account: account) }
    func get(service: String, account: String, authentication: AuthenticationContext?) async throws -> Data { try await inner.get(service: service, account: account, authentication: authentication) }
    func info(service: String, account: String) async throws -> KeychainItemInfo? { try await inner.info(service: service, account: account) }
    func delete(service: String, account: String) async throws { try await inner.delete(service: service, account: account) }
    func deleteAll(service: String) async throws { try await inner.deleteAll(service: service) }
    func accounts(service: String) async throws -> [String] { try await inner.accounts(service: service) }
    func services(withPrefix prefix: String) async throws -> [String] { try await inner.services(withPrefix: prefix) }
}

final class Fired: @unchecked Sendable {
    private let lock = NSLock()
    private var flag = false
    var value: Bool { lock.lock(); defer { lock.unlock() }; return flag }
    func set() { lock.lock(); flag = true; lock.unlock() }
}

func temporaryURL(_ name: String = UUID().uuidString) -> URL {
    FileManager.default.temporaryDirectory.appendingPathComponent("svedge-\(name)")
}

/// A path whose parent is a regular file, so nothing can be created under it.
func blockedDirectory() throws -> URL {
    let file = temporaryURL()
    try Data("not a directory".utf8).write(to: file)
    return file.appendingPathComponent("vault", isDirectory: true)
}

func vault(keychain: any KeychainBackend, directory: URL = temporaryURL(), capabilities: FixedDeviceCapabilities = FixedDeviceCapabilities(),
           logging: Bool = false, secureEnclave: SecureEnclaveUsage = .never, protector: (any KeyProtector)? = nil) -> SecureVault {
    var configuration = SecureVault.Configuration(identifier: "test", directory: directory, secureEnclave: secureEnclave, loggingEnabled: logging)
    configuration.keychain = keychain
    configuration.capabilities = capabilities
    configuration.keyProtector = protector
    return SecureVault(configuration: configuration)
}

final class Insecure: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { false }
    override init() {}
    required init?(coder: NSCoder) {}
    func encode(with coder: NSCoder) {}
}

struct Unencodable: Codable, Sendable {
    var value = Double.nan
}

@Suite("Fixes found in the documentation audit")
struct AuditFixTests {
    @Test("reinstall and reset never touch Keychain items SecureVault does not own")
    func foreignItemsSurvive() async throws {
        let keychain = InMemoryKeychain()
        let options = KeychainWriteOptions(accessibility: .afterFirstUnlock, deviceOnly: false)
        try await keychain.set(Data("legacy".utf8), service: "test.legacy", account: "token", options: options)
        try await keychain.set(Data("other".utf8), service: "test.keysmith", account: "x", options: options)
        try await keychain.set(Data("stale".utf8), service: "test.kv.auth", account: "old", options: options)

        let first = vault(keychain: keychain)
        _ = try await first.exists(forKey: "anything") // runs the reinstall check
        #expect(try await keychain.info(service: "test.kv.auth", account: "old") == nil)
        #expect(try await keychain.info(service: "test.legacy", account: "token") != nil)

        try await first.store("v", forKey: "k", policy: .secret)
        try await first.reset()
        #expect(try await keychain.services(withPrefix: "test.") == ["test.keysmith", "test.legacy"])
    }

    @Test("protected files enforce a required Secure Enclave")
    func filesRequireSecureEnclave() async {
        let required = vault(keychain: InMemoryKeychain(), capabilities: FixedDeviceCapabilities(secureEnclave: false), secureEnclave: .required)
        await expectPolicyViolation { try await required.files.write(Data("x".utf8), named: "f") }
        await expectPolicyViolation { try await required.store("x", forKey: "k") }
    }

    @Test("each database lives in its own folder")
    func databaseFolders() async throws {
        let h = Harness()
        let medical = try await h.vault.database("medical")
        let ledger = try await h.vault.database("ledger", policy: .sensitive)
        try await medical.insert(Patient(id: UUID(), name: "A", diagnosis: "B", age: 1))
        _ = try await ledger.count(type: "x")
        let folders = [medical.fileURL.deletingLastPathComponent(), ledger.fileURL.deletingLastPathComponent()]
        #expect(folders[0] != folders[1])
        #expect(folders.allSatisfy { FileManager.default.fileExists(atPath: $0.path) })
        try await h.vault.deleteDatabase("medical")
        #expect(!FileManager.default.fileExists(atPath: folders[0].path))
        #expect(FileManager.default.fileExists(atPath: folders[1].path))
    }

    @Test("logs show built-in namespaces but hash custom ones")
    func logRedaction() {
        #expect(VaultLog.builtInNamespaces.contains("auth"))
        #expect(!VaultLog.builtInNamespaces.contains("user.42"))
        #expect(VaultLog.hash("user.42").count == 12)
        #expect(VaultLog.hash("user.42") != "user.42")
    }

    @Test("a reordered chunk fails authentication")
    func reorderedChunks() async throws {
        let h = Harness()
        let data = Data((0..<(3 * 65_536)).map { UInt8(truncatingIfNeeded: $0 &* 7) })
        try await h.vault.files.write(data, named: "f")
        let url = try #require(FileManager.default.enumerator(at: h.vault.files.root, includingPropertiesForKeys: nil)?
            .allObjects.compactMap { $0 as? URL }.first { $0.pathExtension == "svf" })
        var bytes = try Data(contentsOf: url)
        let block = 65_536 + 16
        let start = bytes.count - 3 * block
        let first = bytes[start..<start + block]
        let second = bytes[start + block..<start + 2 * block]
        bytes.replaceSubrange(start..<start + 2 * block, with: second + first)
        try bytes.write(to: url)
        await expectError(.decryptionFailed) { try await h.vault.files.read(named: "f") }
    }
}

@Suite("Edge cases: vault, lifecycle and migration")
struct VaultEdgeTests {
    @Test("an unusable directory fails setup, and setup retries")
    func setupFailure() async throws {
        let blocked = vault(keychain: InMemoryKeychain(), directory: try blockedDirectory())
        await expectError(.fileFailure(reason: "vault directory")) { try await blocked.store("x", forKey: "k") }
        await expectError(.fileFailure(reason: "vault directory")) { try await blocked.store("x", forKey: "k") }
    }

    @Test("reset reports a directory that cannot be removed")
    func resetFailure() async throws {
        let parent = temporaryURL()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        let locked = vault(keychain: InMemoryKeychain(), directory: parent.appendingPathComponent("vault"))
        try await locked.store("x", forKey: "k")
        try FileManager.default.setAttributes([.posixPermissions: 0o555], ofItemAtPath: parent.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: parent.path) }
        await expectError(.fileFailure(reason: "reset")) { try await locked.reset() }
    }

    @Test("device lock closes only databases that need an unlocked device")
    func deviceLock() async throws {
        let h = Harness()
        let medical = try await h.vault.database("medical", policy: .highlySensitive)
        let cache = try await h.vault.database("cache", policy: .sensitive)
        try await medical.insert(Patient(id: UUID(), name: "A", diagnosis: "B", age: 1))
        try await cache.insert(Patient(id: UUID(), name: "C", diagnosis: "D", age: 2))
        try await h.vault.store("x", forKey: "k", policy: .highlySensitive)
        await SecureVault.handleDeviceLock(keys: h.vault.keys, lifecycle: h.vault.lifecycle)
        #expect(await medical.currentKeyVersion == nil) // closed
        #expect(await cache.currentKeyVersion == 1)     // still open for background work
        #expect(try await h.vault.retrieve(String.self, forKey: "k") == "x")
        #expect(try await medical.count(Patient.self) == 1) // reopens on demand
    }

    @Test("the lock observer calls back on its notification")
    func lockObserver() async throws {
        let name = Notification.Name("svtest.lock.\(UUID().uuidString)")
        let fired = Fired()
        let observer = ProtectedDataObserver(name: name) { fired.set() }
        NotificationCenter.default.post(name: name, object: nil)
        #expect(fired.value)
        _ = observer
    }

    @Test("values that do not encode, and empty keys, are invalid")
    func invalidValues() async {
        let h = Harness()
        await expectError(.invalidData(reason: "value does not encode as JSON")) { try await h.vault.store(Unencodable(), forKey: "k") }
        await expectError(.invalidData(reason: "key must not be empty")) { try await h.vault.store("x", forKey: "") }
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await h.vault.retrieve(String.self, forKey: "k")
        }
        await expectError(.cancelled) { try await task.value }
    }

    @Test("exists() treats an expired Keychain item as absent")
    func expiredKeychainItem() async throws {
        let h = Harness()
        try await h.vault.store("t", forKey: "t", policy: .accessToken.expiring(after: 5))
        h.clock.advance(10)
        #expect(try await h.vault.exists(forKey: "t") == false)
    }

    @Test("rotation includes listed and open databases; deleting an unopened database works")
    func rotationWithDatabases() async throws {
        let h = Harness()
        try await h.vault.database("medical").insert(Patient(id: UUID(), name: "A", diagnosis: "B", age: 1))
        let report = try await h.vault.rotateKeys(databases: ["medical", "ledger"])
        #expect(report.reencryptedRecords == 1)
        let fresh = vault(keychain: h.keychain, directory: h.directory)
        try await fresh.deleteDatabase("medical")
        #expect(try await fresh.database("medical").count(Patient.self) == 0)
    }

    @Test("logging on runs the redacting logger, including the reinstall warning")
    func logging() async throws {
        let keychain = InMemoryKeychain()
        try await keychain.set(Data(), service: "test.kv.auth", account: "stale", options: KeychainWriteOptions(accessibility: .afterFirstUnlock, deviceOnly: true))
        let logged = vault(keychain: keychain, logging: true)
        try await logged.store("x", forKey: "k", namespace: .user(id: "42"))
        _ = try await logged.retrieve(String.self, forKey: "k", namespace: .user(id: "42"))
        try await logged.delete(forKey: "k", namespace: .user(id: "42"))
        #expect(logged.log.isEnabled)
    }

    @Test("the default configuration and a database policy change")
    func configurationDefaults() async throws {
        let configuration = SecureVault.Configuration()
        #expect(configuration.secureEnclave == .whenAvailable)
        #expect(configuration.sessionNamespaces == [.auth, .session, .cache])
        #expect(!configuration.loggingEnabled)
        #expect(configuration.clock().timeIntervalSinceNow < 1)

        let h = Harness()
        try await h.vault.database("medical", policy: .highlySensitive).insert(Patient(id: UUID(), name: "A", diagnosis: "B", age: 1))
        let reopened = vault(keychain: h.keychain, directory: h.directory, logging: true)
        #expect(try await reopened.database("medical", policy: .sensitive).count(Patient.self) == 1)
    }

    @Test("migration: plist data, Keychain data and text, absent and broken sources")
    func migrationBranches() async throws {
        let suite = "svtest.edge.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(try PropertyListEncoder().encode(Profile(name: "P", email: "e", age: 5)), forKey: "plist")

        let legacy = InMemoryKeychain()
        let options = KeychainWriteOptions(accessibility: .afterFirstUnlock, deviceOnly: false)
        try await legacy.set(Data([0, 1, 2]), service: "legacy", account: "bytes", options: options)
        try await legacy.set(Data([0xFF, 0xFE]), service: "legacy", account: "badtext", options: options)

        let h = Harness()
        let report = await h.vault.migrate([
            .userDefaults("plist", suiteName: suite, as: Profile.self, to: "profile", policy: .sensitive),
            .keychain(service: "legacy", account: "bytes", as: .data, to: "bytes", policy: .secret, source: legacy),
            .keychain(service: "legacy", account: "missing", to: "missing", policy: .secret, source: legacy),
            .keychain(service: "legacy", account: "badtext", as: .string, to: "bad", policy: .secret, source: legacy),
        ])
        #expect(report.migrated.count == 2)
        #expect(report.skipped.count == 1)
        #expect(report.failed.map(\.error) == [.migrationFailed(reason: "Keychain item is not UTF-8 text")])
        #expect(try await h.vault.retrieve(Profile.self, forKey: "profile").age == 5)
        #expect(try await h.vault.retrieve(Data.self, forKey: "bytes") == Data([0, 1, 2]))
    }

    @Test("migration: biometric targets are checked by presence; lost or stale copies fail")
    func migrationVerification() async throws {
        let suite = "svtest.verify.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set("pin", forKey: "pin")

        let ok = await Harness().vault.migrate([.userDefaults("pin", suiteName: suite, as: String.self, to: "pin", policy: .biometric)])
        #expect(ok.migrated.count == 1)

        defaults.set("pin", forKey: "pin")
        let dropping = vault(keychain: FaultyKeychain(.dropWrites))
        let lost = await dropping.migrate([.userDefaults("pin", suiteName: suite, as: String.self, to: "pin", policy: .biometric)])
        #expect(lost.failed.map(\.error) == [.migrationFailed(reason: "stored copy not found")])

        let stale = vault(keychain: FaultyKeychain(.keepFirstWrite))
        try await stale.store("old-token", forKey: "token", policy: .secret)
        defaults.set("new-token", forKey: "token")
        let mismatch = await stale.migrate([.userDefaults("token", suiteName: suite, as: String.self, to: "token", policy: .secret)])
        #expect(mismatch.failed.map(\.error) == [.migrationFailed(reason: "stored copy does not match the source")])
        #expect(defaults.string(forKey: "token") == "new-token")
    }

    @Test("Objective-C rejects objects that do not support secure coding")
    func insecureObject() async {
        let error = await callback { SVVault.testing().set(Insecure(), forKey: "o", namespace: nil, policy: nil, completion: $0) }
        #expect(error?.code == SVErrorCode.invalidData.rawValue)
    }
}

@Suite("Edge cases: core types")
struct CoreEdgeTests {
    @Test("every error has a stable code and a description")
    func errors() {
        let all: [SecureVaultError] = [
            .itemNotFound, .invalidData(reason: "r"), .typeMismatch(expected: "T"), .encryptionFailed, .decryptionFailed,
            .keyUnavailable, .keyRotationFailed(reason: "r"), .authenticationRequired, .authenticationFailed, .userCancelled,
            .biometryNotAvailable, .biometryLockout, .accessDenied, .protectedDataUnavailable, .expired,
            .migrationFailed(reason: "r"), .databaseFailure(reason: "r"), .fileFailure(reason: "r"),
            .securityPolicyViolation(reason: "r"), .keychainFailure(status: -1), .cancelled,
        ]
        #expect(all.map(\.code) == Array(1...21))
        for error in all {
            #expect(error.errorDescription?.isEmpty == false)
            #expect((error as NSError).localizedDescription == error.errorDescription)
            #expect(error.errorCode == error.code)
        }
        #expect(SecureVaultError.wrap(SecureVaultError.expired) == .expired)
        #expect(SecureVaultError.wrap(CancellationError()) == .cancelled)
        struct Unrelated: Error {}
        #expect(SecureVaultError.wrap(Unrelated()) == .invalidData(reason: "Unrelated"))
    }

    @Test("policy modifiers, initialisers and descriptions")
    func policies() {
        let custom = StoragePolicy(classification: .secret, accessibility: .whenUnlocked, deviceOnly: false, userAuthentication: nil,
                                   backend: .encryptedFile, expiresAfter: 10, requiresDevicePasscode: true)
        #expect(custom.backend == .encryptedFile && custom.expiresAfter == 10 && custom.requiresDevicePasscode)
        #expect(StoragePolicy.standard.deviceOnly().deviceOnly)
        #expect(!StoragePolicy.sensitive.deviceOnly(false).deviceOnly)
        #expect(StoragePolicy.sensitive.requiringDevicePasscode().requiresDevicePasscode)
        #expect(KeyDomain(accessibility: .whenUnlocked, deviceOnly: true).description == "wu.local")
        #expect(KeyDomain(id: "bad") == nil)
        #expect(KeyDomain(id: "xx.local") == nil)
        #expect(VaultNamespace("ns").description == "ns")
        #expect(FileProtectionLevel.complete.attribute == .complete)
        #expect(FileProtectionLevel.completeUntilFirstUserAuthentication.attribute == .completeUntilFirstUserAuthentication)
        #expect(DataClassification.standard < .secret)
    }

    @Test("remaining policy rules")
    func rules() async throws {
        var automaticWithAuth = StoragePolicy.secret
        automaticWithAuth.userAuthentication = .devicePasscode
        automaticWithAuth.backend = .automatic
        #expect(try PolicyEngine.resolve(automaticWithAuth, payloadSize: 10, capabilities: FixedDeviceCapabilities()).backend == .keychain)
        await expectPolicyViolation {
            try PolicyEngine.resolve(automaticWithAuth, payloadSize: 10, capabilities: FixedDeviceCapabilities(passcodeSet: false))
        }
        let portablePasscode = StoragePolicy(classification: .secret, accessibility: .whenPasscodeSet, deviceOnly: false)
        await expectPolicyViolation { try PolicyEngine.resolve(portablePasscode, payloadSize: 10, capabilities: FixedDeviceCapabilities()) }
    }

    @Test("malformed envelopes are rejected precisely")
    func envelopes() throws {
        let key = SymmetricKey(size: .bits256)
        let crypto = AESGCMProvider()
        let header = EnvelopeHeader(algorithm: "A256GCM", keyPurpose: "kv", keyDomain: "afu.local", keyVersion: 1, createdAt: Date(), expiresAt: nil)
        let sealed = try Envelope.seal(Data("x".utf8), header: header, key: key, context: Data(), crypto: crypto)

        var badVersion = sealed; badVersion[3] = 9
        #expect(throws: SecureVaultError.invalidData(reason: "unsupported envelope format 9")) { try Envelope.peekHeader(badVersion) }
        var truncated = sealed; truncated[4] = 0x7F
        #expect(throws: SecureVaultError.invalidData(reason: "truncated envelope")) { try Envelope.peekHeader(truncated) }
        var garbled = sealed; garbled[8] = UInt8(ascii: "#")
        #expect(throws: SecureVaultError.invalidData(reason: "unreadable envelope header")) { try Envelope.peekHeader(garbled) }

        var foreign = header; foreign.algorithm = "XYZ"
        let foreignSealed = try Envelope.seal(Data("x".utf8), header: foreign, key: key, context: Data(), crypto: crypto)
        #expect(throws: SecureVaultError.invalidData(reason: "unsupported algorithm XYZ")) {
            try Envelope.open(foreignSealed, key: key, context: Data(), crypto: crypto)
        }
        var unencodable = header; unencodable.createdAt = Date(timeIntervalSince1970: .nan)
        #expect(throws: SecureVaultError.encryptionFailed) { try Envelope.seal(Data(), header: unencodable, key: key, context: Data(), crypto: crypto) }
        #expect(header.keyID?.description == "kv|afu.local")
    }

    @Test("key manager: formats, cache, races and the protection key")
    func keyManager() async throws {
        let keychain = InMemoryKeychain()
        let keys = KeyManager(vaultID: "km", keychain: keychain, protector: nil)
        #expect(await keys.keyService == "km.keys")
        let id = KeyID(purpose: "kv", domain: KeyDomain(accessibility: .whenUnlocked, deviceOnly: true))
        let options = KeychainWriteOptions(accessibility: .whenUnlocked, deviceOnly: true)

        try await keychain.set(Data([0x07, 1]), service: "km.keys", account: "kv|wu.local|v1", options: options)
        await #expect(throws: SecureVaultError.invalidData(reason: "unknown key format")) { try await keys.key(for: id, version: 1) }
        try await keychain.set(Data([0x00, 1, 2]), service: "km.keys", account: "kv|wu.local|v1", options: options)
        await #expect(throws: SecureVaultError.invalidData(reason: "bad key length")) { try await keys.key(for: id, version: 1) }
        try await keychain.set(Data([0x01, 1, 2]), service: "km.keys", account: "kv|wu.local|v1", options: options)
        await #expect(throws: SecureVaultError.keyUnavailable) { try await keys.key(for: id, version: 1) }
        try await keychain.set(Data(), service: "km.keys", account: "kv|wu.local|v1", options: options)
        await #expect(throws: SecureVaultError.keyUnavailable) { try await keys.key(for: id, version: 1) }
        try await keys.destroyAll(id)

        let afu = KeyID(purpose: "kv", domain: KeyDomain(accessibility: .afterFirstUnlock, deviceOnly: true))
        _ = try await keys.currentKey(for: id)
        _ = try await keys.currentKey(for: afu)
        await keys.clearCache(onlyWhenUnlockedDomains: true)
        try await keychain.deleteAll(service: "km.keys")
        _ = try await keys.key(for: afu, version: 1) // still cached
        await #expect(throws: SecureVaultError.keyUnavailable) { try await keys.key(for: id, version: 1) }
    }

    @Test("an add-only key write that loses a race adopts the winner's key")
    func keyRace() async throws {
        let winner = Data([0x00] + Array(repeating: UInt8(7), count: 32))
        let keychain = FaultyKeychain(.loseAddRace(winner: winner))
        let keys = KeyManager(vaultID: "race", keychain: keychain, protector: nil)
        let id = KeyID(purpose: "kv", domain: KeyDomain(accessibility: .afterFirstUnlock, deviceOnly: true))
        let (version, key) = try await keys.currentKey(for: id)
        #expect(version == 1)
        #expect(key.withUnsafeBytes { Data($0) } == Data(repeating: 7, count: 32))
    }

    @Test("the protection key is created once, reused, and survives a creation race")
    func protectionKey() async throws {
        let keychain = InMemoryKeychain()
        let id = KeyID(purpose: "kv", domain: KeyDomain(accessibility: .afterFirstUnlock, deviceOnly: true))
        let first = KeyManager(vaultID: "pk", keychain: keychain, protector: SoftwareKeyProtector())
        let key = try await first.currentKey(for: id).key
        let second = KeyManager(vaultID: "pk", keychain: keychain, protector: SoftwareKeyProtector())
        #expect(try await second.key(for: id, version: 1) == key)
        #expect(await second.usesKeyProtector)

        let racing = FaultyKeychain(.loseAddRace(winner: try SoftwareKeyProtector().makeProtectionKey(), account: "kek|secure-enclave"))
        let raced = KeyManager(vaultID: "pk", keychain: racing, protector: SoftwareKeyProtector())
        _ = try await raced.currentKey(for: id)
        #expect(try await raced.key(for: id, version: 1) == (try await raced.currentKey(for: id).key))
    }

    @Test("object store helpers and error mapping")
    func objectStore() async throws {
        let store = EncryptedObjectStore(root: temporaryURL(), vaultID: "v")
        try await store.write(Data("a".utf8), namespace: "n", key: "k", protection: .complete, excludeFromBackup: true)
        #expect(await store.count(namespace: "n") == 1)
        #expect(await store.count(namespace: "empty") == 0)
        try await store.deleteNamespace("missing")
        try await store.deleteAll()
        try await store.deleteAll()
        #expect(await store.count() == 0)

        let blocked = EncryptedObjectStore(root: try blockedDirectory(), vaultID: "v")
        await #expect(throws: SecureVaultError.self) {
            try await blocked.write(Data(), namespace: "n", key: "k", protection: .completeUntilFirstUserAuthentication, excludeFromBackup: false)
        }
        await #expect(throws: SecureVaultError.self) { try await store.replace(at: temporaryURL().appendingPathComponent("x/y"), with: Data()) }
        await #expect(throws: SecureVaultError.self) { try await store.removeFile(at: temporaryURL()) }

        #expect(EncryptedObjectStore.map(NSError(domain: NSPOSIXErrorDomain, code: Int(EPERM))) == .protectedDataUnavailable)
        #expect(EncryptedObjectStore.map(NSError(domain: NSPOSIXErrorDomain, code: Int(EACCES))) == .protectedDataUnavailable)
        #expect(EncryptedObjectStore.map(NSError(domain: NSCocoaErrorDomain, code: NSFileWriteNoPermissionError)) == .protectedDataUnavailable)
        #expect(EncryptedObjectStore.map(NSError(domain: NSCocoaErrorDomain, code: NSFileReadNoSuchFileError)) == .itemNotFound)
        #expect(EncryptedObjectStore.map(NSError(domain: "x", code: 3)) == .fileFailure(reason: "x 3"))
        #expect(EncryptedObjectStore.data(fromHex: "zz") == nil)
        #expect(EncryptedObjectStore.data(fromHex: String(repeating: "g", count: 64)) == nil)
    }

    @Test("security report findings and identifiers")
    func reports() {
        let everything = SecurityReportBuilder.build(SecurityReportInput(
            now: Date(), capabilities: FixedDeviceCapabilities(passcodeSet: true, biometryAvailable: false, secureEnclave: true),
            keychainIsEphemeral: false, secureEnclaveInUse: false,
            keyVersions: [KeyID(purpose: "db.abc", domain: KeyDomain(accessibility: .whenUnlocked, deviceOnly: true)): [1, 2]],
            storedObjectFiles: 3, loggingEnabled: true
        ))
        #expect(Set(everything.findings.map(\.id)) == ["device.no-biometry", "keys.secure-enclave-off", "keys.rotation-pending", "logging.enabled"])
        #expect(everything.keys.first?.purpose == "db")
        #expect(everything.highestSeverity == .warning)

        let clean = SecurityReportBuilder.build(SecurityReportInput(
            now: Date(), capabilities: FixedDeviceCapabilities(secureEnclave: true), keychainIsEphemeral: false,
            secureEnclaveInUse: true, keyVersions: [:], storedObjectFiles: 0, loggingEnabled: false
        ))
        #expect(clean.findings.isEmpty)
        #expect(clean.highestSeverity == nil)
    }

    @Test("Secure Enclave protector, where the hardware allows it")
    func secureEnclave() throws {
        let protector = SecureEnclaveKeyProtector()
        #expect(protector.identifier == "se-p256-ecies-v1")
        #expect(SoftwareKeyProtector().identifier == "sw-p256-ecies-v1")
        #expect(throws: SecureVaultError.keyUnavailable) { try protector.wrap(Data(), protectionKey: Data([1, 2, 3]), context: Data()) }
        #expect(throws: SecureVaultError.keyUnavailable) { try protector.unwrap(Data(), protectionKey: Data([1, 2, 3]), context: Data()) }
        #expect(throws: SecureVaultError.self) { try SoftwareKeyProtector().unwrap(Data([1]), protectionKey: try SoftwareKeyProtector().makeProtectionKey(), context: Data()) }

        guard SecureEnclaveKeyProtector.isAvailable else { return }
        do {
            let handle = try protector.makeProtectionKey()
            let raw = Data(repeating: 9, count: 32)
            let wrapped = try protector.wrap(raw, protectionKey: handle, context: Data("ctx".utf8))
            #expect(try protector.unwrap(wrapped, protectionKey: handle, context: Data("ctx".utf8)) == raw)
        } catch SecureVaultError.securityPolicyViolation {
            // The Secure Enclave refuses keys to unsigned test processes on some Macs.
        }
    }

    @Test("in-memory Keychain refuses an add-only overwrite")
    func inMemoryDuplicate() async throws {
        let keychain = InMemoryKeychain()
        let options = KeychainWriteOptions(accessibility: .afterFirstUnlock, deviceOnly: true, overwrite: false)
        try await keychain.set(Data(), service: "s", account: "a", options: options)
        await #expect(throws: SecureVaultError.keychainFailure(status: KeychainStatus.duplicateItem)) {
            try await keychain.set(Data(), service: "s", account: "a", options: options)
        }
    }
}

@Suite("Edge cases: SQLite and databases")
struct DatabaseEdgeTests {
    @Test("SQLite open, statement, binding and transaction failures")
    func sqlite() throws {
        let folder = temporaryURL()
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        #expect(throws: SecureVaultError.self) { try SQLiteConnection(path: folder.path) }

        let connection = try SQLiteConnection(path: folder.appendingPathComponent("t.sqlite").path)
        try connection.execute("CREATE TABLE t (a TEXT, b INTEGER)")
        try connection.execute("INSERT INTO t VALUES (?, ?)", [.text("x"), .int(5)])
        #expect(try connection.query("SELECT a, b FROM t").first?.map { String(decoding: $0, as: UTF8.self) } == ["x", "5"])
        #expect(throws: SecureVaultError.self) { try connection.execute("NOT SQL") }
        #expect(throws: SecureVaultError.self) { try connection.execute("SELECT ?", [.int(1), .int(2)]) }
        #expect(throws: SecureVaultError.self) {
            try connection.transaction { try connection.execute("INSERT INTO t VALUES ('y', 1)"); try connection.execute("BROKEN") }
        }
        #expect(try connection.query("SELECT COUNT(*) FROM t").first?.first.map { String(decoding: $0, as: UTF8.self) } == "1")
        connection.close()
        #expect(throws: SecureVaultError.self) { try connection.execute("SELECT 1") }
    }

    @Test("a corrupted record makes rotation fail without losing the old key")
    func rotationFailure() async throws {
        let h = Harness()
        let db = try await h.vault.database("medical")
        let patient = Patient(id: UUID(), name: "A", diagnosis: "B", age: 1)
        try await db.insert(patient)
        await db.close()
        let raw = try SQLiteConnection(path: db.fileURL.path)
        try raw.execute("UPDATE records SET payload = ?", [.blob(Data("garbage".utf8))])
        raw.close()
        await #expect(throws: SecureVaultError.self) { try await db.rotateKey() }
        let id = KeyID(purpose: db.keyPurpose, domain: KeyDomain(accessibility: .whenUnlocked, deviceOnly: true))
        #expect(try await h.vault.keys.versions(for: id) == [1])
    }

    @Test("an unusable database directory fails to open")
    func directoryFailure() async throws {
        let blocked = try blockedDirectory()
        let db = SecureDatabase(name: "x", directory: blocked, domain: KeyDomain(accessibility: .whenUnlocked, deviceOnly: true),
                                keys: KeyManager(vaultID: "d", keychain: InMemoryKeychain(), protector: nil), crypto: AESGCMProvider(),
                                log: VaultLog(enabled: false), now: { Date() })
        await expectError(.fileFailure(reason: "database directory")) { try await db.count(type: "t") }
    }
}

@Suite("Edge cases: protected files")
struct FileEdgeTests {
    func storedFile(_ h: Harness) throws -> URL {
        try #require(FileManager.default.enumerator(at: h.vault.files.root, includingPropertiesForKeys: nil)?
            .allObjects.compactMap { $0 as? URL }.first { $0.pathExtension == "svf" })
    }

    @Test("export failures remove partial output")
    func export() async throws {
        let h = Harness()
        try await h.vault.files.write(Data(repeating: 1, count: 100), named: "f")
        await expectError(.fileFailure(reason: "destination unwritable")) {
            try await h.vault.files.export(named: "f", to: temporaryURL().appendingPathComponent("missing/out"))
        }
        let url = try storedFile(h)
        var bytes = try Data(contentsOf: url)
        bytes[bytes.count - 1] ^= 1
        try bytes.write(to: url)
        let destination = temporaryURL()
        await expectError(.decryptionFailed) { try await h.vault.files.export(named: "f", to: destination) }
        #expect(!FileManager.default.fileExists(atPath: destination.path))
    }

    @Test("bad sources, headers and metadata are rejected")
    func malformed() async throws {
        let h = Harness()
        await expectError(.fileFailure(reason: "source unreadable")) { try await h.vault.files.write(contentsOf: temporaryURL(), named: "x") }
        await expectError(.itemNotFound) { try await h.vault.files.read(named: "absent") }

        try await h.vault.files.write(Data("abc".utf8), named: "f")
        let url = try storedFile(h)
        let original = try Data(contentsOf: url)

        var wrongMagic = original; wrongMagic[0] = UInt8(ascii: "X")
        try wrongMagic.write(to: url)
        await expectError(.invalidData(reason: "not a SecureVault file")) { try await h.vault.files.read(named: "f") }

        var badHeader = original; badHeader[8] = UInt8(ascii: "#")
        try badHeader.write(to: url)
        await expectError(.invalidData(reason: "file header")) { try await h.vault.files.read(named: "f") }

        let headerLength = original[4..<8].reduce(0) { ($0 << 8) | Int($1) }
        var badMetadata = original; badMetadata[8 + headerLength + 4] ^= 1
        try badMetadata.write(to: url)
        await expectError(.decryptionFailed) { try await h.vault.files.read(named: "f") }
        await #expect(throws: SecureVaultError.decryptionFailed) { try await h.vault.files.list() }
    }

    @Test("clearAll, count and purging files whose key is gone")
    func housekeeping() async throws {
        let h = Harness()
        try await h.vault.files.write(Data("a".utf8), named: "a", policy: .sensitive)
        try await h.vault.files.write(Data("b".utf8), named: "b", policy: .standard)
        #expect(await h.vault.files.count() == 2)
        for account in try await h.keychain.accounts(service: "test.keys") where account.hasPrefix("files|afu.local") {
            try await h.keychain.delete(service: "test.keys", account: account)
        }
        await h.vault.lock()
        #expect(try await h.vault.purgeUnreadableItems() == 1)
        #expect(await h.vault.files.count() == 1)
        try await h.vault.files.clearAll()
        try await h.vault.files.clearAll()
        try await h.vault.files.clear(namespace: .cache)
        try await h.vault.files.delete(named: "nothing")
        #expect(await h.vault.files.count() == 0)
    }

    @Test("an unwritable folder fails writes and rotation; a cancelled write leaves nothing")
    func writeFailures() async throws {
        let h = Harness()
        try await h.vault.files.write(Data("a".utf8), named: "a")
        let folder = try storedFile(h).deletingLastPathComponent()
        try FileManager.default.setAttributes([.posixPermissions: 0o555], ofItemAtPath: folder.path)
        await expectError(.fileFailure(reason: "temporary file")) { try await h.vault.files.write(Data("b".utf8), named: "b") }
        await #expect(throws: SecureVaultError.fileFailure(reason: "temporary file")) { try await h.vault.files.rotateKeys() }
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: folder.path)

        let blocked = SecureVault(configuration: .testing(directory: temporaryURL()))
        try await blocked.files.write(Data("x".utf8), named: "x")
        try FileManager.default.removeItem(at: blocked.files.root)
        try Data("file in the way".utf8).write(to: blocked.files.root)
        await expectError(.fileFailure(reason: "write")) { try await blocked.files.write(Data("y".utf8), named: "y") }

        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            try await h.vault.files.write(Data(repeating: 1, count: 200_000), named: "big")
        }
        await expectError(.cancelled) { try await task.value }
        #expect(await h.vault.files.exists(named: "big") == false)
    }
}

/// A crypto provider whose sealing always fails.
struct FailingCrypto: CryptoProvider {
    var algorithm: String { "A256GCM" }
    struct Failure: Error {}
    func seal(_ plaintext: Data, using key: SymmetricKey, authenticating aad: Data) throws -> Data { throw Failure() }
    func open(_ sealed: Data, using key: SymmetricKey, authenticating aad: Data) throws -> Data { throw Failure() }
}

@Suite("Edge cases: last branches")
struct LastBranchTests {
    @Test("a sealing failure is reported as encryptionFailed")
    func sealingFailure() {
        let header = EnvelopeHeader(algorithm: "A256GCM", keyPurpose: "kv", keyDomain: "afu.local", keyVersion: 1, createdAt: Date(), expiresAt: nil)
        #expect(throws: SecureVaultError.encryptionFailed) {
            try Envelope.seal(Data(), header: header, key: SymmetricKey(size: .bits256), context: Data(), crypto: FailingCrypto())
        }
    }

    @Test("SQLite permission errors mean the device is locked")
    func sqlitePermissions() {
        #expect(SQLiteConnection.error(23 /* SQLITE_AUTH */, nil) == .protectedDataUnavailable)
        #expect(SQLiteConnection.error(3 /* SQLITE_PERM */, nil) == .protectedDataUnavailable)
        #expect(SQLiteConnection.error(1, nil) == .databaseFailure(reason: "sqlite 1: unknown"))
    }

    @Test("authentic file metadata that is not valid JSON is rejected")
    func forgedMetadata() async throws {
        let h = Harness()
        try await h.vault.files.write(Data("abc".utf8), named: "f")
        let url = try #require(FileManager.default.enumerator(at: h.vault.files.root, includingPropertiesForKeys: nil)?
            .allObjects.compactMap { $0 as? URL }.first { $0.pathExtension == "svf" })
        let original = try Data(contentsOf: url)
        let headerLength = original[4..<8].reduce(0) { ($0 << 8) | Int($1) }
        let prefix = original.prefix(8 + headerLength)
        let metadataLength = original[8 + headerLength..<12 + headerLength].reduce(0) { ($0 << 8) | Int($1) }
        let chunks = original.suffix(from: 12 + headerLength + metadataLength)

        struct Header: Decodable { let kd: String; let kv: Int; let salt: Data }
        let header = try JSONDecoder().decode(Header.self, from: original[8..<8 + headerLength])
        let domain = try #require(KeyDomain(id: header.kd))
        let dataKey = try await h.vault.keys.key(for: KeyID(purpose: "files", domain: domain), version: header.kv)
        let context = EncryptedObjectStore.data(fromHex: url.deletingPathExtension().lastPathComponent)!
        let forged = try AESGCMProvider().seal(Data("not json".utf8),
                                               using: StreamCipher.metadataKey(dataKey: dataKey, salt: header.salt),
                                               authenticating: Data(SHA256.hash(data: prefix + context)))
        var length = UInt32(forged.count).bigEndian
        try (prefix + Data(bytes: &length, count: 4) + forged + chunks).write(to: url)
        await expectError(.invalidData(reason: "file metadata")) { try await h.vault.files.read(named: "f") }
    }
}

#if canImport(AppKit)
import AppKit
import SwiftUI

@MainActor
final class PhaseBox: ObservableObject {
    @Published var phase: ScenePhase = .active
}

@MainActor
struct PhaseHost: View {
    @ObservedObject var box: PhaseBox
    let log: RenderLog

    var body: some View {
        BiometricGate(reason: "r", authenticator: .stub()) {
            Text("content").onAppear { log.values.append("content") }
        } locked: { unlock, error in
            log.lockedErrors.append(error)
            return BiometricLockedView(unlock: unlock, error: error)
        }
        .environment(\.scenePhase, box.phase)
    }
}

@MainActor
@Suite("Edge cases: SwiftUI lifecycle")
struct GateLifecycleTests {
    @Test("the gate locks again when the app moves to the background")
    func relocks() async {
        let box = PhaseBox()
        let log = RenderLog()
        let hosting = host(PhaseHost(box: box, log: log))
        await waitUntil(hosting) { log.values.contains("content") }
        let lockedBefore = log.lockedErrors.count
        box.phase = .background
        await waitUntil(hosting) { log.lockedErrors.count > lockedBefore }
        #expect(log.lockedErrors.count > lockedBefore)
    }
}
#endif
