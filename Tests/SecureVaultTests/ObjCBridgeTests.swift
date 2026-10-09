//
//  ObjCBridgeTests.swift
//  SecureVaultTests
//
//  Created by Prakash on 09/10/26.
//

import Foundation
import Testing
@testable import SecureVault

/// Bridges a completion-block API to async for testing.
func callback<T>(_ body: (@escaping @Sendable (T?, NSError?) -> Void) -> Void) async -> (T?, NSError?) {
    await withCheckedContinuation { continuation in
        body { value, error in
            continuation.resume(returning: (SendableBox(value).value, error))
        }
    }
}

func callback(_ body: (@escaping @Sendable (NSError?) -> Void) -> Void) async -> NSError? {
    await withCheckedContinuation { continuation in
        body { error in continuation.resume(returning: error) }
    }
}

extension SVVault {
    static func testing() -> SVVault { inMemoryVaultForTesting() }
}

@Suite("Objective-C bridge (PRD §37)")
struct ObjCBridgeTests {
    @Test("strings, data, numbers and secure-coding objects round-trip")
    func values() async {
        let vault = SVVault.testing()
        #expect(await callback { vault.set("tok", forKey: "t", namespace: "auth", policy: .accessToken, completion: $0) } == nil)
        #expect(await callback { vault.string(forKey: "t", namespace: "auth", completion: $0) }.0 == "tok")

        #expect(await callback { vault.set(Data([9, 8]), forKey: "d", namespace: nil, policy: nil, completion: $0) } == nil)
        #expect(await callback { vault.data(forKey: "d", namespace: nil, completion: $0) }.0 == Data([9, 8]))

        #expect(await callback { vault.set(NSNumber(value: 2.5), forKey: "n", namespace: nil, policy: .preference, completion: $0) } == nil)
        #expect(await callback { vault.number(forKey: "n", namespace: nil, completion: $0) }.0 == NSNumber(value: 2.5))

        let object = ["name": "Asha"] as NSDictionary
        #expect(await callback { vault.set(object, forKey: "o", namespace: "user", policy: nil, completion: $0) } == nil)
        let read = await callback { vault.object(ofClasses: [NSDictionary.self, NSString.self], forKey: "o", namespace: "user", completion: $0) }
        #expect(read.0 as? NSDictionary == object)
    }

    @Test("Swift reads what Objective-C wrote")
    func crossLanguage() async throws {
        let vault = SVVault.testing()
        _ = await callback { vault.set("shared", forKey: "k", namespace: nil, policy: nil, completion: $0) }
        _ = await callback { vault.set(NSNumber(value: 7), forKey: "n", namespace: nil, policy: nil, completion: $0) }
        #expect(try await vault.vault.retrieve(String.self, forKey: "k") == "shared")
        #expect(try await vault.vault.retrieve(Int.self, forKey: "n") == 7)
    }

    @Test("bad input and wrong types report NSError codes")
    func errors() async {
        let vault = SVVault.testing()
        let nan = await callback { vault.set(NSNumber(value: Double.nan), forKey: "n", namespace: nil, policy: nil, completion: $0) }
        #expect(nan?.domain == SVError.domain)
        #expect(nan?.code == SVErrorCode.invalidData.rawValue)

        let missing = await callback { vault.string(forKey: "absent", namespace: nil, completion: $0) }
        #expect(missing.0 == nil)
        #expect(missing.1?.code == SVErrorCode.itemNotFound.rawValue)

        _ = await callback { vault.set("text", forKey: "s", namespace: nil, policy: nil, completion: $0) }
        #expect(await callback { vault.number(forKey: "s", namespace: nil, completion: $0) }.1?.code == SVErrorCode.typeMismatch.rawValue)
        _ = await callback { vault.set(Data([1, 2, 3]), forKey: "raw", namespace: nil, policy: nil, completion: $0) }
        #expect(await callback { vault.object(ofClasses: [NSString.self], forKey: "raw", namespace: nil, completion: $0) }.1?.code == SVErrorCode.typeMismatch.rawValue)

        let violation = SVPolicy.highlySensitive.copy() as! SVPolicy
        violation.deviceOnly = false
        #expect(await callback { vault.set("x", forKey: "v", namespace: nil, policy: violation, completion: $0) }?.code == SVErrorCode.securityPolicyViolation.rawValue)
    }

    @Test("contains, remove, clear, logout, reset, rotate, purge")
    func management() async {
        let vault = SVVault.testing()
        _ = await callback { vault.set("tok", forKey: "t", namespace: "auth", policy: .accessToken, completion: $0) }
        _ = await callback { vault.set("p", forKey: "p", namespace: "user", policy: nil, completion: $0) }
        #expect(await callback { vault.contains(key: "t", namespace: "auth", completion: $0) }.0 == true)
        #expect(await callback { vault.rotateKeys(completion: $0) } == nil)
        #expect(await callback { vault.purgeExpired(completion: $0) } == nil)
        #expect(await callback { vault.logout(completion: $0) } == nil)
        #expect(await callback { vault.contains(key: "t", namespace: "auth", completion: $0) }.0 == false)
        #expect(await callback { vault.remove(key: "p", namespace: "user", completion: $0) } == nil)
        #expect(await callback { vault.contains(key: "p", namespace: "user", completion: $0) }.0 == false)
        _ = await callback { vault.set("q", forKey: "q", namespace: "cache", policy: nil, completion: $0) }
        #expect(await callback { vault.clear(namespace: "cache", completion: $0) } == nil)
        #expect(await callback { vault.reset(completion: $0) } == nil)
        // nil completions are allowed for fire-and-forget calls.
        vault.remove(key: "none", namespace: nil, completion: nil)
    }

    @Test("UserDefaults migration")
    func migration() async throws {
        let suite = "svtest.objc.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set("legacy", forKey: "token")
        let vault = SVVault.testing()
        #expect(await callback { vault.migrateUserDefaultsString("token", suiteName: suite, toKey: "accessToken", namespace: "auth", policy: .accessToken, completion: $0) } == nil)
        #expect(defaults.object(forKey: "token") == nil)
        #expect(try await vault.vault.retrieve(String.self, forKey: "accessToken", namespace: .auth) == "legacy")

        defaults.set(42, forKey: "number")
        let failure = await callback { vault.migrateUserDefaultsString("number", suiteName: suite, toKey: "n", namespace: nil, policy: nil, completion: $0) }
        #expect(failure?.code == SVErrorCode.migrationFailed.rawValue)
    }

    @Test("databases from Objective-C")
    func database() async throws {
        let vault = SVVault.testing()
        let (db, error) = await callback { vault.database(named: "medical", policy: nil, completion: $0) }
        #expect(error == nil)
        let database = try #require(db)
        #expect(database.name == "medical")
        #expect(await callback { database.put(["name": "Bob", "age": 17], id: "p1", type: "Patient", completion: $0) } == nil)
        #expect(await callback { database.put(["name": "Eve"], id: "p2", type: "Patient", completion: $0) } == nil)
        #expect(await callback { database.record(id: "p1", type: "Patient", completion: $0) }.0?["name"] as? String == "Bob")
        let missing = await callback { database.record(id: "nope", type: "Patient", completion: $0) }
        #expect(missing.0 == nil && missing.1 == nil)
        #expect(await callback { database.allRecords(type: "Patient", completion: $0) }.0?.count == 2)
        #expect(await callback { database.count(type: "Patient", completion: $0) }.0 == 2)
        #expect(await callback { database.delete(id: "p1", type: "Patient", completion: $0) } == nil)
        #expect(await callback { database.deleteAll(type: "Patient", completion: $0) } == nil)
        #expect(await callback { database.count(type: "Patient", completion: $0) }.0 == 0)

        let invalid = await callback { database.put(["when": Date()], id: "x", type: "Patient", completion: $0) }
        #expect(invalid?.code == SVErrorCode.invalidData.rawValue)

        #expect(await callback { vault.deleteDatabase(named: "medical", completion: $0) } == nil)
        let rejected = await callback { vault.database(named: "bio", policy: .biometric, completion: $0) }
        #expect(rejected.1?.code == SVErrorCode.securityPolicyViolation.rawValue)
    }

    @Test("files from Objective-C")
    func files() async throws {
        let vault = SVVault.testing()
        let store = vault.fileStore
        let source = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let export = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: source); try? FileManager.default.removeItem(at: export) }
        try Data("streamed".utf8).write(to: source)

        #expect(await callback { store.write(Data("pdf".utf8), named: "a.pdf", namespace: "medical", policy: .highlySensitive, completion: $0) } == nil)
        #expect(await callback { store.write(contentsOf: source, named: "b.bin", namespace: "medical", policy: nil, completion: $0) } == nil)
        #expect(await callback { store.read(named: "a.pdf", namespace: "medical", completion: $0) }.0 == Data("pdf".utf8))
        #expect(await callback { store.export(named: "b.bin", namespace: "medical", to: export, completion: $0) } == nil)
        #expect(try Data(contentsOf: export) == Data("streamed".utf8))
        #expect(await callback { store.list(namespace: "medical", completion: $0) }.0 == ["a.pdf", "b.bin"])
        #expect(await callback { store.delete(named: "a.pdf", namespace: "medical", completion: $0) } == nil)
        #expect(await callback { store.read(named: "a.pdf", namespace: "medical", completion: $0) }.1?.code == SVErrorCode.itemNotFound.rawValue)
    }

    @Test("security report as a dictionary")
    func report() async {
        let (report, error) = await callback { SVVault.testing().securityReport(completion: $0) }
        #expect(error == nil)
        #expect((report?["findings"] as? [Any])?.isEmpty == false)
    }

    @Test("biometrics helpers")
    func biometrics() async {
        _ = SVBiometrics.biometryType
        _ = SVBiometrics.isAvailable
        let ok = await callback { (done: @escaping @Sendable (Bool?, NSError?) -> Void) in
            SVBiometrics.authenticate(reason: "r", using: .stub()) { done($0, $1) }
        }
        #expect(ok.0 == true)
        let cancelled = await callback { (done: @escaping @Sendable (Bool?, NSError?) -> Void) in
            SVBiometrics.authenticate(reason: "r", using: .stub(StubBehaviour(evaluateFailure: .userCancel))) { done($0, $1) }
        }
        #expect(cancelled.0 == false)
        #expect(cancelled.1?.code == SVErrorCode.userCancelled.rawValue)
    }

    @Test("version, shared vault and identifier vaults")
    func misc() {
        #expect(SVVault.sdkVersion == "1.0.1")
        #expect(SVVault.sdkBuild == 2)
        #expect(SVVault.sharedVault.vault === SecureVault.shared)
        #expect(SVVault(identifier: "svtest.objc").vault.configuration.identifier == "svtest.objc")
        #expect(SVError.ns(CancellationError()).code == SVErrorCode.cancelled.rawValue)
    }
}

@Suite("Objective-C policy and enums")
struct ObjCPolicyTests {
    @Test("every preset matches its Swift policy")
    func presets() {
        let pairs: [(SVPolicy, StoragePolicy)] = [
            (.standard, .standard), (.preference, .preference), (.sensitive, .sensitive), (.secret, .secret),
            (.accessToken, .accessToken), (.refreshToken, .refreshToken), (.session, .session),
            (.credential, .credential), (.otp, .otp), (.highlySensitive, .highlySensitive), (.biometric, .biometric),
        ]
        for (objc, swift) in pairs {
            #expect(objc.swiftPolicy == swift)
        }
    }

    @Test("copies are independent and every field converts")
    func copies() {
        let policy = SVPolicy(classification: .secret)
        policy.accessibility = .whenUnlocked
        policy.userAuthentication = .userPresence
        policy.backend = .keychain
        policy.expiresAfter = 60
        policy.requiresDevicePasscode = true
        let copy = policy.copy() as! SVPolicy
        copy.backend = .encryptedFile
        #expect(policy.swiftPolicy.backend == .keychain)
        #expect(copy.swiftPolicy.backend == .encryptedFile)
        #expect(policy.swiftPolicy.expiresAfter == 60)
        policy.expiresAfter = 0
        #expect(policy.swiftPolicy.expiresAfter == nil)
        #expect(SVPolicy(StoragePolicy.sensitive.stored(in: .encryptedFile)).backend == .encryptedFile)
        #expect(SVPolicy(StoragePolicy.sensitive.stored(in: .keychain)).backend == .keychain)
    }

    @Test("enums convert both ways")
    func enums() {
        for value in [SVClassification.standard, .sensitive, .secret, .highlySensitive, .biometricProtected] {
            #expect(value.swift.rawValue == value.rawValue)
        }
        for value in Accessibility.allCases {
            #expect(SVAccessibility(value).swift == value)
        }
        let auth: [UserAuthentication?] = [nil, .userPresence, .biometryAny, .biometryCurrentSet, .devicePasscode]
        for value in auth {
            #expect(SVUserAuthentication(value).swift == value)
        }
        #expect(SVStorageBackend.automatic.swift == .automatic)
        #expect(SVStorageBackend.keychain.swift == .keychain)
        #expect(SVStorageBackend.encryptedFile.swift == .encryptedFile)
        for code in 1...21 {
            #expect(SVErrorCode(rawValue: code) != nil)
        }
    }
}
