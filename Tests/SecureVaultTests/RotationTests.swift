//
//  RotationTests.swift
//  SecureVaultTests
//
//  Created by Prakash on 09/10/26.
//

import Foundation
import Testing
@testable import SecureVault

@Suite("Key rotation (PRD §16)")
struct RotationTests {
    @Test("rotation re-encrypts items and retires old keys")
    func rotate() async throws {
        let h = Harness()
        try await h.vault.store("tok", forKey: "t", namespace: .auth, policy: .accessToken)
        try await h.vault.store(Profile(name: "A", email: "a@b.c", age: 3), forKey: "p", namespace: .user, policy: .standard)

        let report = try await h.vault.rotateKeys()
        #expect(report.reencryptedItems == 2)
        #expect(report.isComplete)
        #expect(report.retiredKeyVersions == 2)

        let accounts = try await h.keychain.accounts(service: "test.keys")
        #expect(accounts.allSatisfy { $0.hasSuffix("|v2") })
        await h.vault.lock()
        #expect(try await h.vault.retrieve(String.self, forKey: "t", namespace: .auth) == "tok")
        #expect(try await h.vault.retrieve(Profile.self, forKey: "p", namespace: .user).name == "A")
    }

    @Test("an interrupted rotation loses nothing and can be completed")
    func interrupted() async throws {
        let h = Harness()
        for index in 0..<5 { try await h.vault.store("v\(index)", forKey: "k\(index)") }
        // Crash simulation: a new key version exists but no item was re-encrypted yet.
        let id = KeyID(purpose: "kv", domain: KeyDomain(accessibility: .afterFirstUnlock, deviceOnly: true))
        _ = try await h.vault.keys.rotate(id)
        // New writes use v2 while old items are still on v1, so everything stays readable.
        try await h.vault.store("new", forKey: "fresh")
        for index in 0..<5 { #expect(try await h.vault.retrieve(String.self, forKey: "k\(index)") == "v\(index)") }

        let report = try await h.vault.completePendingRotations()
        #expect(report.reencryptedItems == 5)
        #expect(try await h.vault.keys.versions(for: id) == [2])
        for index in 0..<5 { #expect(try await h.vault.retrieve(String.self, forKey: "k\(index)") == "v\(index)") }
        #expect(try await h.vault.retrieve(String.self, forKey: "fresh") == "new")
    }

    @Test("items needing authentication are skipped and their old key retained")
    func skipsBiometric() async throws {
        let h = Harness()
        try await h.vault.store("pin", forKey: "pin", policy: .biometric)
        let report = try await h.vault.rotateKeys()
        #expect(report.skippedItems == 1)
        #expect(!report.isComplete)
        let id = KeyID(purpose: "kv", domain: KeyDomain(accessibility: .whenPasscodeSet, deviceOnly: true))
        #expect(try await h.vault.keys.versions(for: id) == [1, 2])
    }

    @Test("concurrent first use creates exactly one key")
    func concurrentKeyCreation() async throws {
        let h = Harness()
        try await withThrowingTaskGroup(of: Void.self) { group in
            for index in 0..<50 {
                group.addTask { try await h.vault.store("v\(index)", forKey: "k\(index)") }
            }
            try await group.waitForAll()
        }
        #expect(try await h.keychain.accounts(service: "test.keys") == ["kv|afu.local|v1"])
        for index in 0..<50 { #expect(try await h.vault.retrieve(String.self, forKey: "k\(index)") == "v\(index)") }
    }
}

@Suite("Concurrency (PRD §27)")
struct ConcurrencyTests {
    @Test("hundreds of parallel reads and writes")
    func parallel() async throws {
        let h = Harness()
        try await withThrowingTaskGroup(of: Void.self) { group in
            for index in 0..<200 {
                group.addTask {
                    let policy: StoragePolicy = index.isMultiple(of: 2) ? .accessToken : .sensitive
                    try await h.vault.store(index, forKey: "k\(index % 40)", namespace: .cache, policy: policy)
                    _ = try await h.vault.value(Int.self, forKey: "k\(index % 40)", namespace: .cache)
                }
            }
            try await group.waitForAll()
        }
        for key in 0..<40 {
            let value = try await h.vault.retrieve(Int.self, forKey: "k\(key)", namespace: .cache)
            #expect(value % 40 == key)
        }
    }

    @Test("a cancelled task does not write")
    func cancellation() async throws {
        let h = Harness()
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            try await h.vault.store("x", forKey: "cancelled")
        }
        await expectError(.cancelled) { try await task.value }
        #expect(try await h.vault.exists(forKey: "cancelled") == false)
    }
}
