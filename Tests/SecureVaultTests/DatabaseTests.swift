//
//  DatabaseTests.swift
//  SecureVaultTests
//
//  Created by Prakash on 09/10/26.
//

import Foundation
import Testing
@testable import SecureVault

@Suite("Secure database (PRD §17–18)")
struct DatabaseTests {
    let alice = Patient(id: UUID(), name: "Alice Kumari", diagnosis: "Hypertension", age: 52)
    let bob = Patient(id: UUID(), name: "Bob Menon", diagnosis: "Asthma", age: 17)

    @Test("insert, get, all, filter, count, delete")
    func crud() async throws {
        let h = Harness()
        let db = try await h.vault.database("medical", policy: .highlySensitive)
        try await db.insert(alice)
        try await db.insert(contentsOf: [bob])
        #expect(try await db.get(Patient.self, id: alice.id) == alice)
        #expect(try await db.count(Patient.self) == 2)
        #expect(try await db.all(Patient.self) { $0.age >= 18 } == [alice])

        var updated = alice
        updated.diagnosis = "Controlled"
        try await db.insert(updated)
        #expect(try await db.get(Patient.self, id: alice.id)?.diagnosis == "Controlled")
        #expect(try await db.count(Patient.self) == 2)

        try await db.delete(Patient.self, id: bob.id)
        #expect(try await db.get(Patient.self, id: bob.id) == nil)
        try await db.deleteAll(Patient.self)
        #expect(try await db.count(Patient.self) == 0)
    }

    @Test("the database file holds no names, ids or contents")
    func noPlaintext() async throws {
        let h = Harness()
        let db = try await h.vault.database("medical")
        try await db.insert(alice)
        await db.close()
        let disk = h.allBytesOnDisk()
        #expect(!disk.contains("Alice Kumari"))
        #expect(!disk.contains("Hypertension"))
        #expect(!disk.contains(alice.id.uuidString))
        #expect(!disk.contains("Patient"))
        #expect(!disk.contains("medical"))
    }

    @Test("data survives close and reopen")
    func persistence() async throws {
        let h = Harness()
        try await h.vault.database("medical").insert(alice)
        await h.vault.lock()
        #expect(try await h.vault.database("medical").get(Patient.self, id: alice.id) == alice)
    }

    @Test("rotation re-encrypts every record in one transaction")
    func rotate() async throws {
        let h = Harness()
        let db = try await h.vault.database("medical")
        try await db.insert(contentsOf: [alice, bob])
        #expect(try await db.rotateKey() == 2)
        #expect(await db.currentKeyVersion == 2)
        await db.close()
        #expect(try await db.get(Patient.self, id: alice.id) == alice)
        #expect(try await db.count(Patient.self) == 2)
        let purpose = db.keyPurpose
        let families = try await h.vault.keys.allKeyIDs().filter { $0.key.purpose == purpose }
        #expect(families.values.allSatisfy { $0 == [2] })
    }

    @Test("an orphaned key from an interrupted rotation is cleaned up on open")
    func orphanCleanup() async throws {
        let h = Harness()
        let db = try await h.vault.database("medical")
        try await db.insert(alice)
        let id = KeyID(purpose: db.keyPurpose, domain: KeyDomain(accessibility: .whenUnlocked, deviceOnly: true))
        _ = try await h.vault.keys.rotate(id) // crashed before the transaction committed
        await db.close()
        #expect(try await db.get(Patient.self, id: alice.id) == alice)
        #expect(try await h.vault.keys.versions(for: id) == [1])
    }

    @Test("records written from Objective-C JSON are readable as Swift types")
    func untyped() async throws {
        let h = Harness()
        let db = try await h.vault.database("medical")
        let json = try JSONEncoder().encode(alice)
        try await db.putData(json, id: alice.id.uuidString, type: "Patient")
        #expect(try await db.get(Patient.self, id: alice.id) == alice)
    }

    @Test("biometric databases are rejected in V1")
    func biometricRejected() async {
        let h = Harness()
        await expectPolicyViolation { try await h.vault.database("x", policy: .biometric) }
    }

    @Test("deleteDatabase removes the file and its keys")
    func deleteDatabase() async throws {
        let h = Harness()
        let db = try await h.vault.database("medical")
        try await db.insert(alice)
        let purpose = db.keyPurpose
        try await h.vault.deleteDatabase("medical")
        #expect(!FileManager.default.fileExists(atPath: db.fileURL.path))
        #expect(try await h.vault.keys.allKeyIDs().keys.allSatisfy { $0.purpose != purpose })
        #expect(try await h.vault.database("medical").count(Patient.self) == 0)
    }
}
