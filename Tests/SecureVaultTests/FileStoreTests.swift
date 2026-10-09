//
//  FileStoreTests.swift
//  SecureVaultTests
//
//  Created by Prakash on 09/10/26.
//

import Foundation
import Testing
@testable import SecureVault

@Suite("Protected files (PRD §19)")
struct FileStoreTests {
    func bytes(_ count: Int) -> Data { Data((0..<count).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 7) }) }

    @Test("small, empty, exact-chunk and multi-chunk files round-trip", arguments: [0, 10, 65_536, 200_000])
    func roundTrip(size: Int) async throws {
        let h = Harness()
        let data = bytes(size)
        try await h.vault.files.write(data, named: "report.pdf", namespace: .medical, policy: .highlySensitive)
        #expect(try await h.vault.files.read(named: "report.pdf", namespace: .medical) == data)
    }

    @Test("streams from and to URLs")
    func streaming() async throws {
        let h = Harness()
        let source = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let destination = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: source); try? FileManager.default.removeItem(at: destination) }
        let data = bytes(300_000)
        try data.write(to: source)
        try await h.vault.files.write(contentsOf: source, named: "scan.jpg")
        try await h.vault.files.export(named: "scan.jpg", to: destination)
        #expect(try Data(contentsOf: destination) == data)
    }

    @Test("names and contents are not on disk; list() still works")
    func noPlaintext() async throws {
        let h = Harness()
        try await h.vault.files.write(Data("Quarterly Statement Body".utf8), named: "statement-2026.pdf", namespace: .financial)
        let disk = h.allBytesOnDisk()
        #expect(!disk.contains("Quarterly Statement"))
        #expect(!disk.contains("statement-2026"))
        let listed = try await h.vault.files.list(namespace: .financial)
        #expect(listed.map(\.name) == ["statement-2026.pdf"])
        #expect(listed.first?.size == 24)
    }

    func storedFile(_ h: Harness) -> URL {
        let enumerator = FileManager.default.enumerator(at: h.vault.files.root, includingPropertiesForKeys: nil)!
        return (enumerator.allObjects as! [URL]).first { $0.pathExtension == "svf" }!
    }

    @Test("a flipped bit in a chunk fails")
    func tamper() async throws {
        let h = Harness()
        try await h.vault.files.write(bytes(150_000), named: "f")
        let url = storedFile(h)
        var data = try Data(contentsOf: url)
        data[data.count - 70_000] ^= 0x01
        try data.write(to: url)
        await expectError(.decryptionFailed) { try await h.vault.files.read(named: "f") }
    }

    @Test("truncation at a chunk boundary fails")
    func truncation() async throws {
        let h = Harness()
        try await h.vault.files.write(bytes(200_000), named: "f")
        let url = storedFile(h)
        let data = try Data(contentsOf: url)
        let lastChunk = (200_000 % 65_536) + 16
        try data.prefix(data.count - lastChunk).write(to: url)
        await expectError(.decryptionFailed) { try await h.vault.files.read(named: "f") }
    }

    @Test("biometric files are rejected in V1")
    func biometricRejected() async {
        let h = Harness()
        await expectPolicyViolation { try await h.vault.files.write(Data(), named: "x", policy: .biometric) }
    }

    @Test("rotation re-encrypts files")
    func rotate() async throws {
        let h = Harness()
        let data = bytes(100_000)
        try await h.vault.files.write(data, named: "a")
        try await h.vault.files.write(Data("b".utf8), named: "b", namespace: .user)
        let report = try await h.vault.rotateKeys()
        #expect(report.reencryptedFiles == 2)
        await h.vault.lock()
        #expect(try await h.vault.files.read(named: "a") == data)
        let families = try await h.vault.keys.allKeyIDs().filter { $0.key.purpose == "files" }
        #expect(families.values.allSatisfy { $0 == [2] })
    }

    @Test("clearing a namespace removes its files only")
    func clear() async throws {
        let h = Harness()
        try await h.vault.files.write(Data("1".utf8), named: "a", namespace: .cache)
        try await h.vault.files.write(Data("2".utf8), named: "b", namespace: .user)
        try await h.vault.logout()
        #expect(await h.vault.files.exists(named: "a", namespace: .cache) == false)
        #expect(await h.vault.files.exists(named: "b", namespace: .user))
    }
}

@Suite("Lifecycle ordering")
struct LifecycleOrderingTests {
    @Test("using files before any other vault call does not lose the file key")
    func filesFirst() async throws {
        let h = Harness()
        try await h.vault.files.write(Data("first".utf8), named: "a")
        try await h.vault.store("x", forKey: "k")
        await h.vault.lock()
        #expect(try await h.vault.files.read(named: "a") == Data("first".utf8))
    }
}
