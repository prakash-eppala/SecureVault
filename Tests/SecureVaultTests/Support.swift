//
//  Support.swift
//  SecureVaultTests
//
//  Created by Prakash on 09/10/26.
//

import Foundation
import Testing
@testable import SecureVault

/// A clock tests can move forward.
final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var current = Date(timeIntervalSince1970: 1_800_000_000)
    var now: Date { lock.lock(); defer { lock.unlock() }; return current }
    func advance(_ seconds: TimeInterval) { lock.lock(); current += seconds; lock.unlock() }
}

struct Harness {
    let vault: SecureVault
    let keychain: InMemoryKeychain
    let clock: TestClock
    let directory: URL

    init(capabilities: FixedDeviceCapabilities = FixedDeviceCapabilities(), protector: (any KeyProtector)? = nil, keychain: InMemoryKeychain = InMemoryKeychain(), directory: URL? = nil) {
        let clock = TestClock()
        let directory = directory ?? FileManager.default.temporaryDirectory.appendingPathComponent("svtest-\(UUID().uuidString)")
        var configuration = SecureVault.Configuration.testing(directory: directory, capabilities: capabilities, keychain: keychain)
        configuration.keyProtector = protector
        configuration.clock = { clock.now }
        self.vault = SecureVault(configuration: configuration)
        self.keychain = keychain
        self.clock = clock
        self.directory = directory
    }

    /// Every file under the vault directory, concatenated. Used to prove no plaintext reaches the disk.
    func allBytesOnDisk() -> Data {
        var bytes = Data()
        let enumerator = FileManager.default.enumerator(at: directory, includingPropertiesForKeys: nil)
        while let url = enumerator?.nextObject() as? URL {
            if let data = try? Data(contentsOf: url) { bytes.append(data) }
        }
        return bytes
    }

    func kvService(_ namespace: VaultNamespace) -> String { "test.kv.\(namespace.rawValue)" }
}

struct Profile: Codable, Sendable, Equatable {
    var name: String
    var email: String
    var age: Int
}

struct Patient: SecureRecord, Equatable {
    let id: UUID
    var name: String
    var diagnosis: String
    var age: Int
}

func expectError<T>(_ expected: SecureVaultError, _ body: () async throws -> T, sourceLocation: SourceLocation = #_sourceLocation) async {
    do {
        _ = try await body()
        Issue.record("expected \(expected), got success", sourceLocation: sourceLocation)
    } catch let error as SecureVaultError {
        #expect(error == expected, sourceLocation: sourceLocation)
    } catch {
        Issue.record("expected \(expected), got \(error)", sourceLocation: sourceLocation)
    }
}

func expectPolicyViolation<T>(_ body: () async throws -> T, sourceLocation: SourceLocation = #_sourceLocation) async {
    do {
        _ = try await body()
        Issue.record("expected a policy violation, got success", sourceLocation: sourceLocation)
    } catch SecureVaultError.securityPolicyViolation {
        // expected
    } catch {
        Issue.record("expected a policy violation, got \(error)", sourceLocation: sourceLocation)
    }
}

extension Data {
    func contains(_ needle: String) -> Bool { range(of: Data(needle.utf8)) != nil }
}
