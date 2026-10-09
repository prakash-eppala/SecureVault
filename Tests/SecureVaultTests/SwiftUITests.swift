//
//  SwiftUITests.swift
//  SecureVaultTests
//
//  Created by Prakash on 09/10/26.
//

#if canImport(AppKit)
import AppKit
import SwiftUI
import Testing
@testable import SecureVault

/// Records what a hosted view rendered, so tests can wait for asynchronous loads.
@MainActor
final class RenderLog {
    var values: [String?] = []
    var model: SecureValue<String>?
    var setter: ((String?) -> Void)?
    var unlock: (() -> Void)?
    var lockedErrors: [SecureVaultError?] = []
}

@MainActor
struct StorageProbe: View {
    @SecureStorage("name", namespace: .user, policy: .sensitive) var name: String?
    let log: RenderLog

    var body: some View {
        log.values.append(name)
        log.model = $name
        log.setter = { name = $0 }
        return Text(name ?? "none")
    }
}

@MainActor
func host<V: View>(_ view: V) -> NSHostingView<V> {
    let hosting = NSHostingView(rootView: view)
    hosting.frame = NSRect(x: 0, y: 0, width: 320, height: 480)
    hosting.layoutSubtreeIfNeeded()
    return hosting
}

/// Pumps layout until `condition` holds or two seconds pass.
@MainActor
func waitUntil(_ hosting: NSView, _ condition: () -> Bool) async {
    for _ in 0..<200 where !condition() {
        hosting.layoutSubtreeIfNeeded()
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
}

@MainActor
@Suite("SwiftUI (PRD §38)")
struct SwiftUITests {
    @Test("SecureValue loads, stores, binds and deletes")
    func secureValue() async throws {
        let vault = SecureVault(configuration: .testing())
        try await vault.store("Asha", forKey: "name")
        let model = SecureValue<String>("name", vault: vault)
        #expect(model.key == "name" && model.namespace == .default && model.policy == .sensitive)
        await model.load()
        #expect(model.value == "Asha")
        #expect(!model.isLoading)

        await model.set("Ravi")
        #expect(try await vault.retrieve(String.self, forKey: "name") == "Ravi")

        model.binding.wrappedValue = "Mira"
        await waitUntil(NSView()) { model.value == "Mira" }
        try await Task.sleep(nanoseconds: 50_000_000)
        #expect(try await vault.retrieve(String.self, forKey: "name") == "Mira")
        #expect(model.binding.wrappedValue == "Mira")

        await model.delete()
        #expect(model.value == nil)
        #expect(try await vault.exists(forKey: "name") == false)
    }

    @Test("SecureValue reports errors and restores the previous value")
    func secureValueErrors() async throws {
        let vault = SecureVault(configuration: .testing(capabilities: FixedDeviceCapabilities(passcodeSet: false)))
        try await vault.store(42, forKey: "n")
        let wrongType = SecureValue<String>("n", vault: vault)
        await wrongType.load()
        #expect(wrongType.error == .typeMismatch(expected: "String"))

        let strict = SecureValue<String>("k", policy: .highlySensitive, vault: vault)
        await strict.set("x")
        #expect(strict.value == nil)
        if case .securityPolicyViolation = strict.error {} else { Issue.record("expected a policy violation") }
    }

    @Test("SecureValue without a vault does nothing until attached")
    func attach() async throws {
        let vault = SecureVault(configuration: .testing())
        try await vault.store("v", forKey: "k")
        let model = SecureValue<String>("k")
        await model.load()
        await model.set("ignored")
        #expect(model.vault == nil)
        model.attach(vault)
        model.attach(SecureVault(configuration: .testing())) // the first vault wins; loads once
        #expect(model.vault === vault)
        await waitUntil(NSView()) { model.value == "v" }
        #expect(model.value == "v")
    }

    @Test("@SecureStorage loads from the environment vault and writes back")
    func propertyWrapper() async throws {
        let vault = SecureVault(configuration: .testing())
        try await vault.store("Asha", forKey: "name", namespace: .user)
        let log = RenderLog()
        let hosting = host(StorageProbe(log: log).secureVault(vault))
        await waitUntil(hosting) { log.values.last == "Asha" }
        #expect(log.values.last == "Asha")
        #expect(log.model?.isLoading == false)

        log.setter?("Ravi")
        await waitUntil(hosting) { log.values.last == "Ravi" }
        try await Task.sleep(nanoseconds: 50_000_000)
        #expect(try await vault.retrieve(String.self, forKey: "name", namespace: .user) == "Ravi")
    }

    @Test("the default environment vault is the shared vault")
    func environmentDefault() {
        #expect(EnvironmentValues().secureVault === SecureVault.shared)
        var values = EnvironmentValues()
        let vault = SecureVault(configuration: .testing())
        values.secureVault = vault
        #expect(values.secureVault === vault)
    }

    @Test("BiometricGate shows content after a successful prompt")
    func gateUnlocks() async {
        let log = RenderLog()
        let gate = BiometricGate(reason: "Unlock", authenticator: .stub()) {
            Text("secret content").onAppear { log.values.append("content") }
        }
        let hosting = host(gate)
        await waitUntil(hosting) { log.values.contains("content") }
        #expect(log.values.contains("content"))
    }

    @Test("BiometricGate stays locked on failure and retries from the unlock action")
    func gateStaysLocked() async {
        let log = RenderLog()
        let gate = BiometricGate(reason: "Unlock", authenticator: .stub(StubBehaviour(evaluateFailure: .authenticationFailed))) {
            Text("secret")
        } locked: { unlock, error in
            log.unlock = unlock
            log.lockedErrors.append(error)
            return BiometricLockedView(unlock: unlock, error: error)
        }
        let hosting = host(gate)
        await waitUntil(hosting) { log.lockedErrors.contains(.authenticationFailed) }
        #expect(log.lockedErrors.contains(.authenticationFailed))
        log.unlock?()
        try? await Task.sleep(nanoseconds: 100_000_000)
        hosting.layoutSubtreeIfNeeded()
        #expect(log.lockedErrors.last == .authenticationFailed)
    }

    @Test("gate without auto-prompt, the locked view and the modifier render")
    func rendering() async {
        let manual = host(BiometricGate(reason: "r", authenticateOnAppear: false, authenticator: .stub()) { Text("x") })
        manual.layoutSubtreeIfNeeded()
        _ = host(BiometricLockedView(unlock: {}, error: .biometryLockout))
        _ = host(BiometricLockedView(unlock: {}, error: .userCancelled))
        _ = host(BiometricLockedView(unlock: {}, error: nil))
        let log = RenderLog()
        let modified = host(Text("guarded").onAppear { log.values.append("guarded") }
            .biometricLock(reason: "r", authenticator: .stub()))
        await waitUntil(modified) { log.values.contains("guarded") }
        #expect(log.values.contains("guarded"))
    }
}
#endif
