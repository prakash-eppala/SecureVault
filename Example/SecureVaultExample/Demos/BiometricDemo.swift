//
//  BiometricDemo.swift
//  SecureVaultExample
//
//  Created by Prakash on 09/10/26.
//

import SecureVault
import SwiftUI

/// A PIN that can only be read after Face ID, Touch ID or Optic ID.
struct BiometricDemo: View {
    @Environment(\.secureVault) private var vault
    @State private var log = DemoLog()
    private let authenticator = BiometricAuthenticator()

    var body: some View {
        Form {
            Section("This device") {
                LabeledContent("Biometry", value: authenticator.biometryKind.rawValue)
                LabeledContent("Available", value: authenticator.isBiometryAvailable ? "Yes" : "No")
                LabeledContent("Passcode fallback", value: authenticator.canAuthenticate(allowingPasscodeFallback: true) ? "Yes" : "No")
            }
            Section {
                Text("On the Simulator, choose Features > Face ID > Enrolled first, then Matching Face when asked.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            Section("PIN (.biometric)") {
                ActionRow("Store PIN", systemImage: "lock.shield", log: log) {
                    try await vault.store("4821", forKey: "cardPIN", namespace: .financial, policy: .biometric)
                    return "Keychain item that needs biometry from the current enrollment"
                }
                ActionRow("Read PIN (system prompt)", systemImage: "faceid", log: log) {
                    let pin = try await vault.retrieve(String.self, forKey: "cardPIN", namespace: .financial)
                    return "PIN \(pin)"
                }
                ActionRow("Prompt once, read twice", systemImage: "rectangle.stack.badge.person.crop", log: log) {
                    let context = try await authenticator.authenticate(reason: "Show your card PIN", reuseDuration: 10)
                    let first = try await vault.retrieve(String.self, forKey: "cardPIN", namespace: .financial, authentication: context)
                    let second = try await vault.retrieve(String.self, forKey: "cardPIN", namespace: .financial, authentication: context)
                    return "Read \(first) and \(second) with one prompt"
                }
                ActionRow("Exists? (never prompts)", systemImage: "questionmark.circle", log: log) {
                    try await vault.exists(forKey: "cardPIN", namespace: .financial) ? "Yes" : "No"
                }
                ActionRow("Delete PIN", systemImage: "trash", log: log) {
                    try await vault.delete(forKey: "cardPIN", namespace: .financial)
                    return "Deleted"
                }
            }
            Section("Enrollment") {
                ActionRow("Enrollment fingerprint", systemImage: "touchid", log: log) {
                    authenticator.enrollmentFingerprint.map { $0.prefix(8).map { String(format: "%02x", $0) }.joined() } ?? "No biometry enrolled"
                }
            }
            DemoLogSection(log: log)
        }
        .navigationTitle("Biometric PIN")
    }
}

/// Content hidden behind `BiometricGate`; it locks again when the app goes to the background.
struct GateDemo: View {
    var body: some View {
        BiometricGate(reason: "Unlock your records") {
            List {
                Section("Unlocked") {
                    Label("Blood group: O+", systemImage: "drop")
                    Label("Allergies: penicillin", systemImage: "allergens")
                    Label("Emergency contact: +91 98765 43210", systemImage: "phone")
                }
                Section {
                    Text("Send the app to the background and come back: the screen locks again.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("BiometricGate")
    }
}
