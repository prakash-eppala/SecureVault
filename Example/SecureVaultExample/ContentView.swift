//
//  ContentView.swift
//  SecureVaultExample
//
//  Created by Prakash on 09/10/26.
//

import SecureVault
import SwiftUI

/// Every SecureVault feature, one screen each.
struct ContentView: View {
    var body: some View {
        NavigationStack {
            List {
                Section("Key-value storage") {
                    NavigationLink("Tokens and policies") { TokensDemo() }
                    NavigationLink("Expiry") { ExpiryDemo() }
                    NavigationLink("@SecureStorage in SwiftUI") { SecureStorageDemo() }
                }
                Section("Biometrics") {
                    NavigationLink("Biometric-protected PIN") { BiometricDemo() }
                    NavigationLink("BiometricGate") { GateDemo() }
                }
                Section("Records and files") {
                    NavigationLink("Encrypted database") { DatabaseDemo() }
                    NavigationLink("Protected files") { FilesDemo() }
                }
                Section("Lifecycle") {
                    NavigationLink("Migration") { MigrationDemo() }
                    NavigationLink("Namespaces, logout and reset") { SessionDemo() }
                    NavigationLink("Key rotation") { RotationDemo() }
                }
                Section("Diagnostics") {
                    NavigationLink("Security report") { ReportDemo() }
                }
                Section("Objective-C") {
                    NavigationLink("SVVault from Objective-C") { ObjCDemoView() }
                }
                Section {
                    LabeledContent("SDK", value: "\(SecureVault.version) (build \(SecureVault.build))")
                }
            }
            .navigationTitle("SecureVault")
        }
    }
}

#Preview {
    ContentView().secureVault(SecureVault(configuration: .testing()))
}
