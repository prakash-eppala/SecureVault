//
//  RotationDemo.swift
//  SecureVaultExample
//
//  Created by Prakash on 09/10/26.
//

import SecureVault
import SwiftUI

/// Rotates every key in use and re-encrypts data, crash-safely.
struct RotationDemo: View {
    @Environment(\.secureVault) private var vault
    @State private var log = DemoLog()

    var body: some View {
        Form {
            Section {
                Text("Every value records which key version sealed it, and old versions are deleted last, so an interrupted rotation never loses data. Items that need biometry are skipped and keep their old key.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            Section {
                ActionRow("Rotate all keys", systemImage: "arrow.triangle.2.circlepath", log: log) {
                    let report = try await vault.rotateKeys(databases: ["medical"])
                    return """
                    items re-encrypted   \(report.reencryptedItems)
                    items skipped        \(report.skippedItems)
                    records re-encrypted \(report.reencryptedRecords)
                    files re-encrypted   \(report.reencryptedFiles)
                    old versions retired \(report.retiredKeyVersions)
                    complete             \(report.isComplete)
                    """
                }
                ActionRow("Finish an interrupted rotation", systemImage: "arrow.clockwise", log: log) {
                    let report = try await vault.completePendingRotations()
                    return "Re-encrypted \(report.reencryptedItems), retired \(report.retiredKeyVersions)"
                }
                ActionRow("Remove unreadable items", systemImage: "trash.slash", log: log) {
                    "Removed \(try await vault.purgeUnreadableItems()) (data whose key did not survive a restore)"
                }
            }
            DemoLogSection(log: log)
        }
        .navigationTitle("Key rotation")
    }
}
