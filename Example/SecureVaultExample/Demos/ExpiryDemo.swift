//
//  ExpiryDemo.swift
//  SecureVaultExample
//
//  Created by Prakash on 09/10/26.
//

import SecureVault
import SwiftUI

/// Values that expire: a one-time code and a short-lived session.
struct ExpiryDemo: View {
    @Environment(\.secureVault) private var vault
    @State private var log = DemoLog()
    @State private var expiresAt: Date?

    var body: some View {
        Form {
            Section {
                Text("Expiry is stored inside the encrypted envelope, so it cannot be extended by editing the file. Expired values are deleted when read.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            Section("Session that expires in 10 seconds") {
                ActionRow("Start session", systemImage: "timer", log: log) {
                    try await vault.store("session-\(Int.random(in: 1000...9999))", forKey: "session", namespace: .session,
                                          policy: .session.expiring(after: 10))
                    expiresAt = Date().addingTimeInterval(10)
                    return "Stored with a 10 second lifetime"
                }
                if let expiresAt {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let left = max(0, Int(expiresAt.timeIntervalSince(context.date).rounded(.up)))
                        LabeledContent("Time left", value: left == 0 ? "Expired" : "\(left) s")
                    }
                }
                ActionRow("Read session", systemImage: "eye", log: log) {
                    try await vault.retrieve(String.self, forKey: "session", namespace: .session)
                }
            }
            Section("One-time code (.otp, 5 minutes)") {
                ActionRow("Store code", systemImage: "number", log: log) {
                    let code = String(format: "%06d", Int.random(in: 0...999_999))
                    try await vault.store(code, forKey: "otp", namespace: .session, policy: .otp)
                    return "Stored \(code)"
                }
                ActionRow("Read code", systemImage: "eye", log: log) {
                    try await vault.retrieve(String.self, forKey: "otp", namespace: .session)
                }
            }
            Section {
                ActionRow("Delete every expired value", systemImage: "trash", log: log) {
                    "Removed \(try await vault.purgeExpired())"
                }
            }
            DemoLogSection(log: log)
        }
        .navigationTitle("Expiry")
    }
}
