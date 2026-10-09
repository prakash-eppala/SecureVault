//
//  DemoLog.swift
//  SecureVaultExample
//
//  Created by Prakash on 09/10/26.
//

import SecureVault
import SwiftUI

/// Collects the outcome of each demo action so the screen can show what SecureVault did.
@MainActor
@Observable
final class DemoLog {
    struct Entry: Identifiable {
        let id = UUID()
        let title: String
        let detail: String
        let succeeded: Bool
    }

    private(set) var entries: [Entry] = []

    /// Runs an action and records its result or its error.
    func run(_ title: String, _ action: @escaping @MainActor () async throws -> String) {
        Task {
            do {
                record(title, try await action(), succeeded: true)
            } catch let error as SecureVaultError {
                record(title, "\(error.localizedDescription) (code \(error.code))", succeeded: false)
            } catch {
                record(title, error.localizedDescription, succeeded: false)
            }
        }
    }

    func record(_ title: String, _ detail: String, succeeded: Bool) {
        entries.insert(Entry(title: title, detail: detail, succeeded: succeeded), at: 0)
    }

    func clear() { entries.removeAll() }
}

/// The log, newest first.
struct DemoLogSection: View {
    let log: DemoLog

    var body: some View {
        Section {
            if log.entries.isEmpty {
                Text("Results appear here.").foregroundStyle(.secondary)
            }
            ForEach(log.entries) { entry in
                VStack(alignment: .leading, spacing: 4) {
                    Label(entry.title, systemImage: entry.succeeded ? "checkmark.circle.fill" : "xmark.octagon.fill")
                        .foregroundStyle(entry.succeeded ? .green : .red)
                        .font(.subheadline.weight(.semibold))
                    Text(entry.detail)
                        .font(.footnote.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                .padding(.vertical, 2)
            }
        } header: {
            HStack {
                Text("Results")
                Spacer()
                if !log.entries.isEmpty {
                    Button("Clear") { log.clear() }.font(.caption)
                }
            }
        }
    }
}

/// A row button that runs an action through the log.
struct ActionRow: View {
    let title: String
    let systemImage: String
    let log: DemoLog
    let action: @MainActor () async throws -> String

    init(_ title: String, systemImage: String, log: DemoLog, action: @escaping @MainActor () async throws -> String) {
        self.title = title
        self.systemImage = systemImage
        self.log = log
        self.action = action
    }

    var body: some View {
        Button {
            log.run(title, action)
        } label: {
            Label(title, systemImage: systemImage)
        }
    }
}
