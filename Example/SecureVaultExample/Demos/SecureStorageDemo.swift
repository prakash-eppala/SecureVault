//
//  SecureStorageDemo.swift
//  SecureVaultExample
//
//  Created by Prakash on 09/10/26.
//

import SecureVault
import SwiftUI

/// `@SecureStorage` works like `@AppStorage`, but the value is encrypted.
struct SecureStorageDemo: View {
    @SecureStorage("draftNote", namespace: .user, policy: .sensitive) private var note: String?
    @SecureStorage("launches", namespace: .preferences, policy: .preference) private var launches: Int?

    var body: some View {
        Form {
            Section {
                Text("Edits are saved to the vault as you type. Leave this screen and come back: the text is read back from encrypted storage.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            Section("Encrypted note") {
                TextField("Write something private", text: Binding(get: { note ?? "" }, set: { note = $0.isEmpty ? nil : $0 }), axis: .vertical)
                    .lineLimit(3...8)
                if $note.isLoading {
                    ProgressView()
                }
                if let error = $note.error {
                    Text(error.localizedDescription).foregroundStyle(.red).font(.footnote)
                }
                Button("Delete note", role: .destructive) { note = nil }
                    .disabled(note == nil)
            }
            Section("Counter") {
                LabeledContent("Times this screen opened", value: "\(launches ?? 0)")
            }
        }
        .navigationTitle("@SecureStorage")
        .task {
            await $launches.load()
            launches = (launches ?? 0) + 1
        }
    }
}
