//
//  FilesDemo.swift
//  SecureVaultExample
//
//  Created by Prakash on 09/10/26.
//

import SecureVault
import SwiftUI

/// Encrypted files, streamed in 64 KiB chunks, with names hidden on disk.
struct FilesDemo: View {
    @Environment(\.secureVault) private var vault
    @State private var files: [ProtectedFileInfo] = []
    @State private var log = DemoLog()

    var body: some View {
        Form {
            Section {
                ForEach(files, id: \.name) { file in
                    LabeledContent(file.name, value: ByteCountFormatter.string(fromByteCount: file.size, countStyle: .file))
                }
                .onDelete { offsets in
                    let names = offsets.map { files[$0].name }
                    log.run("Delete \(names.joined(separator: ", "))") {
                        for name in names { try await vault.files.delete(named: name, namespace: .medical) }
                        try await reload()
                        return "Deleted"
                    }
                }
                if files.isEmpty {
                    Text("No files yet.").foregroundStyle(.secondary)
                }
            } header: {
                Text("Medical files")
            }
            Section("Actions") {
                ActionRow("Save a report", systemImage: "doc.text", log: log) {
                    let report = "Lab report\nPatient: Asha Rao\nHbA1c: 5.6%\nCreated: \(Date.now.formatted())\n"
                    try await vault.files.write(Data(report.utf8), named: "lab-report.txt", namespace: .medical, policy: .highlySensitive)
                    try await reload()
                    return "Encrypted and saved"
                }
                ActionRow("Stream a 2 MB scan from disk", systemImage: "photo", log: log) {
                    let source = FileManager.default.temporaryDirectory.appendingPathComponent("scan.bin")
                    try Data((0..<2_000_000).map { UInt8(truncatingIfNeeded: $0) }).write(to: source)
                    defer { try? FileManager.default.removeItem(at: source) }
                    try await vault.files.write(contentsOf: source, named: "x-ray.bin", namespace: .medical, policy: .highlySensitive)
                    try await reload()
                    return "Streamed without loading it into memory"
                }
                ActionRow("Read the report", systemImage: "eye", log: log) {
                    String(decoding: try await vault.files.read(named: "lab-report.txt", namespace: .medical), as: UTF8.self)
                }
                ActionRow("Export the scan to a temporary file", systemImage: "square.and.arrow.up", log: log) {
                    let destination = FileManager.default.temporaryDirectory.appendingPathComponent("x-ray-export.bin")
                    try? FileManager.default.removeItem(at: destination)
                    try await vault.files.export(named: "x-ray.bin", namespace: .medical, to: destination)
                    let size = (try FileManager.default.attributesOfItem(atPath: destination.path)[.size] as? NSNumber)?.int64Value ?? 0
                    try FileManager.default.removeItem(at: destination)
                    return "Decrypted \(ByteCountFormatter.string(fromByteCount: size, countStyle: .file)), then deleted the plaintext copy"
                }
                ActionRow("Re-encrypt files with a new key", systemImage: "arrow.triangle.2.circlepath", log: log) {
                    "Re-encrypted \(try await vault.files.rotateKeys()) files"
                }
            }
            DemoLogSection(log: log)
        }
        .navigationTitle("Protected files")
        .task { try? await reload() }
    }

    private func reload() async throws {
        files = try await vault.files.list(namespace: .medical)
    }
}
