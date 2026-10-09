//
//  DatabaseDemo.swift
//  SecureVaultExample
//
//  Created by Prakash on 09/10/26.
//

import SecureVault
import SwiftUI

/// Patient records in an encrypted database. Names, ids and contents never reach the file in plaintext.
struct DatabaseDemo: View {
    @Environment(\.secureVault) private var vault
    @State private var patients: [Patient] = []
    @State private var adultsOnly = false
    @State private var log = DemoLog()

    var body: some View {
        Form {
            Section {
                Toggle("Adults only (filtered in memory)", isOn: $adultsOnly)
                ForEach(patients, id: \.id) { patient in
                    VStack(alignment: .leading) {
                        Text(patient.name).font(.body.weight(.medium))
                        Text("\(patient.condition) · \(patient.age) years").font(.footnote).foregroundStyle(.secondary)
                    }
                }
                .onDelete { offsets in
                    let removed = offsets.map { patients[$0] }
                    log.run("Delete \(removed.count) record(s)") {
                        let db = try await database()
                        for patient in removed { try await db.delete(Patient.self, id: patient.id) }
                        try await reload()
                        return "Deleted"
                    }
                }
                if patients.isEmpty {
                    Text("No records yet.").foregroundStyle(.secondary)
                }
            } header: {
                Text("Patients (\(patients.count))")
            }
            Section("Actions") {
                ActionRow("Add a patient", systemImage: "person.badge.plus", log: log) {
                    let patient = Patient.random()
                    try await database().insert(patient)
                    try await reload()
                    return "Inserted \(patient.name)"
                }
                ActionRow("Add five in one transaction", systemImage: "person.3", log: log) {
                    try await database().insert(contentsOf: (0..<5).map { _ in Patient.random() })
                    try await reload()
                    return "Inserted 5"
                }
                ActionRow("Look up the first by id", systemImage: "magnifyingglass", log: log) {
                    guard let first = patients.first else { return "Nothing to look up" }
                    let found = try await database().get(Patient.self, id: first.id)
                    return found.map { "\($0.name), \($0.condition)" } ?? "Not found"
                }
                ActionRow("Rotate the database key", systemImage: "arrow.triangle.2.circlepath", log: log) {
                    "Re-encrypted \(try await database().rotateKey()) records in one transaction"
                }
                ActionRow("Delete all patients", systemImage: "trash", log: log) {
                    try await database().deleteAll(Patient.self)
                    try await reload()
                    return "Deleted all"
                }
            }
            DemoLogSection(log: log)
        }
        .navigationTitle("Encrypted database")
        .task { try? await reload() }
        .onChange(of: adultsOnly) { Task { try? await reload() } }
    }

    private func database() async throws -> SecureDatabase {
        try await vault.database("medical", policy: .highlySensitive)
    }

    private func reload() async throws {
        let db = try await database()
        let records = adultsOnly ? try await db.all(Patient.self) { $0.age >= 18 } : try await db.all(Patient.self)
        patients = records.sorted { $0.name < $1.name }
    }
}
