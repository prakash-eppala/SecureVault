//
//  ReportDemo.swift
//  SecureVaultExample
//
//  Created by Prakash on 09/10/26.
//

import SecureVault
import SwiftUI

/// The security posture report. It never contains values or key names.
struct ReportDemo: View {
    @Environment(\.secureVault) private var vault
    @State private var report: SecurityReport?

    var body: some View {
        Form {
            if let report {
                Section("Device") {
                    LabeledContent("Passcode set", value: report.passcodeSet ? "Yes" : "No")
                    LabeledContent("Biometry", value: report.biometry.rawValue)
                    LabeledContent("Secure Enclave", value: report.secureEnclaveAvailable ? (report.secureEnclaveInUse ? "In use" : "Available") : "Not available")
                    LabeledContent("Encrypted value files", value: "\(report.storedObjectFiles)")
                }
                Section("Findings") {
                    if report.findings.isEmpty {
                        Label("No findings", systemImage: "checkmark.seal").foregroundStyle(.green)
                    }
                    ForEach(report.findings) { finding in
                        VStack(alignment: .leading, spacing: 4) {
                            Label(finding.code, systemImage: symbol(finding.severity))
                                .foregroundStyle(color(finding.severity))
                                .font(.subheadline.weight(.semibold))
                            Text(finding.message).font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                }
                Section("Keys") {
                    ForEach(Array(report.keys.enumerated()), id: \.offset) { _, key in
                        LabeledContent("\(key.purpose) · \(key.domain)", value: "\(key.versions) version(s)")
                    }
                }
            } else {
                ProgressView()
            }
        }
        .navigationTitle("Security report")
        .refreshable { report = await vault.securityReport() }
        .task { report = await vault.securityReport() }
    }

    private func symbol(_ severity: SecurityReport.Finding.Severity) -> String {
        switch severity {
        case .critical: "exclamationmark.octagon.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .info: "info.circle.fill"
        }
    }

    private func color(_ severity: SecurityReport.Finding.Severity) -> Color {
        switch severity {
        case .critical: .red
        case .warning: .orange
        case .info: .blue
        }
    }
}
