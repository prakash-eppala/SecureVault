//
//  ObjCDemoView.swift
//  SecureVaultExample
//
//  Created by Prakash on 09/10/26.
//

import SwiftUI

/// Runs `ObjCDemo.m`, which uses SecureVault through `@import SecureVault;`.
struct ObjCDemoView: View {
    @State private var lines: [String] = []
    @State private var running = false

    var body: some View {
        Form {
            Section {
                Text("Objective-C sees the SV… classes: SVVault, SVPolicy, SVDatabase, SVFileStore, SVBiometrics and SVError. Completion blocks run on the main queue.")
                    .font(.footnote).foregroundStyle(.secondary)
                Button {
                    running = true
                    ObjCDemo.run { output in
                        lines = output
                        running = false
                    }
                } label: {
                    Label(running ? "Running…" : "Run the Objective-C demo", systemImage: "chevron.left.forwardslash.chevron.right")
                }
                .disabled(running)
            }
            Section("Output") {
                ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                    Text(line).font(.footnote.monospaced())
                }
            }
        }
        .navigationTitle("Objective-C")
    }
}
