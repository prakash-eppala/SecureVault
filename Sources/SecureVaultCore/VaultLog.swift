//
//  VaultLog.swift
//  SecureVaultCore
//
//  Created by Prakash on 09/10/26.
//

import Foundation
import os

/// SDK logging. Off by default. Never receives values, keys or payloads, only operation names,
/// namespaces and hashed key names (PRD §26).
public struct VaultLog: Sendable {
    public let isEnabled: Bool
    private let logger = Logger(subsystem: "com.securevault.sdk", category: "vault")

    public init(enabled: Bool) { self.isEnabled = enabled }

    package func event(_ operation: StaticString, namespace: String? = nil, key: String? = nil) {
        guard isEnabled else { return }
        let keyHash = key.map { String(Digest.hex(Digest.sha256($0)).prefix(12)) } ?? "-"
        logger.debug("\(operation, privacy: .public) ns=\(namespace ?? "-", privacy: .public) key#=\(keyHash, privacy: .public)")
    }

    package func warning(_ message: String) {
        guard isEnabled else { return }
        logger.warning("\(message, privacy: .public)")
    }
}
