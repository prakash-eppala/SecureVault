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
        let keyHash = key.map(Self.hash) ?? "-"
        let space = namespace.map { Self.builtInNamespaces.contains($0) ? $0 : "#" + Self.hash($0) } ?? "-"
        logger.debug("\(operation, privacy: .public) ns=\(space, privacy: .public) key#=\(keyHash, privacy: .public)")
    }

    static let builtInNamespaces: Set<String> = [
        VaultNamespace.default, .auth, .session, .user, .preferences, .medical, .financial, .cache,
    ].reduce(into: []) { $0.insert($1.rawValue) }

    static func hash(_ value: String) -> String {
        String(Digest.hex(Digest.sha256(value)).prefix(12))
    }

    package func warning(_ message: String) {
        guard isEnabled else { return }
        logger.warning("\(message, privacy: .public)")
    }
}
