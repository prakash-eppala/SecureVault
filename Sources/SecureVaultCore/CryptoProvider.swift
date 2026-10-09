//
//  CryptoProvider.swift
//  SecureVaultCore
//
//  Created by Prakash on 09/10/26.
//

import CryptoKit
import Foundation

/// Authenticated encryption used for envelopes. V1 ships AES-256-GCM (`AESGCMProvider`).
public protocol CryptoProvider: Sendable {
    /// Stored in every envelope, e.g. `A256GCM`.
    var algorithm: String { get }
    /// Returns nonce ‖ ciphertext ‖ tag.
    func seal(_ plaintext: Data, using key: SymmetricKey, authenticating aad: Data) throws -> Data
    func open(_ sealed: Data, using key: SymmetricKey, authenticating aad: Data) throws -> Data
}

/// Protects data keys at rest beyond the Keychain, e.g. Secure Enclave wrapping (PRD §15.2).
public protocol KeyProtector: Sendable {
    /// Recorded with each protected key, e.g. `se-p256-ecies-v1`.
    var identifier: String { get }
    /// Creates the protecting key; the returned opaque blob is persisted in the Keychain.
    func makeProtectionKey() throws -> Data
    func wrap(_ key: Data, protectionKey: Data, context: Data) throws -> Data
    func unwrap(_ wrapped: Data, protectionKey: Data, context: Data) throws -> Data
}

package enum Digest {
    package static func sha256(_ parts: String...) -> Data {
        Data(SHA256.hash(data: Data(parts.joined(separator: "\u{1F}").utf8)))
    }

    package static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
