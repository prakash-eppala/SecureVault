//
//  StreamCipher.swift
//  SecureVaultCrypto
//
//  Created by Prakash on 09/10/26.
//

import CryptoKit
import Foundation
#if canImport(SecureVaultCore)
import SecureVaultCore
#endif

/// Chunked online authenticated encryption: the STREAM construction over AES-256-GCM (PRD §19).
///
/// Each file gets its own key, `HKDF(dataKey, salt)`. Chunk `i` uses nonce `prefix(7) ‖ i(4, BE) ‖ last(1)`
/// and associated data `SHA256(header ‖ context)`. Reordering, truncation and splicing fail authentication.
public struct StreamCipher: Sendable {
    public static let chunkSize = 64 * 1024
    public static let tagSize = 16

    private let key: SymmetricKey
    private let noncePrefix: Data
    private let aad: Data

    public init(dataKey: SymmetricKey, salt: Data, noncePrefix: Data, header: Data, context: Data) {
        precondition(noncePrefix.count == 7)
        self.key = KeyDerivation.derive(dataKey, label: "files.stream", salt: salt)
        self.noncePrefix = noncePrefix
        self.aad = Data(SHA256.hash(data: header + context))
    }

    /// A key for small sealed metadata belonging to the same file.
    public static func metadataKey(dataKey: SymmetricKey, salt: Data) -> SymmetricKey {
        KeyDerivation.derive(dataKey, label: "files.meta", salt: salt)
    }

    public func seal(chunk: Data, index: UInt32, isLast: Bool) throws -> Data {
        let sealed = try AES.GCM.seal(chunk, using: key, nonce: nonce(index, isLast), authenticating: aad)
        return sealed.ciphertext + sealed.tag
    }

    public func open(chunk: Data, index: UInt32, isLast: Bool) throws -> Data {
        guard chunk.count >= Self.tagSize else { throw SecureVaultError.decryptionFailed }
        do {
            let box = try AES.GCM.SealedBox(
                nonce: nonce(index, isLast),
                ciphertext: chunk.prefix(chunk.count - Self.tagSize),
                tag: chunk.suffix(Self.tagSize)
            )
            return try AES.GCM.open(box, using: key, authenticating: aad)
        } catch {
            throw SecureVaultError.decryptionFailed
        }
    }

    private func nonce(_ index: UInt32, _ isLast: Bool) throws -> AES.GCM.Nonce {
        var bytes = noncePrefix
        var counter = index.bigEndian
        withUnsafeBytes(of: &counter) { bytes.append(contentsOf: $0) }
        bytes.append(isLast ? 1 : 0)
        return try AES.GCM.Nonce(data: bytes)
    }
}
