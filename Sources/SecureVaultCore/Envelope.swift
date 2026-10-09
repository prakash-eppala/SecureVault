//
//  Envelope.swift
//  SecureVaultCore
//
//  Created by Prakash on 09/10/26.
//

import CryptoKit
import Foundation

/// Authenticated metadata stored in front of every ciphertext (PRD §14).
public struct EnvelopeHeader: Codable, Sendable, Equatable {
    public var algorithm: String
    public var keyPurpose: String
    public var keyDomain: String
    public var keyVersion: Int
    public var createdAt: Date
    public var expiresAt: Date?

    enum CodingKeys: String, CodingKey {
        case algorithm = "alg", keyPurpose = "kp", keyDomain = "kd", keyVersion = "kv", createdAt = "ca", expiresAt = "ea"
    }

    public init(algorithm: String, keyPurpose: String, keyDomain: String, keyVersion: Int, createdAt: Date, expiresAt: Date?) {
        self.algorithm = algorithm
        self.keyPurpose = keyPurpose
        self.keyDomain = keyDomain
        self.keyVersion = keyVersion
        self.createdAt = createdAt
        self.expiresAt = expiresAt
    }

    public var keyID: KeyID? {
        KeyDomain(id: keyDomain).map { KeyID(purpose: keyPurpose, domain: $0) }
    }
}

/// `SVE` ‖ version(1) ‖ headerLength(4, BE) ‖ header JSON ‖ nonce ‖ ciphertext ‖ tag.
/// The associated data is everything before the sealed box plus a location context.
public enum Envelope {
    static let magic = Data("SVE".utf8)
    public static let formatVersion: UInt8 = 1

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        encoder.outputFormatting = .sortedKeys
        return encoder
    }()

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return decoder
    }()

    public static func seal(
        _ plaintext: Data, header: EnvelopeHeader, key: SymmetricKey, context: Data, crypto: any CryptoProvider
    ) throws -> Data {
        guard let headerData = try? encoder.encode(header) else { throw SecureVaultError.encryptionFailed }
        var prefix = magic
        prefix.append(formatVersion)
        var length = UInt32(headerData.count).bigEndian
        withUnsafeBytes(of: &length) { prefix.append(contentsOf: $0) }
        prefix.append(headerData)

        let sealed: Data
        do {
            sealed = try crypto.seal(plaintext, using: key, authenticating: prefix + context)
        } catch {
            throw SecureVaultError.encryptionFailed
        }
        return prefix + sealed
    }

    /// Reads the header without authenticating it. Use only for routing (key lookup, expiry hints).
    public static func peekHeader(_ envelope: Data) throws -> EnvelopeHeader {
        try split(envelope).header
    }

    public static func open(
        _ envelope: Data, key: SymmetricKey, context: Data, crypto: any CryptoProvider
    ) throws -> (header: EnvelopeHeader, plaintext: Data) {
        let parts = try split(envelope)
        guard parts.header.algorithm == crypto.algorithm else {
            throw SecureVaultError.invalidData(reason: "unsupported algorithm \(parts.header.algorithm)")
        }
        do {
            let plaintext = try crypto.open(parts.sealed, using: key, authenticating: parts.prefix + context)
            return (parts.header, plaintext)
        } catch {
            throw SecureVaultError.decryptionFailed
        }
    }

    private static func split(_ envelope: Data) throws -> (prefix: Data, header: EnvelopeHeader, sealed: Data) {
        let bytes = Data(envelope) // rebase indices to 0
        guard bytes.count > 8, bytes.prefix(3) == magic else {
            throw SecureVaultError.invalidData(reason: "not a SecureVault envelope")
        }
        guard bytes[3] == formatVersion else {
            throw SecureVaultError.invalidData(reason: "unsupported envelope format \(bytes[3])")
        }
        let length = bytes[4..<8].reduce(0) { ($0 << 8) | Int($1) }
        let headerEnd = 8 + length
        guard length > 0, bytes.count > headerEnd else {
            throw SecureVaultError.invalidData(reason: "truncated envelope")
        }
        guard let header = try? decoder.decode(EnvelopeHeader.self, from: bytes[8..<headerEnd]) else {
            throw SecureVaultError.invalidData(reason: "unreadable envelope header")
        }
        return (Data(bytes[0..<headerEnd]), header, Data(bytes[headerEnd...]))
    }
}
