//
//  SecureRecord.swift
//  SecureVaultDatabase
//
//  Created by Prakash on 09/10/26.
//

import Foundation

/// A record stored in a `SecureDatabase`. Conform any Codable model with a string-convertible id:
///
///     struct Patient: SecureRecord { let id: UUID; var name: String }
public protocol SecureRecord: Codable, Sendable, Identifiable where ID: CustomStringConvertible {
    /// The record type name used for indexing. Defaults to the Swift type name; override to keep it stable across renames.
    static var recordType: String { get }
}

extension SecureRecord {
    public static var recordType: String { String(describing: Self.self) }
}
