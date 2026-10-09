//
//  SQLite.swift
//  SecureVaultDatabase
//
//  Created by Prakash on 09/10/26.
//

import Foundation
import SQLite3
#if canImport(SecureVaultCore)
import SecureVaultCore
#endif

/// Minimal SQLite wrapper. Not thread-safe; owned by the `SecureDatabase` actor.
final class SQLiteConnection {
    enum Value {
        case blob(Data)
        case text(String)
        case int(Int64)
    }

    private var handle: OpaquePointer?
    private static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    init(path: String) throws {
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX
        let status = sqlite3_open_v2(path, &handle, flags, nil)
        guard status == SQLITE_OK else {
            let error = Self.error(status, handle)
            sqlite3_close_v2(handle)
            handle = nil
            throw error
        }
        sqlite3_busy_timeout(handle, 2_000)
    }

    deinit { close() }

    func close() {
        if let handle { sqlite3_close_v2(handle) }
        handle = nil
    }

    func execute(_ sql: String, _ values: [Value] = []) throws {
        let statement = try prepare(sql, values)
        defer { sqlite3_finalize(statement) }
        var status = sqlite3_step(statement)
        while status == SQLITE_ROW { status = sqlite3_step(statement) }
        guard status == SQLITE_DONE else { throw Self.error(status, handle) }
    }

    func query(_ sql: String, _ values: [Value] = []) throws -> [[Data]] {
        let statement = try prepare(sql, values)
        defer { sqlite3_finalize(statement) }
        var rows: [[Data]] = []
        while true {
            let status = sqlite3_step(statement)
            if status == SQLITE_DONE { break }
            guard status == SQLITE_ROW else { throw Self.error(status, handle) }
            let columns = sqlite3_column_count(statement)
            rows.append((0..<columns).map { column in
                let count = Int(sqlite3_column_bytes(statement, column))
                guard count > 0, let bytes = sqlite3_column_blob(statement, column) else { return Data() }
                return Data(bytes: bytes, count: count)
            })
        }
        return rows
    }

    func transaction<T>(_ body: () throws -> T) throws -> T {
        try execute("BEGIN IMMEDIATE")
        do {
            let result = try body()
            try execute("COMMIT")
            return result
        } catch {
            try? execute("ROLLBACK")
            throw error
        }
    }

    private func prepare(_ sql: String, _ values: [Value]) throws -> OpaquePointer? {
        var statement: OpaquePointer?
        let status = sqlite3_prepare_v2(handle, sql, -1, &statement, nil)
        guard status == SQLITE_OK else { throw Self.error(status, handle) }
        for (offset, value) in values.enumerated() {
            let index = Int32(offset + 1)
            let bound: Int32
            switch value {
            case .blob(let data):
                bound = data.withUnsafeBytes { sqlite3_bind_blob(statement, index, $0.baseAddress, Int32($0.count), Self.transient) }
            case .text(let text):
                bound = sqlite3_bind_text(statement, index, text, -1, Self.transient)
            case .int(let number):
                bound = sqlite3_bind_int64(statement, index, number)
            }
            guard bound == SQLITE_OK else {
                sqlite3_finalize(statement)
                throw Self.error(bound, handle)
            }
        }
        return statement
    }

    static func error(_ status: Int32, _ handle: OpaquePointer?) -> SecureVaultError {
        let primary = status & 0xFF
        if primary == SQLITE_AUTH || primary == SQLITE_PERM {
            return .protectedDataUnavailable
        }
        let message = handle.flatMap { sqlite3_errmsg($0) }.map { String(cString: $0) } ?? "unknown"
        return .databaseFailure(reason: "sqlite \(status): \(message)")
    }
}
