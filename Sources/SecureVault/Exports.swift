//
//  Exports.swift
//  SecureVault
//
//  Created by Prakash on 09/10/26.
//

// The Swift package splits SecureVault into modules and re-exports them here.
// CocoaPods builds one module, so there is nothing to re-export.
#if canImport(SecureVaultBiometrics)
@_exported import SecureVaultBiometrics
#endif
#if canImport(SecureVaultCore)
@_exported import SecureVaultCore
#endif
#if canImport(SecureVaultCrypto)
@_exported import SecureVaultCrypto
#endif
#if canImport(SecureVaultDatabase)
@_exported import SecureVaultDatabase
#endif
#if canImport(SecureVaultDiagnostics)
@_exported import SecureVaultDiagnostics
#endif
#if canImport(SecureVaultFiles)
@_exported import SecureVaultFiles
#endif
#if canImport(SecureVaultKeychain)
@_exported import SecureVaultKeychain
#endif
