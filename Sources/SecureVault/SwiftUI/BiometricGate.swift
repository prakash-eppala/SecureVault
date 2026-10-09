//
//  BiometricGate.swift
//  SecureVault
//
//  Created by Prakash on 09/10/26.
//

import SwiftUI

/// Hides content until the user authenticates, and locks again when the app leaves the foreground.
///
///     BiometricGate(reason: "Unlock your records") { RecordsView() }
public struct BiometricGate<Content: View, Locked: View>: View {
    private let reason: String
    private let allowPasscodeFallback: Bool
    private let authenticateOnAppear: Bool
    private let content: () -> Content
    private let locked: (_ unlock: @escaping () -> Void, _ error: SecureVaultError?) -> Locked

    @State private var isUnlocked = false
    @State private var isAuthenticating = false
    @State private var error: SecureVaultError?
    @Environment(\.scenePhase) private var scenePhase

    public init(
        reason: String,
        allowPasscodeFallback: Bool = true,
        authenticateOnAppear: Bool = true,
        @ViewBuilder content: @escaping () -> Content,
        @ViewBuilder locked: @escaping (_ unlock: @escaping () -> Void, _ error: SecureVaultError?) -> Locked
    ) {
        self.reason = reason
        self.allowPasscodeFallback = allowPasscodeFallback
        self.authenticateOnAppear = authenticateOnAppear
        self.content = content
        self.locked = locked
    }

    public var body: some View {
        Group {
            if isUnlocked {
                content()
            } else {
                locked(unlock, error)
            }
        }
        .task {
            if authenticateOnAppear, !isUnlocked { await authenticate() }
        }
        .onChange(of: scenePhase) { phase in
            if phase == .background { isUnlocked = false }
        }
    }

    private func unlock() {
        Task { await authenticate() }
    }

    @MainActor
    private func authenticate() async {
        guard !isAuthenticating else { return }
        isAuthenticating = true
        defer { isAuthenticating = false }
        do {
            _ = try await BiometricAuthenticator().authenticate(reason: reason, allowingPasscodeFallback: allowPasscodeFallback)
            error = nil
            isUnlocked = true
        } catch {
            self.error = SecureVaultError.wrap(error)
        }
    }
}

extension BiometricGate where Locked == BiometricLockedView {
    public init(
        reason: String,
        allowPasscodeFallback: Bool = true,
        authenticateOnAppear: Bool = true,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.init(reason: reason, allowPasscodeFallback: allowPasscodeFallback, authenticateOnAppear: authenticateOnAppear, content: content) {
            BiometricLockedView(unlock: $0, error: $1)
        }
    }
}

/// The default locked screen: a lock symbol, the last error if any, and an Unlock button.
public struct BiometricLockedView: View {
    let unlock: () -> Void
    let error: SecureVaultError?

    public init(unlock: @escaping () -> Void, error: SecureVaultError?) {
        self.unlock = unlock
        self.error = error
    }

    public var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.fill")
                .font(.system(size: 44, weight: .regular))
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text("Locked")
                .font(.title2.weight(.semibold))
            if let error, error != .userCancelled {
                Text(error.localizedDescription)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            Button(action: unlock) {
                Text("Unlock")
                    .frame(minWidth: 120)
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

extension View {
    /// Wraps the view in a `BiometricGate`.
    public func biometricLock(reason: String, allowPasscodeFallback: Bool = true) -> some View {
        BiometricGate(reason: reason, allowPasscodeFallback: allowPasscodeFallback) { self }
    }
}
