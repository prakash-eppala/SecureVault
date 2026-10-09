//
//  Patient.swift
//  SecureVaultExample
//
//  Created by Prakash on 09/10/26.
//

import Foundation
import SecureVault

/// A record for the encrypted database demo.
struct Patient: SecureRecord, Hashable {
    let id: UUID
    var name: String
    var condition: String
    var age: Int

    static func random() -> Patient {
        let names = ["Asha Rao", "Ravi Kumar", "Mira Shah", "Arjun Nair", "Leela Iyer", "Kabir Das"]
        let conditions = ["Hypertension", "Asthma", "Diabetes type 2", "Migraine", "Healthy"]
        return Patient(id: UUID(), name: names.randomElement()!, condition: conditions.randomElement()!, age: Int.random(in: 4...88))
    }
}
