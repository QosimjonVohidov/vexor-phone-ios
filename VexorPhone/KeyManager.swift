import Foundation
import LocalAuthentication
import Security

enum KeyError: Error, CustomStringConvertible {
    case message(String)

    var description: String {
        switch self {
        case .message(let text): return text
        }
    }
}

/// Secure Enclave'dagi biometrik bilan himoyalangan P-256 kalit.
/// Maxfiy kalit telefondan chiqmaydi. Imzolash uchun Face ID / Touch ID kerak.
/// Yuz yoki barmoq izi qo'shilsa yoki o'zgarsa (biometryCurrentSet), kalit yaroqsiz bo'ladi.
enum KeyManager {
    static let tag = Data("uz.qosimjon.vexorphone.signing".utf8)

    private static func baseQuery() -> [String: Any] {
        return [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ]
    }

    static func keyExists() -> Bool {
        let context = LAContext()
        context.interactionNotAllowed = true   // Face ID oynasini ochmasdan faqat "kalit bormi" deb so'raymiz

        var query = baseQuery()
        query[kSecReturnRef as String] = true
        query[kSecUseAuthenticationContext as String] = context
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        // Biometrik talab qilinadigan kalit uchun "interaktsiya kerak" ham "kalit bor" degani
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    static func createKey() throws -> SecKey {
        var error: Unmanaged<CFError>?

        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &error
        ) else {
            let text = error.map { "\($0.takeRetainedValue())" } ?? "unknown"
            throw KeyError.message("Access control failed: \(text)")
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access
            ] as [String: Any]
        ]

        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let text = error.map { "\($0.takeRetainedValue())" } ?? "unknown"
            throw KeyError.message("Key creation failed: \(text)")
        }

        return key
    }

    /// 65 bayt: 04 || X || Y (kompyuter shu formatni qabul qiladi)
    static func publicKeyBase64(of privateKey: SecKey) -> String? {
        guard let publicKey = SecKeyCopyPublicKey(privateKey),
              let data = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            return nil
        }
        return data.base64EncodedString()
    }

    /// Imzolash paytida tizim Face ID / Touch ID oynasini ko'rsatadi.
    /// Natija: DER (X9.62) ECDSA imzo, SHA-256 xesh bilan.
    static func sign(message: Data, reason: String) throws -> (signature: Data, publicKey: String) {
        let context = LAContext()
        context.localizedReason = reason

        var query = baseQuery()
        query[kSecReturnRef as String] = true
        query[kSecUseAuthenticationContext as String] = context

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess, let ref = item else {
            throw KeyError.message("Key not found (status \(status)). Create the key first.")
        }

        let privateKey = ref as! SecKey
        var error: Unmanaged<CFError>?

        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            message as CFData,
            &error
        ) as Data? else {
            let text = error.map { "\($0.takeRetainedValue())" } ?? "unknown"
            throw KeyError.message("Signing failed: \(text)")
        }

        let publicKey = publicKeyBase64(of: privateKey) ?? ""
        return (signature, publicKey)
    }

    static func deleteKey() -> Bool {
        let status = SecItemDelete(baseQuery() as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
