package company.ize.applecryptointeroperability

import java.security.*
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

//  Created by Zsombor SZABO on 08/03/2019.
//  Copyright © IZE. All rights reserved.
//  See LICENSE.txt for licensing information.
//

/**
 * Given a private key and data to sign, generate a digital signature.
 *
 * Computes digital signature using specified key over input data.  The operation algorithm further
 * defines the exact format of input data, operation to be performed and output signature.
 *
 * @param key Private key with which to sign.
 * @param algorithm One of [SecKeyAlgorithm] constants suitable to generate signature with this key.
 * @param dataToSign The data to be signed, typically the digest of the actual data.
 * @return The signature over [dataToSign] represented by a new ByteArray.
 *
 * @see <a href="https://opensource.apple.com/source/Security/Security-58286.70.7/keychain/SecKey.h.auto.html">SecKey.h</a>
 */
fun SecKeyCreateSignature(key: Key, algorithm: SecKeyAlgorithm, dataToSign: ByteArray): ByteArray {
    when (algorithm) {
        SecKeyAlgorithm.ECDSA_SIGNATURE_DIGEST_X962_SHA256 -> {
            val privateKey = key as? ECPrivateKey ?: throw IllegalArgumentException(
                "Expected EC private key")
            val s = Signature.getInstance("SHA256withECDSA")
            s.initSign(privateKey)
            s.update(dataToSign)
            return s.sign()
        }
        else -> throw IllegalArgumentException("Not supported algorithm")
    }
}

/**
 * Given a public key, data which has been signed, and a signature, verify the signature.
 *
 * Verifies digital signature operation using specified key and signed data.  The operation
 * algorithm further defines the exact format of input data, signature and operation to be
 * performed.
 *
 * @param key Public key with which to verify the signature.
 * @param algorithm One of [SecKeyAlgorithm] constants suitable to verify signature with this key.
 * @param signedData The data over which sig is being verified, typically the digest of the actual
 * data.
 * @param signature The signature to verify.
 * @return True if the signature was valid, False otherwise.
 *
 * @see <a href="https://opensource.apple.com/source/Security/Security-58286.70.7/keychain/SecKey.h.auto.html">SecKey.h</a>
 */
fun SecKeyVerifySignature(key: Key, algorithm: SecKeyAlgorithm, signedData: ByteArray,
                          signature: ByteArray): Boolean {
    when (algorithm) {
        SecKeyAlgorithm.ECDSA_SIGNATURE_DIGEST_X962_SHA256 -> {
            val publicKey = key as? ECPublicKey ?: throw IllegalArgumentException(
                "Expected EC public key")
            val s = Signature.getInstance("SHA256withECDSA")
            s.initVerify(publicKey)
            s.update(signedData)
            return s.verify(signature)
        }
        else -> throw IllegalArgumentException("Not supported algorithm")
    }
}

/**
 * Encrypt a block of plaintext.
 *
 * Encrypts plaintext data using specified key.  The exact type of the operation including the
 * format of input and output data is specified by encryption algorithm.
 *
 * @param key Public key with which to encrypt the data.
 * @param algorithm One of [SecKeyAlgorithm] constants suitable to perform encryption with this key.
 * @param plaintext The data to encrypt. The length and format of the data must conform to chosen
 * algorithm, typically be less or equal to the value returned by SecKeyGetBlockSize().
 * @return The ciphertext represented as a ByteArray.
 *
 * @see <a href="https://opensource.apple.com/source/Security/Security-58286.70.7/keychain/SecKey.h.auto.html">SecKey.h</a>
 */
fun SecKeyCreateEncryptedData(key: Key, algorithm: SecKeyAlgorithm, plaintext: ByteArray)
        : ByteArray {
    when (algorithm) {
        SecKeyAlgorithm.ECIES_ENCRYPTION_STANDARD_VARIABLE_IV_X963_SHA256_AES_GCM -> {
            val publicKey = key as? ECPublicKey ?: throw IllegalArgumentException(
                "Expected EC public key")

            // Generate an ephemeral EC key pair
            val ephemeralEcKeyPairGenerator = KeyPairGenerator.getInstance(
                publicKey.algorithm)
            ephemeralEcKeyPairGenerator.initialize(publicKey.params)
            val ephemeralEcKeyPair = ephemeralEcKeyPairGenerator.generateKeyPair()

            // Use ECDH to generate a symmetric key
            val keyAgreement = KeyAgreement.getInstance("ECDH")
            keyAgreement.init(ephemeralEcKeyPair.private)
            keyAgreement.doPhase(publicKey, true)
            val symmetricKey = keyAgreement.generateSecret()

            // Use SHA256 ANSI x9.63 Key Derivation Function with the ephemeral public key to
            // generate a 32 byte key
            val counterData = byteArrayOf(0x00, 0x00, 0x00, 0x01)
            val sharedInfo = (ephemeralEcKeyPair.public as ECPublicKey)
                .toUncompressedPoint()
            val preHashKey = symmetricKey + counterData + sharedInfo
            val hashedKey = MessageDigest.getInstance("SHA-256").digest(
                preHashKey)

            // Use the first 16 bytes as an AES-GCM key
            val aesGcmKey = SecretKeySpec(hashedKey.copyOfRange(0, 16), "AES")

            // Use the second 16 bytes as the initialization vector (IV)
            val iv = hashedKey.copyOfRange(16, 32)

            // Use AES/GCM/NoPadding to encrypt the plaintext and generate a 16 byte GCM tag
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmParameterSpec = GCMParameterSpec(16 * 8, iv)
            cipher.init(Cipher.ENCRYPT_MODE, aesGcmKey, gcmParameterSpec)
            val encryptedDataAndGcmTag = cipher.doFinal(plaintext)

            // Construct the envelope by combining the ephemeral EC public key, the encrypted data
            // and the GCM tag
            return sharedInfo + encryptedDataAndGcmTag
        }
        else -> throw IllegalArgumentException("Not supported algorithm")
    }
}

/**
 * Decrypt a block of ciphertext.
 *
 * Decrypts ciphertext data using specified key.  The exact type of the operation including the
 * format of input and output data is specified by decryption algorithm.
 *
 * @param key Private key with which to decrypt the data.
 * @param algorithm One of [SecKeyAlgorithm] constants suitable to perform decryption with this key.
 * @param ciphertext The data to decrypt. The length and format of the data must conform to chosen
 * algorithm, typically be less or equal to the value returned by SecKeyGetBlockSize().
 * @return The plaintext represented as a ByteArray.
 *
 * @see <a href="https://opensource.apple.com/source/Security/Security-58286.70.7/keychain/SecKey.h.auto.html">SecKey.h</a>
 */
fun SecKeyCreateDecryptedData(key: Key, algorithm: SecKeyAlgorithm, ciphertext: ByteArray)
        : ByteArray {
    when (algorithm) {
        SecKeyAlgorithm.ECIES_ENCRYPTION_STANDARD_VARIABLE_IV_X963_SHA256_AES_GCM -> {
            val privateKey = key as? ECPrivateKey ?: throw IllegalArgumentException(
                "Expected EC private key")

            // Extract the ephemeral EC public key, the encrypted data and the GCM tag
            val uncompressedPointKeyLengthBytes =
                2*(privateKey.params.order.bitLength() + java.lang.Byte.SIZE - 1) / java.lang.Byte
                    .SIZE
            val sharedInfo = ciphertext.copyOfRange(0, uncompressedPointKeyLengthBytes)
            val ephemeralEcPublicKey = sharedInfo.fromUncompressedPointToECPublicKey()
            val encryptedDataAndGcmTag =
                ciphertext.copyOfRange(uncompressedPointKeyLengthBytes, ciphertext.size)

            // Use ECDH to calculate symmetric key
            val keyAgreement = KeyAgreement.getInstance("ECDH")
            keyAgreement.init(privateKey)
            keyAgreement.doPhase(ephemeralEcPublicKey, true)
            val symmetricKey = keyAgreement.generateSecret()

            // Get AES-GCM key and iv using ANSI x9.63 Key Derivation Function
            val counterData = byteArrayOf(0x00, 0x00, 0x00, 0x01)
            val preHashKey = symmetricKey + counterData + sharedInfo
            val hashedKey = MessageDigest.getInstance("SHA-256").digest(
                preHashKey)

            // Use the first 16 bytes as an AES-GCM key
            val aesGcmKey = SecretKeySpec(hashedKey.copyOfRange(0, 16), "AES")

            // Use the second 16 bytes as the initialization vector (IV)
            val iv = hashedKey.copyOfRange(16, 32)

            // Use AES/GCM/NoPadding to decrypt the encrypted data with GCM tag
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmParameterSpec = GCMParameterSpec(16 * 8, iv)
            cipher.init(Cipher.DECRYPT_MODE, aesGcmKey, gcmParameterSpec)

            return cipher.doFinal(encryptedDataAndGcmTag)
        }
        else -> throw IllegalArgumentException("Not supported algorithm")
    }
}

enum class SecKeyAlgorithm {
    /**
     * kSecKeyAlgorithmECDSASignatureDigestX962SHA256
     */
    ECDSA_SIGNATURE_DIGEST_X962_SHA256,

    /**
     * kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM
     *
    ECIES encryption or decryption.  This algorithm does not limit the size of the message to be encrypted or decrypted.
    Encryption is done using AES-GCM with key negotiated by kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256.  AES Key size
    is 128bit for EC keys <=256bit and 256bit for bigger EC keys.  Ephemeral public key data is used as sharedInfo for KDF,
    and static public key data is used as authenticationData for AES-GCM processing.  AES-GCM uses 16 bytes long TAG, AES key
    is first half of KDF output and 16 byte long IV (initialization vector) is second half of KDF output.
     */
    ECIES_ENCRYPTION_STANDARD_VARIABLE_IV_X963_SHA256_AES_GCM
}
