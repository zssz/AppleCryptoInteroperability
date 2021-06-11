package company.ize.applecryptointeroperability

import org.junit.Assert
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class RSAInstrumentedTest {
    private val plaintext = "Hello, World!".toByteArray()

    private fun kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM(
        publicKey: RSAPublicKey,
        privateKey: RSAPrivateKey
    ) {
        // Encryption and decryption
        val encryptedData = SecKeyCreateEncryptedData(publicKey,
            SecKeyAlgorithm.RSA_ENCRYPTION_OAEP_SHA_256_AES_GCM, plaintext)
        val decryptedData = SecKeyCreateDecryptedData(privateKey,
            SecKeyAlgorithm.RSA_ENCRYPTION_OAEP_SHA_256_AES_GCM, encryptedData)
        Assert.assertTrue(decryptedData.contentEquals(plaintext))

        // With this algorithm we expect that outputs are different when the same data is
        // encrypted with the same key
        val otherEncryptedData = SecKeyCreateEncryptedData(publicKey,
            SecKeyAlgorithm.RSA_ENCRYPTION_OAEP_SHA_256_AES_GCM, plaintext)
        Assert.assertFalse(otherEncryptedData.contentEquals(encryptedData))
    }

    @Test
    fun kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM_RSA2048() {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA").apply {
            initialize(2048)
        }
        val keyPair = keyPairGenerator.generateKeyPair()
        val publicKey = keyPair.public as RSAPublicKey
        val privateKey = keyPair.private as RSAPrivateKey

        kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM(publicKey, privateKey)
    }

    @Test
    fun kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM_RSA4096() {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA").apply {
            initialize(4096)
        }
        val keyPair = keyPairGenerator.generateKeyPair()
        val publicKey = keyPair.public as RSAPublicKey
        val privateKey = keyPair.private as RSAPrivateKey

        kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM(publicKey, privateKey)
    }
}