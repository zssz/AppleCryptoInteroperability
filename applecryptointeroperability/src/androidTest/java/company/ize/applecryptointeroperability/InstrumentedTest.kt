package company.ize.applecryptointeroperability

import org.junit.Assert
import org.junit.Test
import java.security.Key
import java.util.*

class InstrumentedTest {

    private val plaintext = "Hello, World!".toByteArray()

    private val publicKey = "BBMRAqnDqG1Deru7d51hiOaE0T9sj4nivVH3PAfGJtDbN5uP30m7aZFpcI/qIJju5lE9iz55xIIengu0NqGTdQs="
        .base64Decoded().fromUncompressedPointToECPublicKey()

    private val privateKey = "BBMRAqnDqG1Deru7d51hiOaE0T9sj4nivVH3PAfGJtDbN5uP30m7aZFpcI/qIJju5lE9iz55xIIengu0NqGTdQs/cjiVMrMto+8M2H5VQyjKlHrnBl121xmDIlEKtXnCLA=="
        .base64Decoded().fromUncompressedPointToECPrivateKey()

    @Test
    fun ecKeyConversions() {
        Assert.assertNotNull(publicKey)
        Assert.assertNotNull(privateKey)
    }

    @Test
    fun kSecKeyAlgorithmECDSASignatureDigestX962SHA256() {
        // Signing and verification
        val signature = SecKeyCreateSignature(privateKey as Key,
            SecKeyAlgorithm.ECDSA_SIGNATURE_DIGEST_X962_SHA256, plaintext)
        val valid = SecKeyVerifySignature(publicKey,
            SecKeyAlgorithm.ECDSA_SIGNATURE_DIGEST_X962_SHA256, plaintext, signature)
        Assert.assertTrue(valid)

        // With this algorithm we expect that signatures are different when the same data is signed
        // with the same key
        val otherSignature = SecKeyCreateSignature(privateKey,
            SecKeyAlgorithm.ECDSA_SIGNATURE_DIGEST_X962_SHA256, plaintext)
        Assert.assertFalse(Arrays.equals(otherSignature, signature))

        // Signature sample for our test data made with Apple framework is valid
        val signatureSample = "MEQCIG4bTXvvCbV9c+Fk3Wyx+2eFEzlABkucfvDOXEceHq5JAiA12eHg9kPdBdH6WikqofMDK/fEhfOjC/2fkry20mcpvw=="
            .base64Decoded()
        val validSignatureSample = SecKeyVerifySignature(publicKey,
            SecKeyAlgorithm.ECDSA_SIGNATURE_DIGEST_X962_SHA256, plaintext, signatureSample)
        Assert.assertTrue(validSignatureSample)
    }

    @Test
    fun kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM() {
        // Encryption and decryption
        val encryptedData = SecKeyCreateEncryptedData(publicKey,
            SecKeyAlgorithm.ECIES_ENCRYPTION_STANDARD_VARIABLE_IV_X963_SHA256_AES_GCM, plaintext)
        val decryptedData = SecKeyCreateDecryptedData(privateKey,
            SecKeyAlgorithm.ECIES_ENCRYPTION_STANDARD_VARIABLE_IV_X963_SHA256_AES_GCM,
            encryptedData)
        Assert.assertTrue(Arrays.equals(plaintext, decryptedData))

        // With this algorithm we expect that outputs are different when the same data is
        // encrypted with the same key
        val otherEncryptedData = SecKeyCreateEncryptedData(publicKey,
            SecKeyAlgorithm.ECIES_ENCRYPTION_STANDARD_VARIABLE_IV_X963_SHA256_AES_GCM, plaintext)
        Assert.assertFalse(Arrays.equals(encryptedData, otherEncryptedData))

        // Encrypted data sample of our test data made with Apple framework can be decrypted
        val encryptedDataSample = "BLABoEXShyyRJYaXPmwseK2pVA5AoFgdilIlMb2QA3fquvQ3HWXq8LLG6d/d+7kDeF+ipKsyD8bqieC8JQTCrg2sQBxifQZpM3KG5kdh42VzA1o2DHQoo5nEJ5q0hQ=="
            .base64Decoded()
        val decryptedDataSample = SecKeyCreateDecryptedData(privateKey,
            SecKeyAlgorithm.ECIES_ENCRYPTION_STANDARD_VARIABLE_IV_X963_SHA256_AES_GCM,
            encryptedDataSample)
        Assert.assertTrue(Arrays.equals(plaintext, decryptedDataSample))
    }

}
