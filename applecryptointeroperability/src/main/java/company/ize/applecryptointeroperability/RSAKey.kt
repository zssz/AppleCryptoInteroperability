package company.ize.applecryptointeroperability

import android.security.keystore.KeyProperties
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import java.math.BigInteger
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPrivateKeySpec
import java.security.spec.RSAPublicKeySpec

//  Created by Min Kuan LIM on 27/05/2021.
//  Copyright © IZE. All rights reserved.
//  See LICENSE.txt for licensing information.
//

/**
 * Return the default BER or DER encoding for this key.
 */
fun RSAPublicKey.getAsn1Primitive(): ByteArray = SubjectPublicKeyInfo
    .getInstance(encoded)
    .parsePublicKey()
    .encoded

/**
 * Derive the public key spec by first attempting to convert
 * this key into a [RSAPrivateCrtKey].
 *
 * If it fails, attempt to derive the public exponent by using
 * the most common value (65537).
 *
 * Note: This is not a fool proof solution and can only yield a probabilistic result
 */
fun RSAPrivateKey.derivePublicKeySpec(): RSAPublicKeySpec =
    if (this is RSAPrivateCrtKey) {
        RSAPublicKeySpec(this.modulus, this.publicExponent)
    } else {
        val keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_RSA)
        val rsaPrivateKeySpec = keyFactory.getKeySpec(this, RSAPrivateKeySpec::class.java)
        // Making a wild guess on what might be the public exponent
        // by using the most common value (65537)
        RSAPublicKeySpec(
            rsaPrivateKeySpec.modulus,
            BigInteger.valueOf(65537)
        )
    }

/**
 * Get the derived public key
 *
 * @see [derivePublicKeySpec]
 */
fun RSAPrivateKey.derivePublicKey(): RSAPublicKey {
    val keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_RSA)
    val publicKeySpec = derivePublicKeySpec()
    return keyFactory.generatePublic(publicKeySpec) as RSAPublicKey
}
