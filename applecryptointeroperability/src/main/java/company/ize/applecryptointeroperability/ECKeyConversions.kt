package company.ize.applecryptointeroperability

import java.math.BigInteger
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.util.*
import java.security.AlgorithmParameters
import java.security.interfaces.ECPrivateKey
import java.security.spec.*

//  Created by Zsombor SZABO on 08/03/2019.
//  Copyright © IZE. All rights reserved.
//  See LICENSE.txt for licensing information.
//  

fun ECPublicKey.toUncompressedPoint(): ByteArray {
    val keySizeBytes =
        (params.order.bitLength() + java.lang.Byte.SIZE - 1) / java.lang.Byte.SIZE

    val uncompressedPoint = ByteArray(1 + 2 * keySizeBytes)
    var offset = 0
    uncompressedPoint[offset++] = 0x04

    val x = w.affineX.toByteArray()
    if (x.size <= keySizeBytes) {
        System.arraycopy(x, 0, uncompressedPoint, offset + keySizeBytes - x.size,
            x.size)
    } else if (x.size == keySizeBytes + 1 && x[0].toInt() == 0) {
        System.arraycopy(x, 1, uncompressedPoint, offset, keySizeBytes)
    } else {
        throw IllegalStateException("x value is too large")
    }
    offset += keySizeBytes

    val y = w.affineY.toByteArray()
    if (y.size <= keySizeBytes) {
        System.arraycopy(y, 0, uncompressedPoint, offset + keySizeBytes - y.size,
            y.size)
    } else if (y.size == keySizeBytes + 1 && y[0].toInt() == 0) {
        System.arraycopy(y, 1, uncompressedPoint, offset, keySizeBytes)
    } else {
        throw IllegalStateException("y value is too large")
    }

    return uncompressedPoint
}

fun ByteArray.fromUncompressedPointToECPublicKey(): ECPublicKey {
    val uncompressedPointIndicator: Byte = 0x04
    if (this[0] != uncompressedPointIndicator) {
        throw IllegalArgumentException("Invalid encoding, no uncompressed point indicator")
    }
    val keySizeLengthBytes = (this.size - 1) / 2
    val standardName: String
    when (keySizeLengthBytes * 8) {
        256 -> standardName = "secp256r1"
        384 -> standardName = "secp384r1"
        else -> throw IllegalArgumentException("Invalid encoding, not the correct size")
    }
    val parameters = AlgorithmParameters.getInstance("EC")
    parameters.init(ECGenParameterSpec(standardName))
    val ecParameterSpec = parameters.getParameterSpec(ECParameterSpec::class.java)
    val x = BigInteger(1, Arrays.copyOfRange(this, 1,
        1 + keySizeLengthBytes))
    val y = BigInteger(1, Arrays.copyOfRange(this, 1 + keySizeLengthBytes,
        this.size))
    val ecPublicKeySpec = ECPublicKeySpec(ECPoint(x, y), ecParameterSpec)
    val keyFactory = KeyFactory.getInstance("EC")
    return keyFactory.generatePublic(ecPublicKeySpec) as ECPublicKey
}

fun ByteArray.fromUncompressedPointToECPrivateKey(): ECPrivateKey {
    val uncompressedPointIndicator: Byte = 0x04
    if (this[0] != uncompressedPointIndicator) {
        throw IllegalArgumentException("Invalid encoding, no uncompressed point indicator")
    }
    val keySizeLengthBytes = (this.size - 1) / 3
    val standardName: String
    when (keySizeLengthBytes * 8) {
        256 -> standardName = "secp256r1"
        384 -> standardName = "secp384r1"
        else -> throw IllegalArgumentException("Invalid encoding, not the correct size")
    }
    val parameters = AlgorithmParameters.getInstance("EC")
    parameters.init(ECGenParameterSpec(standardName))
    val ecParameterSpec = parameters.getParameterSpec(ECParameterSpec::class.java)
    val s = BigInteger(1, Arrays.copyOfRange(this, 1 + 2 * keySizeLengthBytes,
        this.size))
    val ecPrivateKeySpec = ECPrivateKeySpec(s, ecParameterSpec)
    val keyFactory = KeyFactory.getInstance("EC")
    return keyFactory.generatePrivate(ecPrivateKeySpec) as ECPrivateKey
}
