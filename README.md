# AppleCryptoInteroperability
[![Build Status](https://travis-ci.org/zssz/AppleCryptoInteroperability.svg?branch=master)](https://travis-ci.org/zssz/AppleCryptoInteroperability) [![Platform](https://img.shields.io/badge/platform-Android-brightgreen.svg)](https://developer.android.com) [![Language](https://img.shields.io/badge/language-Kotlin-orange.svg)](https://kotlinlang.org) [![Documented](https://img.shields.io/badge/documented-%E2%9C%93-brightgreen.svg)]() [![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-blue.svg?style=flat)](https://www.apache.org/licenses/LICENSE-2.0)

Cryptographic interoperability between Android and iOS.

This project's goal is to provide Android equivalents of the cryptographic functions inside Apple's [Security framework](https://developer.apple.com/documentation/security) for the purpose of easy cryptographic interoperability.

## Examples

### Signature / Verification

#### iOS 

```swift
let plaintext: NSData = ...
let privateKey: SecKey = ...
let publicKey: SecKey = ...
let signature = SecKeyCreateSignature(privateKey, .ecdsaSignatureDigestX962SHA256, plaintext.sha256Digest() as CFData, nil)
let valid = SecKeyVerifySignature(publicKey, .ecdsaSignatureDigestX962SHA256, plaintext.sha256Digest() as CFData, signature as CFData, nil)
XCTAssertTrue(valid)
```

#### Android Equivalent

```kotlin
val plaintext: ByteArray = ...
val privateKey: ECPrivateKey = ...
val publicKey: ECPublicKey = ...
val signature = SecKeyCreateSignature(privateKey, SecKeyAlgorithm.ECDSA_SIGNATURE_DIGEST_X962_SHA256, plaintext)
val valid = SecKeyVerifySignature(publicKey, SecKeyAlgorithm.ECDSA_SIGNATURE_DIGEST_X962_SHA256, plaintext, signature)
Assert.assertTrue(valid)
```

### Encryption / Decryption

#### iOS

```swift
let plaintext: NSData = ...
let privateKey: SecKey = ...
let publicKey: SecKey = ...
let encryptedData = SecKeyCreateEncryptedData(publicKey, .eciesEncryptionStandardVariableIVX963SHA256AESGCM, plaintext as CFData, nil)
let decryptedData = SecKeyCreateDecryptedData(privateKey, .eciesEncryptionStandardVariableIVX963SHA256AESGCM, encryptedData as CFData, nil)
XCTAssertTrue(plaintext == decryptedData)
```

#### Android

```kotlin
val plaintext: ByteArray = ...
val privateKey: ECPrivateKey = ...
val publicKey: ECPublicKey = ...
val encryptedData = SecKeyCreateEncryptedData(publicKey, SecKeyAlgorithm.ECIES_ENCRYPTION_STANDARD_VARIABLE_IV_X963_SHA256_AES_GCM, plaintext)
val decryptedData = SecKeyCreateDecryptedData(privateKey, SecKeyAlgorithm.ECIES_ENCRYPTION_STANDARD_VARIABLE_IV_X963_SHA256_AES_GCM, encryptedData)
Assert.assertTrue(Arrays.equals(plaintext, decryptedData))
```

## Supported SecKey Algorithms

### Signature / Verification

- [kSecKeyAlgorithmECDSASignatureDigestX962SHA256](https://developer.apple.com/documentation/security/kseckeyalgorithmecdsasignaturedigestx962sha256?language=objc)

### Encryption / Decryption

- [kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM](https://developer.apple.com/documentation/security/kseckeyalgorithmeciesencryptionstandardvariableivx963sha256aesgcm?language=objc)
  
## Requirements

### Build

This software was built using [Android Studio](https://developer.android.com/studio) 3.3.2 on macOS 10.14.3 with the Android 28 SDK. You should be able to open the project and run the tests. Note: before running the local unit tests, run the instrumented tests first.

### Runtime  

Minimum Android 26 SDK

## Contributing

Contributions are welcome!

## Acknowledgement

This project was inspired by [BlueECC](https://github.com/IBM-Swift/BlueECC).

## License

This software is distributed under the terms and conditions of the [Apache License 2.0](LICENSE.txt).
