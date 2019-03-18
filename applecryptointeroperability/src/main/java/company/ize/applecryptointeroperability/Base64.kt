package company.ize.applecryptointeroperability

//import android.util.Base64
import java.util.*

//  Created by Zsombor SZABO on 13/03/2019.
//  Copyright © IZE. All rights reserved.
//  See LICENSE.txt for licensing information.
//

fun ByteArray.base64EncodedString(): String {
//    return Base64.encodeToString(this, Base64.DEFAULT)
    return Base64.getEncoder().encodeToString(this)
}

fun String.base64Decoded(): ByteArray {
//    return Base64.decode(this, Base64.DEFAULT)
    return Base64.getDecoder().decode(this)
}
