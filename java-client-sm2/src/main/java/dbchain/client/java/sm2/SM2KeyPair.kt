package dbchain.client.java.sm2

import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters

class SM2KeyPair(
    val privateKey: ECPrivateKeyParameters,
    val publicKey: ECPublicKeyParameters
)

class PublicKeyXY(
    val xBytes: ByteArray,
    val yBytes: ByteArray
)