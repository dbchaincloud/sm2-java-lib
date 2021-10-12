package dbchain.client.java.sm2

import com.gcigb.dbchain.IDBChainEncrypt
import org.bitcoinj.crypto.DeterministicKey
import org.bouncycastle.crypto.params.ECPublicKeyParameters

class SM2Encrypt : IDBChainEncrypt {
    override val pubKeyType: String
        get() = "tendermint/PubKeySm2"

    /**
     * 签名
     * @param privateByteArray ByteArray 私钥 32 个字节
     * @param data ByteArray 明文
     */
    override fun sign(privateByteArray: ByteArray, data: ByteArray): ByteArray {
        val ecPrivateKeyParameters = SM2Util.importPrivateKey(privateByteArray)
        return SM2Util.signDecodeDER(ecPrivateKeyParameters, null, data)
    }

    /**
     * 验证签名
     * @param publicKeyByteArray ByteArray 公钥 64 个字节
     * @param data ByteArray 明文
     * @param sign ByteArray 签名
     * @return Boolean true 通过，否则失败
     */
    override fun verify(publicKeyByteArray: ByteArray, data: ByteArray, sign: ByteArray): Boolean {
        if (publicKeyByteArray.size < 64) return false
        val xByteArray = ByteArray(32)
        val yByteArray = ByteArray(32)
        System.arraycopy(publicKeyByteArray, 0, xByteArray, 0, 32)
        System.arraycopy(publicKeyByteArray, 32, yByteArray, 0, 32)
        val ecPublicKeyParameters = SM2Util.importPublicKey(xByteArray, yByteArray)
        return SM2Util.verify(ecPublicKeyParameters, null, data, SM2Util.encodeSM2SignToDER(sign))
    }

    /**
     * 加密
     * @param publicKeyByteArray ByteArray 公钥 64 个字节
     * @param data ByteArray 明文
     * @return ByteArray 密文
     */
    override fun encrypt(publicKeyByteArray: ByteArray, data: ByteArray): ByteArray {
        if (publicKeyByteArray.size < 64) return ByteArray(0)
        val xByteArray = ByteArray(32)
        val yByteArray = ByteArray(32)
        System.arraycopy(publicKeyByteArray, 0, xByteArray, 0, 32)
        System.arraycopy(publicKeyByteArray, 32, yByteArray, 0, 32)
        val pubKey: ECPublicKeyParameters = SM2Util.importPublicKey(xByteArray, yByteArray)
        return SM2Util.encrypt(pubKey, data)
    }

    /**
     * 解密
     * @param privateByteArray ByteArray 私钥 32 个字节
     * @param data ByteArray 密文
     * @return ByteArray 解密后的明文
     */
    override fun decrypt(privateByteArray: ByteArray, data: ByteArray): ByteArray {
        val priKey = SM2Util.importPrivateKey(privateByteArray)
        return SM2Util.decrypt(priKey, data)
    }

    /**
     * 公钥生成地址
     * @param publicKeyByteArray33 ByteArray 33 个字节的公钥（压缩过的）
     * @return String 地址
     */
    override fun generateAddressByPublicKeyByteArray33(publicKeyByteArray33: ByteArray): String {
        return AddressUtil.generateAddress(publicKeyByteArray33)
    }

    /**
     * 根据私钥生成公钥
     * @param privateByteArray ByteArray 私钥 32 个字节
     * @param dkKey DeterministicKey
     * @return ByteArray
     */
    override fun generatePublicKey33ByPrivateKey(
        privateByteArray: ByteArray,
        dkKey: org.bitcoinj.crypto.DeterministicKey?
    ): ByteArray {
        val ecPrivateKeyParameters = SM2Util.importPrivateKey(privateByteArray)
        val publicKeyXY = SM2Util.getPublicKeyXY(ecPrivateKeyParameters)
        val publicKey = SM2Util.importPublicKey(publicKeyXY.xBytes, publicKeyXY.yBytes)
        return publicKey.q.getEncoded(true)
    }

    /**
     * 根据私钥生成公钥
     * @param privateByteArray ByteArray 私钥 32 个字节
     * @param dkKey DeterministicKey
     * @return ByteArray
     */
    override fun generatePublicKey64ByPrivateKey(
        privateByteArray: ByteArray,
        dkKey: org.bitcoinj.crypto.DeterministicKey?
    ): ByteArray {
        val ecPrivateKeyParameters = SM2Util.importPrivateKey(privateByteArray)
        val publicKeyXY = SM2Util.getPublicKeyXY(ecPrivateKeyParameters)
        val publicKeyByteArray64 = ByteArray(64)
        System.arraycopy(publicKeyXY.xBytes, 0, publicKeyByteArray64, 0, 32)
        System.arraycopy(publicKeyXY.yBytes, 0, publicKeyByteArray64, 32, 32)
        return publicKeyByteArray64
    }
}