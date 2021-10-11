package dbchain.client.java.sm2

import cloud.dbchain.client.sm2.BCECUtil.buildECPublicKeyByPrivateKey
import cloud.dbchain.client.sm2.BCECUtil.convertPrivateKeyToParameters
import cloud.dbchain.client.sm2.BCECUtil.convertPublicKeyToParameters
import cloud.dbchain.client.sm2.BCECUtil.createECPublicKeyParameters
import cloud.dbchain.client.sm2.BCECUtil.generateKeyPair
import cloud.dbchain.client.sm2.BCECUtil.generateKeyPairParameter
import cloud.dbchain.client.sm2.BCECUtil.getCurveLength
import org.bouncycastle.asn1.*
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.CryptoException
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.engines.SM2Engine
import org.bouncycastle.crypto.params.*
import org.bouncycastle.crypto.signers.SM2Signer
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve
import java.io.IOException
import java.lang.Exception
import java.math.BigInteger
import java.security.*
import java.security.spec.ECFieldFp
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.EllipticCurve

object SM2Util : GMBaseUtil() {
    //////////////////////////////////////////////////////////////////////////////////////
    /*
     * 以下为SM2推荐曲线参数
     */
    val CURVE = SM2P256V1Curve()
    val SM2_ECC_P = CURVE.q
    val SM2_ECC_A = CURVE.a.toBigInteger()
    val SM2_ECC_B = CURVE.b.toBigInteger()
    val SM2_ECC_N = CURVE.order
    val SM2_ECC_H = CURVE.cofactor
    val SM2_ECC_GX = BigInteger(
        "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16
    )
    val SM2_ECC_GY = BigInteger(
        "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16
    )
    val G_POINT = CURVE.createPoint(SM2_ECC_GX, SM2_ECC_GY)
    val DOMAIN_PARAMS = ECDomainParameters(
        CURVE, G_POINT,
        SM2_ECC_N, SM2_ECC_H
    )
    val CURVE_LEN = getCurveLength(DOMAIN_PARAMS)

    //////////////////////////////////////////////////////////////////////////////////////
    val JDK_CURVE = EllipticCurve(ECFieldFp(SM2_ECC_P), SM2_ECC_A, SM2_ECC_B)
    val JDK_G_POINT = ECPoint(
        G_POINT.affineXCoord.toBigInteger(), G_POINT.affineYCoord.toBigInteger()
    )
    val JDK_EC_SPEC = ECParameterSpec(
        JDK_CURVE, JDK_G_POINT, SM2_ECC_N, SM2_ECC_H.toInt()
    )

    //////////////////////////////////////////////////////////////////////////////////////
    const val SM3_DIGEST_LENGTH = 32

    /**
     * 生成ECC密钥对
     *
     * @return ECC密钥对
     */
    fun generateSM2KeyPair(): SM2KeyPair {
        val random = SecureRandom()
        val keyPair = generateKeyPairParameter(DOMAIN_PARAMS, random)
        val priKey = keyPair.private as ECPrivateKeyParameters
        val pubKey = keyPair.public as ECPublicKeyParameters
        return SM2KeyPair(priKey, pubKey)
    }

    /**
     * 生成ECC密钥对
     *
     * @return
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    @Throws(
        NoSuchProviderException::class,
        NoSuchAlgorithmException::class,
        InvalidAlgorithmParameterException::class
    )
    fun generateKeyPair(): KeyPair {
        val random = SecureRandom()
        return generateKeyPair(DOMAIN_PARAMS, random)
    }

    /**
     * 导入私钥
     *
     * @param privateKeyD ECPrivateKeyParameters.d
     * @return
     */
    fun importPrivateKey(privateKeyD: ByteArray?): ECPrivateKeyParameters {
        return ECPrivateKeyParameters(BigInteger(1, privateKeyD), DOMAIN_PARAMS)
    }

    /**
     * 导入公钥
     *
     * @param xBytes
     * @param yBytes
     * @return
     */
    fun importPublicKey(xBytes: ByteArray?, yBytes: ByteArray?): ECPublicKeyParameters {
        return createECPublicKeyParameters(
            xBytes!!,
            yBytes!!, CURVE, DOMAIN_PARAMS
        )
    }

    /**
     * 根据私钥获取公钥
     *
     * @param ecPrivateKeyParameters
     * @return
     */
    fun getECPublicKeyByPrivateKey(ecPrivateKeyParameters: ECPrivateKeyParameters?): ECPublicKeyParameters {
        return buildECPublicKeyByPrivateKey(ecPrivateKeyParameters!!)
    }

    /**
     * 根据私钥获取公钥 x,y 值
     *
     * @param ecPrivateKeyParameters
     * @return
     */
    fun getPublicKeyXY(ecPrivateKeyParameters: ECPrivateKeyParameters?): PublicKeyXY {
        return getPublicKeyXY(
            buildECPublicKeyByPrivateKey(
                ecPrivateKeyParameters!!
            )
        )
    }

    /**
     * 获取私钥字节流
     *
     * @param privateKeyParameters
     * @return
     */
    fun getPrivateKeyBytes(privateKeyParameters: ECPrivateKeyParameters): ByteArray {
        return privateKeyParameters.d.toByteArray()
    }

    /**
     * ECPublicKeyParameters 转为 x,y 值
     *
     * @param publicKeyParameters
     * @return
     */
    fun getPublicKeyXY(publicKeyParameters: ECPublicKeyParameters): PublicKeyXY {
        val x = publicKeyParameters.q.affineXCoord.encoded
        val y = publicKeyParameters.q.affineYCoord.encoded
        return PublicKeyXY(x, y)
    }

    /**
     * 只获取私钥里的d值，32字节
     *
     * @param privateKey
     * @return
     */
    fun getRawPrivateKey(privateKey: BCECPrivateKey): ByteArray {
        return fixToCurveLengthBytes(privateKey.d.toByteArray())
    }

    /**
     * 只获取公钥里的XY分量，64字节
     *
     * @param publicKey
     * @return 64字节数组
     */
    fun getRawPublicKey(publicKey: BCECPublicKey): ByteArray {
        val src65 = publicKey.q.getEncoded(false)
        val rawXY = ByteArray(CURVE_LEN * 2) //SM2的话这里应该是64字节
        System.arraycopy(src65, 1, rawXY, 0, rawXY.size)
        return rawXY
    }

    /**
     * @param pubKey  公钥
     * @param srcData 原文
     * @return 默认输出C1C3C2顺序的密文。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @throws InvalidCipherTextException
     */
    @Throws(InvalidCipherTextException::class)
    fun encrypt(pubKey: BCECPublicKey?, srcData: ByteArray): ByteArray {
        val pubKeyParameters = convertPublicKeyToParameters(
            pubKey!!
        )
        return encrypt(SM2Engine.Mode.C1C3C2, pubKeyParameters, srcData)
    }

    /**
     * @param mode    指定密文结构，旧标准的为C1C2C3，新的[《SM2密码算法使用规范》 GM/T 0009-2012]标准为C1C3C2
     * @param pubKey  公钥
     * @param srcData 原文
     * @return 根据mode不同，输出的密文C1C2C3排列顺序不同。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @throws InvalidCipherTextException
     */
    @Throws(InvalidCipherTextException::class)
    fun encrypt(mode: SM2Engine.Mode?, pubKey: BCECPublicKey?, srcData: ByteArray): ByteArray {
        val pubKeyParameters = convertPublicKeyToParameters(
            pubKey!!
        )
        return encrypt(mode, pubKeyParameters, srcData)
    }

    /**
     * @param pubKeyParameters 公钥
     * @param srcData          原文
     * @return 默认输出C1C3C2顺序的密文。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @throws InvalidCipherTextException
     */
    @Throws(InvalidCipherTextException::class)
    fun encrypt(pubKeyParameters: ECPublicKeyParameters?, srcData: ByteArray): ByteArray {
        return encrypt(SM2Engine.Mode.C1C3C2, pubKeyParameters, srcData)
    }

    /**
     * @param mode             指定密文结构，旧标准的为C1C2C3，新的[《SM2密码算法使用规范》 GM/T 0009-2012]标准为C1C3C2
     * @param pubKeyParameters 公钥
     * @param srcData          原文
     * @return 根据mode不同，输出的密文C1C2C3排列顺序不同。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @throws InvalidCipherTextException
     */
    @Throws(InvalidCipherTextException::class)
    fun encrypt(
        mode: SM2Engine.Mode?,
        pubKeyParameters: ECPublicKeyParameters?,
        srcData: ByteArray
    ): ByteArray {
        val engine = SM2Engine(mode)
        val pwr = ParametersWithRandom(pubKeyParameters, SecureRandom())
        engine.init(true, pwr)
        return engine.processBlock(srcData, 0, srcData.size)
    }

    /**
     * @param priKey    私钥
     * @param sm2Cipher 默认输入C1C3C2顺序的密文。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return 原文。SM2解密返回了数据则一定是原文，因为SM2自带校验，如果密文被篡改或者密钥对不上，都是会直接报异常的。
     * @throws InvalidCipherTextException
     */
    @Throws(InvalidCipherTextException::class)
    fun decrypt(priKey: BCECPrivateKey?, sm2Cipher: ByteArray): ByteArray {
        val priKeyParameters = convertPrivateKeyToParameters(
            priKey!!
        )
        return decrypt(SM2Engine.Mode.C1C3C2, priKeyParameters, sm2Cipher)
    }

    /**
     * @param mode      指定密文结构，旧标准的为C1C2C3，新的[《SM2密码算法使用规范》 GM/T 0009-2012]标准为C1C3C2
     * @param priKey    私钥
     * @param sm2Cipher 根据mode不同，需要输入的密文C1C2C3排列顺序不同。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return 原文。SM2解密返回了数据则一定是原文，因为SM2自带校验，如果密文被篡改或者密钥对不上，都是会直接报异常的。
     * @throws InvalidCipherTextException
     */
    @Throws(InvalidCipherTextException::class)
    fun decrypt(mode: SM2Engine.Mode?, priKey: BCECPrivateKey?, sm2Cipher: ByteArray): ByteArray {
        val priKeyParameters = convertPrivateKeyToParameters(
            priKey!!
        )
        return decrypt(mode, priKeyParameters, sm2Cipher)
    }

    /**
     * @param priKeyParameters 私钥
     * @param sm2Cipher        默认输入C1C3C2顺序的密文。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return 原文。SM2解密返回了数据则一定是原文，因为SM2自带校验，如果密文被篡改或者密钥对不上，都是会直接报异常的。
     * @throws InvalidCipherTextException
     */
    @Throws(InvalidCipherTextException::class)
    fun decrypt(priKeyParameters: ECPrivateKeyParameters?, sm2Cipher: ByteArray): ByteArray {
        return decrypt(SM2Engine.Mode.C1C3C2, priKeyParameters, sm2Cipher)
    }

    /**
     * @param mode             指定密文结构，旧标准的为C1C2C3，新的[《SM2密码算法使用规范》 GM/T 0009-2012]标准为C1C3C2
     * @param priKeyParameters 私钥
     * @param sm2Cipher        根据mode不同，需要输入的密文C1C2C3排列顺序不同。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return 原文。SM2解密返回了数据则一定是原文，因为SM2自带校验，如果密文被篡改或者密钥对不上，都是会直接报异常的。
     * @throws InvalidCipherTextException
     */
    @Throws(InvalidCipherTextException::class)
    fun decrypt(
        mode: SM2Engine.Mode?,
        priKeyParameters: ECPrivateKeyParameters?,
        sm2Cipher: ByteArray
    ): ByteArray {
        val engine = SM2Engine(mode)
        engine.init(false, priKeyParameters)
        return engine.processBlock(sm2Cipher, 0, sm2Cipher.size)
    }

    /**
     * 分解SM2密文
     *
     * @param cipherText 默认输入C1C3C2顺序的密文。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return
     * @throws Exception
     */
    @Throws(Exception::class)
    fun parseSM2Cipher(cipherText: ByteArray): SM2Cipher {
        val curveLength = getCurveLength(DOMAIN_PARAMS)
        return parseSM2Cipher(SM2Engine.Mode.C1C3C2, curveLength, SM3_DIGEST_LENGTH, cipherText)
    }

    /**
     * 分解SM2密文
     *
     * @param mode       指定密文结构，旧标准的为C1C2C3，新的[《SM2密码算法使用规范》 GM/T 0009-2012]标准为C1C3C2
     * @param cipherText 根据mode不同，需要输入的密文C1C2C3排列顺序不同。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return
     */
    @Throws(Exception::class)
    fun parseSM2Cipher(mode: SM2Engine.Mode, cipherText: ByteArray): SM2Cipher {
        val curveLength = getCurveLength(DOMAIN_PARAMS)
        return parseSM2Cipher(mode, curveLength, SM3_DIGEST_LENGTH, cipherText)
    }

    /**
     * @param curveLength  曲线长度，SM2的话就是256位。
     * @param digestLength 摘要长度，如果是SM2的话因为默认使用SM3摘要，SM3摘要长度为32字节。
     * @param cipherText   默认输入C1C3C2顺序的密文。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return
     * @throws Exception
     */
    @Throws(Exception::class)
    fun parseSM2Cipher(
        curveLength: Int, digestLength: Int, cipherText: ByteArray
    ): SM2Cipher {
        return parseSM2Cipher(SM2Engine.Mode.C1C3C2, curveLength, digestLength, cipherText)
    }

    /**
     * 分解SM2密文
     *
     * @param mode         指定密文结构，旧标准的为C1C2C3，新的[《SM2密码算法使用规范》 GM/T 0009-2012]标准为C1C3C2
     * @param curveLength  曲线长度，SM2的话就是256位。
     * @param digestLength 摘要长度，如果是SM2的话因为默认使用SM3摘要，SM3摘要长度为32字节。
     * @param cipherText   根据mode不同，需要输入的密文C1C2C3排列顺序不同。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return
     */
    @Throws(Exception::class)
    fun parseSM2Cipher(
        mode: SM2Engine.Mode, curveLength: Int, digestLength: Int,
        cipherText: ByteArray
    ): SM2Cipher {
        val c1 = ByteArray(curveLength * 2 + 1)
        val c2 = ByteArray(cipherText.size - c1.size - digestLength)
        val c3 = ByteArray(digestLength)
        System.arraycopy(cipherText, 0, c1, 0, c1.size)
        if (mode == SM2Engine.Mode.C1C2C3) {
            System.arraycopy(cipherText, c1.size, c2, 0, c2.size)
            System.arraycopy(cipherText, c1.size + c2.size, c3, 0, c3.size)
        } else if (mode == SM2Engine.Mode.C1C3C2) {
            System.arraycopy(cipherText, c1.size, c3, 0, c3.size)
            System.arraycopy(cipherText, c1.size + c3.size, c2, 0, c2.size)
        } else {
            throw Exception("Unsupported mode:$mode")
        }
        val result = SM2Cipher()
        result.c1 = c1
        result.c2 = c2
        result.c3 = c3
        result.cipherText = cipherText
        return result
    }

    /**
     * DER编码密文
     *
     * @param cipher 默认输入C1C3C2顺序的密文。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return DER编码后的密文
     * @throws IOException
     */
    @Throws(Exception::class)
    fun encodeSM2CipherToDER(cipher: ByteArray): ByteArray {
        val curveLength = getCurveLength(DOMAIN_PARAMS)
        return encodeSM2CipherToDER(SM2Engine.Mode.C1C3C2, curveLength, SM3_DIGEST_LENGTH, cipher)
    }

    /**
     * DER编码密文
     *
     * @param mode   指定密文结构，旧标准的为C1C2C3，新的[《SM2密码算法使用规范》 GM/T 0009-2012]标准为C1C3C2
     * @param cipher 根据mode不同，需要输入的密文C1C2C3排列顺序不同。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return 按指定mode DER编码后的密文
     * @throws Exception
     */
    @Throws(Exception::class)
    fun encodeSM2CipherToDER(mode: SM2Engine.Mode, cipher: ByteArray): ByteArray {
        val curveLength = getCurveLength(DOMAIN_PARAMS)
        return encodeSM2CipherToDER(mode, curveLength, SM3_DIGEST_LENGTH, cipher)
    }

    /**
     * DER编码密文
     *
     * @param curveLength  曲线长度，SM2的话就是256位。
     * @param digestLength 摘要长度，如果是SM2的话因为默认使用SM3摘要，SM3摘要长度为32字节。
     * @param cipher       默认输入C1C3C2顺序的密文。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return 默认输出按C1C3C2编码的结果
     * @throws IOException
     */
    @Throws(Exception::class)
    fun encodeSM2CipherToDER(curveLength: Int, digestLength: Int, cipher: ByteArray): ByteArray {
        return encodeSM2CipherToDER(SM2Engine.Mode.C1C3C2, curveLength, digestLength, cipher)
    }

    /**
     * @param mode         指定密文结构，旧标准的为C1C2C3，新的[《SM2密码算法使用规范》 GM/T 0009-2012]标准为C1C3C2
     * @param curveLength  曲线长度，SM2的话就是256位。
     * @param digestLength 摘要长度，如果是SM2的话因为默认使用SM3摘要，SM3摘要长度为32字节。
     * @param cipher       根据mode不同，需要输入的密文C1C2C3排列顺序不同。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @return 按指定mode DER编码后的密文
     * @throws Exception
     */
    @Throws(Exception::class)
    fun encodeSM2CipherToDER(
        mode: SM2Engine.Mode,
        curveLength: Int,
        digestLength: Int,
        cipher: ByteArray
    ): ByteArray {
        val c1x = ByteArray(curveLength)
        val c1y = ByteArray(curveLength)
        val c2 = ByteArray(cipher.size - c1x.size - c1y.size - 1 - digestLength)
        val c3 = ByteArray(digestLength)
        var startPos = 1
        System.arraycopy(cipher, startPos, c1x, 0, c1x.size)
        startPos += c1x.size
        System.arraycopy(cipher, startPos, c1y, 0, c1y.size)
        startPos += c1y.size
        if (mode == SM2Engine.Mode.C1C2C3) {
            System.arraycopy(cipher, startPos, c2, 0, c2.size)
            startPos += c2.size
            System.arraycopy(cipher, startPos, c3, 0, c3.size)
        } else if (mode == SM2Engine.Mode.C1C3C2) {
            System.arraycopy(cipher, startPos, c3, 0, c3.size)
            startPos += c3.size
            System.arraycopy(cipher, startPos, c2, 0, c2.size)
        } else {
            throw Exception("Unsupported mode:$mode")
        }
        val arr = arrayOfNulls<ASN1Encodable>(4)
        // c1x,c1y的第一个bit可能为1，这个时候要确保他们表示的大数一定是正数，所以new BigInteger符号强制设为正。
        arr[0] = ASN1Integer(BigInteger(1, c1x))
        arr[1] = ASN1Integer(BigInteger(1, c1y))
        if (mode == SM2Engine.Mode.C1C2C3) {
            arr[2] = DEROctetString(c2)
            arr[3] = DEROctetString(c3)
        } else if (mode == SM2Engine.Mode.C1C3C2) {
            arr[2] = DEROctetString(c3)
            arr[3] = DEROctetString(c2)
        }
        val ds = DERSequence(arr)
        return ds.getEncoded(ASN1Encoding.DER)
    }

    /**
     * 解码DER密文
     *
     * @param derCipher 默认输入按C1C3C2顺序DER编码的密文
     * @return 输出按C1C3C2排列的字节数组，C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     */
    @Throws(Exception::class)
    fun decodeDERSM2Cipher(derCipher: ByteArray?): ByteArray {
        return decodeDERSM2Cipher(SM2Engine.Mode.C1C3C2, derCipher)
    }

    /**
     * @param mode      指定密文结构，旧标准的为C1C2C3，新的[《SM2密码算法使用规范》 GM/T 0009-2012]标准为C1C3C2
     * @param derCipher 根据mode输入C1C2C3或C1C3C2顺序DER编码后的密文
     * @return 根据mode不同，输出的密文C1C2C3排列顺序不同。C1为65字节第1字节为压缩标识，这里固定为0x04，后面64字节为xy分量各32字节。C3为32字节。C2长度与原文一致。
     * @throws Exception
     */
    @Throws(Exception::class)
    fun decodeDERSM2Cipher(mode: SM2Engine.Mode, derCipher: ByteArray?): ByteArray {
        val `as` = DERSequence.getInstance(derCipher)
        var c1x = (`as`.getObjectAt(0) as ASN1Integer).value.toByteArray()
        var c1y = (`as`.getObjectAt(1) as ASN1Integer).value.toByteArray()
        // c1x，c1y可能因为大正数的补0规则在第一个有效字节前面插了一个(byte)0，变成33个字节，在这里要修正回32个字节去
        c1x = fixToCurveLengthBytes(c1x)
        c1y = fixToCurveLengthBytes(c1y)
        val c3: ByteArray
        val c2: ByteArray
        if (mode == SM2Engine.Mode.C1C2C3) {
            c2 = (`as`.getObjectAt(2) as DEROctetString).octets
            c3 = (`as`.getObjectAt(3) as DEROctetString).octets
        } else if (mode == SM2Engine.Mode.C1C3C2) {
            c3 = (`as`.getObjectAt(2) as DEROctetString).octets
            c2 = (`as`.getObjectAt(3) as DEROctetString).octets
        } else {
            throw Exception("Unsupported mode:$mode")
        }
        var pos = 0
        val cipherText = ByteArray(1 + c1x.size + c1y.size + c2.size + c3.size)
        val uncompressedFlag: Byte = 0x04
        cipherText[0] = uncompressedFlag
        pos += 1
        System.arraycopy(c1x, 0, cipherText, pos, c1x.size)
        pos += c1x.size
        System.arraycopy(c1y, 0, cipherText, pos, c1y.size)
        pos += c1y.size
        if (mode == SM2Engine.Mode.C1C2C3) {
            System.arraycopy(c2, 0, cipherText, pos, c2.size)
            pos += c2.size
            System.arraycopy(c3, 0, cipherText, pos, c3.size)
        } else if (mode == SM2Engine.Mode.C1C3C2) {
            System.arraycopy(c3, 0, cipherText, pos, c3.size)
            pos += c3.size
            System.arraycopy(c2, 0, cipherText, pos, c2.size)
        }
        return cipherText
    }

    /**
     * 签名
     *
     * @param priKey  私钥
     * @param srcData 原文
     * @return DER编码后的签名值
     * @throws CryptoException
     */
    @Throws(CryptoException::class)
    fun sign(priKey: BCECPrivateKey?, srcData: ByteArray): ByteArray {
        val priKeyParameters = convertPrivateKeyToParameters(
            priKey!!
        )
        return sign(priKeyParameters, null, srcData)
    }

    /**
     * 签名
     * 不指定withId，则默认withId为字节数组:"1234567812345678".getBytes()
     *
     * @param priKeyParameters 私钥
     * @param srcData          原文
     * @return DER编码后的签名值
     * @throws CryptoException
     */
    @Throws(CryptoException::class)
    fun sign(priKeyParameters: ECPrivateKeyParameters?, srcData: ByteArray): ByteArray {
        return sign(priKeyParameters, null, srcData)
    }

    /**
     * 私钥签名
     *
     * @param priKey  私钥
     * @param withId  可以为null，若为null，则默认withId为字节数组:"1234567812345678".getBytes()
     * @param srcData 原文
     * @return DER编码后的签名值
     * @throws CryptoException
     */
    @Throws(CryptoException::class)
    fun sign(priKey: BCECPrivateKey?, withId: ByteArray?, srcData: ByteArray): ByteArray {
        val priKeyParameters = convertPrivateKeyToParameters(
            priKey!!
        )
        return sign(priKeyParameters, withId, srcData)
    }

    /**
     * 签名
     *
     * @param priKeyParameters 私钥
     * @param withId           可以为null，若为null，则默认withId为字节数组:"1234567812345678".getBytes()
     * @param srcData          源数据
     * @return DER编码后的签名值
     * @throws CryptoException
     */
    @Throws(CryptoException::class)
    fun sign(
        priKeyParameters: ECPrivateKeyParameters?,
        withId: ByteArray?,
        srcData: ByteArray
    ): ByteArray {
        val signer = SM2Signer()
        var param: CipherParameters? = null
        val pwr = ParametersWithRandom(priKeyParameters, SecureRandom())
        param = if (withId != null) {
            ParametersWithID(pwr, withId)
        } else {
            pwr
        }
        signer.init(true, param)
        signer.update(srcData, 0, srcData.size)
        return signer.generateSignature()
    }

    @Throws(CryptoException::class)
    fun signDecodeDER(
        priKeyParameters: ECPrivateKeyParameters?,
        withId: ByteArray?,
        srcData: ByteArray
    ): ByteArray {
        return decodeDERSM2Sign(sign(priKeyParameters, null, srcData))
    }

    /**
     * 将DER编码的SM2签名解码成64字节的纯R+S字节流
     *
     * @param derSign
     * @return 64字节数组，前32字节为R，后32字节为S
     */
    fun decodeDERSM2Sign(derSign: ByteArray?): ByteArray {
        val `as` = DERSequence.getInstance(derSign)
        var rBytes = (`as`.getObjectAt(0) as ASN1Integer).value.toByteArray()
        var sBytes = (`as`.getObjectAt(1) as ASN1Integer).value.toByteArray()
        //由于大数的补0规则，所以可能会出现33个字节的情况，要修正回32个字节
        rBytes = fixToCurveLengthBytes(rBytes)
        sBytes = fixToCurveLengthBytes(sBytes)
        val rawSign = ByteArray(rBytes.size + sBytes.size)
        System.arraycopy(rBytes, 0, rawSign, 0, rBytes.size)
        System.arraycopy(sBytes, 0, rawSign, rBytes.size, sBytes.size)
        return rawSign
    }

    /**
     * 把64字节的纯R+S字节数组编码成DER编码
     *
     * @param rawSign 64字节数组形式的SM2签名值，前32字节为R，后32字节为S
     * @return DER编码后的SM2签名值
     * @throws IOException
     */
    @Throws(IOException::class)
    fun encodeSM2SignToDER(rawSign: ByteArray): ByteArray {
        //要保证大数是正数
        val r = BigInteger(1, extractBytes(rawSign, 0, 32))
        val s = BigInteger(1, extractBytes(rawSign, 32, 32))
        val v = ASN1EncodableVector()
        v.add(ASN1Integer(r))
        v.add(ASN1Integer(s))
        return DERSequence(v).getEncoded(ASN1Encoding.DER)
    }

    /**
     * 验签
     *
     * @param pubKey  公钥
     * @param srcData 原文
     * @param sign    DER编码的签名值
     * @return
     */
    fun verify(pubKey: BCECPublicKey?, srcData: ByteArray, sign: ByteArray?): Boolean {
        val pubKeyParameters = convertPublicKeyToParameters(
            pubKey!!
        )
        return verify(pubKeyParameters, null, srcData, sign)
    }

    /**
     * 验签
     * 不指定withId，则默认withId为字节数组:"1234567812345678".getBytes()
     *
     * @param pubKeyParameters 公钥
     * @param srcData          原文
     * @param sign             DER编码的签名值
     * @return 验签成功返回true，失败返回false
     */
    fun verify(
        pubKeyParameters: ECPublicKeyParameters?,
        srcData: ByteArray,
        sign: ByteArray?
    ): Boolean {
        return verify(pubKeyParameters, null, srcData, sign)
    }

    /**
     * 验签
     *
     * @param pubKey  公钥
     * @param withId  可以为null，若为null，则默认withId为字节数组:"1234567812345678".getBytes()
     * @param srcData 原文
     * @param sign    DER编码的签名值
     * @return
     */
    fun verify(
        pubKey: BCECPublicKey?,
        withId: ByteArray?,
        srcData: ByteArray,
        sign: ByteArray?
    ): Boolean {
        val pubKeyParameters = convertPublicKeyToParameters(
            pubKey!!
        )
        return verify(pubKeyParameters, withId, srcData, sign)
    }

    /**
     * 验签
     *
     * @param pubKeyParameters 公钥
     * @param withId           可以为null，若为null，则默认withId为字节数组:"1234567812345678".getBytes()
     * @param srcData          原文
     * @param sign             DER编码的签名值
     * @return 验签成功返回true，失败返回false
     */
    fun verify(
        pubKeyParameters: ECPublicKeyParameters?,
        withId: ByteArray?,
        srcData: ByteArray,
        sign: ByteArray?
    ): Boolean {
        val signer = SM2Signer()
        val param: CipherParameters?
        param = if (withId != null) {
            ParametersWithID(pubKeyParameters, withId)
        } else {
            pubKeyParameters
        }
        signer.init(false, param)
        signer.update(srcData, 0, srcData.size)
        return signer.verifySignature(sign)
    }

    private fun extractBytes(src: ByteArray, offset: Int, length: Int): ByteArray {
        val result = ByteArray(length)
        System.arraycopy(src, offset, result, 0, result.size)
        return result
    }

    private fun fixToCurveLengthBytes(src: ByteArray): ByteArray {
        if (src.size == CURVE_LEN) {
            return src
        }
        val result = ByteArray(CURVE_LEN)
        if (src.size > CURVE_LEN) {
            System.arraycopy(src, src.size - result.size, result, 0, result.size)
        } else {
            System.arraycopy(src, 0, result, result.size - src.size, src.size)
        }
        return result
    }
}