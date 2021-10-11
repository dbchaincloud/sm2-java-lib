package cloud.dbchain.client.sm2

import dbchain.client.java.sm2.SM2Util
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x9.X962Parameters
import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.asn1.x9.X9ECPoint
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.*
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.bouncycastle.math.ec.ECCurve
import org.bouncycastle.math.ec.FixedPointCombMultiplier
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemReader
import org.bouncycastle.util.io.pem.PemWriter
import java.io.*
import java.lang.IllegalArgumentException
import java.math.BigInteger
import java.security.*
import java.security.spec.*


/**
 * 这个工具类的方法，也适用于其他基于BC库的ECC算法
 */
object BCECUtil {
    private const val ALGO_NAME_EC = "EC"
    private const val PEM_STRING_PUBLIC = "PUBLIC KEY"
    private const val PEM_STRING_ECPRIVATEKEY = "EC PRIVATE KEY"

    /**
     * 生成ECC密钥对
     *
     * @return ECC密钥对
     */
    fun generateKeyPairParameter(
        domainParameters: ECDomainParameters?, random: SecureRandom?
    ): AsymmetricCipherKeyPair {
        val keyGenerationParams = ECKeyGenerationParameters(
            domainParameters,
            random
        )
        val keyGen = ECKeyPairGenerator()
        keyGen.init(keyGenerationParams)
        return keyGen.generateKeyPair()
    }

    @Throws(
        NoSuchProviderException::class,
        NoSuchAlgorithmException::class,
        InvalidAlgorithmParameterException::class
    )
    fun generateKeyPair(domainParameters: ECDomainParameters, random: SecureRandom?): KeyPair {
        val kpg = KeyPairGenerator.getInstance(ALGO_NAME_EC, BouncyCastleProvider.PROVIDER_NAME)
        val parameterSpec = org.bouncycastle.jce.spec.ECParameterSpec(
            domainParameters.curve, domainParameters.g,
            domainParameters.n, domainParameters.h
        )
        kpg.initialize(parameterSpec, random)
        return kpg.generateKeyPair()
    }

    fun getCurveLength(ecKey: ECKeyParameters): Int {
        return getCurveLength(ecKey.parameters)
    }

    fun getCurveLength(domainParams: ECDomainParameters): Int {
        return (domainParams.curve.fieldSize + 7) / 8
    }

    fun fixToCurveLengthBytes(curveLength: Int, src: ByteArray): ByteArray {
        if (src.size == curveLength) {
            return src
        }
        val result = ByteArray(curveLength)
        if (src.size > curveLength) {
            System.arraycopy(src, src.size - result.size, result, 0, result.size)
        } else {
            System.arraycopy(src, 0, result, result.size - src.size, src.size)
        }
        return result
    }

    /**
     * @param dHex             十六进制字符串形式的私钥d值，如果是SM2算法，Hex字符串长度应该是64（即32字节）
     * @param domainParameters EC Domain参数，一般是固定的，如果是SM2算法的可参考[]
     * @return
     */
    fun createECPrivateKeyParameters(
        dHex: String?, domainParameters: ECDomainParameters?
    ): ECPrivateKeyParameters {
        return createECPrivateKeyParameters(ByteUtils.fromHexString(dHex), domainParameters)
    }

    /**
     * @param dBytes           字节数组形式的私钥d值，如果是SM2算法，应该是32字节
     * @param domainParameters EC Domain参数，一般是固定的，如果是SM2算法的可参考[]
     * @return
     */
    fun createECPrivateKeyParameters(
        dBytes: ByteArray?, domainParameters: ECDomainParameters?
    ): ECPrivateKeyParameters {
        return createECPrivateKeyParameters(BigInteger(1, dBytes), domainParameters)
    }

    /**
     * @param d                大数形式的私钥d值
     * @param domainParameters EC Domain参数，一般是固定的，如果是SM2算法的可参考[com]
     * @return
     */
    fun createECPrivateKeyParameters(
        d: BigInteger?, domainParameters: ECDomainParameters?
    ): ECPrivateKeyParameters {
        return ECPrivateKeyParameters(d, domainParameters)
    }

    /**
     * 根据EC私钥构造EC公钥
     *
     * @param priKey ECC私钥参数对象
     * @return
     */
    fun buildECPublicKeyByPrivateKey(priKey: ECPrivateKeyParameters): ECPublicKeyParameters {
        val domainParameters = priKey.parameters
        val q = FixedPointCombMultiplier().multiply(domainParameters.g, priKey.d)
        return ECPublicKeyParameters(q, domainParameters)
    }

    /**
     * @param x                大数形式的公钥x分量
     * @param y                大数形式的公钥y分量
     * @param curve            EC曲线参数，一般是固定的，如果是SM2算法的可参考[]
     * @param domainParameters EC Domain参数，一般是固定的，如果是SM2算法的可参考[]
     * @return
     */
    fun createECPublicKeyParameters(
        x: BigInteger, y: BigInteger, curve: ECCurve, domainParameters: ECDomainParameters
    ): ECPublicKeyParameters {
        return createECPublicKeyParameters(
            x.toByteArray(),
            y.toByteArray(),
            curve,
            domainParameters
        )
    }

    /**
     * @param xHex             十六进制形式的公钥x分量，如果是SM2算法，Hex字符串长度应该是64（即32字节）
     * @param yHex             十六进制形式的公钥y分量，如果是SM2算法，Hex字符串长度应该是64（即32字节）
     * @param curve            EC曲线参数，一般是固定的，如果是SM2算法的可参考[]
     * @param domainParameters EC Domain参数，一般是固定的，如果是SM2算法的可参考[]
     * @return
     */
    fun createECPublicKeyParameters(
        xHex: String?, yHex: String?, curve: ECCurve, domainParameters: ECDomainParameters
    ): ECPublicKeyParameters {
        return createECPublicKeyParameters(
            ByteUtils.fromHexString(xHex), ByteUtils.fromHexString(yHex),
            curve, domainParameters
        )
    }

    /**
     * @param xBytes           十六进制形式的公钥x分量，如果是SM2算法，应该是32字节
     * @param yBytes           十六进制形式的公钥y分量，如果是SM2算法，应该是32字节
     * @param curve            EC曲线参数，一般是固定的，如果是SM2算法的可参考[]
     * @param domainParameters EC Domain参数，一般是固定的，如果是SM2算法的可参考[]
     * @return
     */
    fun createECPublicKeyParameters(
        xBytes: ByteArray, yBytes: ByteArray, curve: ECCurve, domainParameters: ECDomainParameters
    ): ECPublicKeyParameters {
        var xBytes = xBytes
        var yBytes = yBytes
        val uncompressedFlag: Byte = 0x04
        val curveLength = getCurveLength(domainParameters)
        xBytes = fixToCurveLengthBytes(curveLength, xBytes)
        yBytes = fixToCurveLengthBytes(curveLength, yBytes)
        val encodedPubKey = ByteArray(1 + xBytes.size + yBytes.size)
        encodedPubKey[0] = uncompressedFlag
        System.arraycopy(xBytes, 0, encodedPubKey, 1, xBytes.size)
        System.arraycopy(yBytes, 0, encodedPubKey, 1 + xBytes.size, yBytes.size)
        return ECPublicKeyParameters(curve.decodePoint(encodedPubKey), domainParameters)
    }

    fun convertPrivateKeyToParameters(ecPriKey: BCECPrivateKey): ECPrivateKeyParameters {
        val parameterSpec = ecPriKey.parameters
        val domainParameters = ECDomainParameters(
            parameterSpec.curve, parameterSpec.g,
            parameterSpec.n, parameterSpec.h
        )
        return ECPrivateKeyParameters(ecPriKey.d, domainParameters)
    }

    fun convertPublicKeyToParameters(ecPubKey: BCECPublicKey): ECPublicKeyParameters {
        val parameterSpec = ecPubKey.parameters
        val domainParameters = ECDomainParameters(
            parameterSpec.curve, parameterSpec.g,
            parameterSpec.n, parameterSpec.h
        )
        return ECPublicKeyParameters(ecPubKey.q, domainParameters)
    }

    @Throws(
        NoSuchProviderException::class,
        NoSuchAlgorithmException::class,
        InvalidKeySpecException::class,
        IOException::class
    )
    fun createPublicKeyFromSubjectPublicKeyInfo(subPubInfo: SubjectPublicKeyInfo): BCECPublicKey {
        return convertX509ToECPublicKey(subPubInfo.toASN1Primitive().getEncoded(ASN1Encoding.DER))
    }

    /**
     * 将ECC私钥转换为PKCS8标准的字节流
     *
     * @param priKey
     * @param pubKey 可以为空，但是如果为空的话得到的结果OpenSSL可能解析不了
     * @return
     */
    fun convertECPrivateKeyToPKCS8(
        priKey: ECPrivateKeyParameters, pubKey: ECPublicKeyParameters?
    ): ByteArray {
        val domainParams = priKey.parameters
        val spec = org.bouncycastle.jce.spec.ECParameterSpec(
            domainParams.curve, domainParams.g,
            domainParams.n, domainParams.h
        )
        var publicKey: BCECPublicKey? = null
        if (pubKey != null) {
            publicKey = BCECPublicKey(
                ALGO_NAME_EC, pubKey, spec,
                BouncyCastleProvider.CONFIGURATION
            )
        }
        val privateKey = BCECPrivateKey(
            ALGO_NAME_EC, priKey, publicKey,
            spec, BouncyCastleProvider.CONFIGURATION
        )
        return privateKey.encoded
    }

    /**
     * 将PKCS8标准的私钥字节流转换为私钥对象
     *
     * @param pkcs8Key
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeySpecException
     */
    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        InvalidKeySpecException::class
    )
    fun convertPKCS8ToECPrivateKey(pkcs8Key: ByteArray?): BCECPrivateKey {
        val peks = PKCS8EncodedKeySpec(pkcs8Key)
        val kf = KeyFactory.getInstance(ALGO_NAME_EC, BouncyCastleProvider.PROVIDER_NAME)
        return kf.generatePrivate(peks) as BCECPrivateKey
    }

    /**
     * 将PKCS8标准的私钥字节流转换为PEM
     *
     * @param encodedKey
     * @return
     * @throws IOException
     */
    @Throws(IOException::class)
    fun convertECPrivateKeyPKCS8ToPEM(encodedKey: ByteArray): String {
        return convertEncodedDataToPEM(PEM_STRING_ECPRIVATEKEY, encodedKey)
    }

    /**
     * 将PEM格式的私钥转换为PKCS8标准字节流
     *
     * @param pemString
     * @return
     * @throws IOException
     */
    @Throws(IOException::class)
    fun convertECPrivateKeyPEMToPKCS8(pemString: String): ByteArray {
        return convertPEMToEncodedData(pemString)
    }

    /**
     * 将ECC私钥转换为SEC1标准的字节流
     * openssl d2i_ECPrivateKey函数要求的DER编码的私钥也是SEC1标准的，
     * 这个工具函数的主要目的就是为了能生成一个openssl可以直接“识别”的ECC私钥.
     * 相对RSA私钥的PKCS1标准，ECC私钥的标准为SEC1
     *
     * @param priKey
     * @param pubKey
     * @return
     * @throws IOException
     */
    @Throws(IOException::class)
    fun convertECPrivateKeyToSEC1(
        priKey: ECPrivateKeyParameters,
        pubKey: ECPublicKeyParameters?
    ): ByteArray {
        val pkcs8Bytes = convertECPrivateKeyToPKCS8(priKey, pubKey)
        val pki =
            PrivateKeyInfo.getInstance(pkcs8Bytes)
        val encodable = pki.parsePrivateKey()
        val primitive = encodable.toASN1Primitive()
        return primitive.encoded
    }

    /**
     * 将SEC1标准的私钥字节流恢复为PKCS8标准的字节流
     *
     * @param sec1Key
     * @return
     * @throws IOException
     */
    @Throws(IOException::class)
    fun convertECPrivateKeySEC1ToPKCS8(sec1Key: ByteArray?): ByteArray {
        /**
         * 参考org.bouncycastle.asn1.pkcs.PrivateKeyInfo和
         * org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey，逆向拼装
         */
        val params = getDomainParametersFromName(SM2Util.JDK_EC_SPEC, false)
        val privKey: ASN1OctetString = DEROctetString(sec1Key)
        val v = ASN1EncodableVector()
        v.add(ASN1Integer(0)) //版本号
        v.add(AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params)) //算法标识
        v.add(privKey)
        val ds = DERSequence(v)
        return ds.getEncoded(ASN1Encoding.DER)
    }

    /**
     * 将SEC1标准的私钥字节流转为BCECPrivateKey对象
     *
     * @param sec1Key
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeySpecException
     * @throws IOException
     */
    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        InvalidKeySpecException::class,
        IOException::class
    )
    fun convertSEC1ToBCECPrivateKey(sec1Key: ByteArray?): BCECPrivateKey {
        val peks = PKCS8EncodedKeySpec(convertECPrivateKeySEC1ToPKCS8(sec1Key))
        val kf = KeyFactory.getInstance(ALGO_NAME_EC, BouncyCastleProvider.PROVIDER_NAME)
        return kf.generatePrivate(peks) as BCECPrivateKey
    }

    /**
     * 将SEC1标准的私钥字节流转为ECPrivateKeyParameters对象
     * openssl i2d_ECPrivateKey函数生成的DER编码的ecc私钥是：SEC1标准的、带有EC_GROUP、带有公钥的，
     * 这个工具函数的主要目的就是为了使Java程序能够“识别”openssl生成的ECC私钥
     *
     * @param sec1Key
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeySpecException
     */
    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        InvalidKeySpecException::class,
        IOException::class
    )
    fun convertSEC1ToECPrivateKey(sec1Key: ByteArray?): ECPrivateKeyParameters {
        val privateKey = convertSEC1ToBCECPrivateKey(sec1Key)
        return convertPrivateKeyToParameters(privateKey)
    }

    /**
     * 将ECC公钥对象转换为X509标准的字节流
     *
     * @param pubKey
     * @return
     */
    fun convertECPublicKeyToX509(pubKey: ECPublicKeyParameters): ByteArray {
        val domainParams = pubKey.parameters
        val spec = org.bouncycastle.jce.spec.ECParameterSpec(
            domainParams.curve, domainParams.g,
            domainParams.n, domainParams.h
        )
        val publicKey = BCECPublicKey(
            ALGO_NAME_EC, pubKey, spec,
            BouncyCastleProvider.CONFIGURATION
        )
        return publicKey.encoded
    }

    /**
     * 将X509标准的公钥字节流转为公钥对象
     *
     * @param x509Bytes
     * @return
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    @Throws(
        NoSuchProviderException::class,
        NoSuchAlgorithmException::class,
        InvalidKeySpecException::class
    )
    fun convertX509ToECPublicKey(x509Bytes: ByteArray?): BCECPublicKey {
        val eks = X509EncodedKeySpec(x509Bytes)
        val kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
        return kf.generatePublic(eks) as BCECPublicKey
    }

    /**
     * 将X509标准的公钥字节流转为PEM
     *
     * @param encodedKey
     * @return
     * @throws IOException
     */
    @Throws(IOException::class)
    fun convertECPublicKeyX509ToPEM(encodedKey: ByteArray): String {
        return convertEncodedDataToPEM(PEM_STRING_PUBLIC, encodedKey)
    }

    /**
     * 将PEM格式的公钥转为X509标准的字节流
     *
     * @param pemString
     * @return
     * @throws IOException
     */
    @Throws(IOException::class)
    fun convertECPublicKeyPEMToX509(pemString: String): ByteArray {
        return convertPEMToEncodedData(pemString)
    }

    /**
     * copy from BC
     *
     * @param genSpec
     * @return
     */
    fun getDomainParametersFromGenSpec(genSpec: ECGenParameterSpec): X9ECParameters {
        return getDomainParametersFromName(genSpec.name)
    }

    /**
     * copy from BC
     *
     * @param curveName
     * @return
     */
    fun getDomainParametersFromName(curveName: String): X9ECParameters {
        var curveName = curveName
        var domainParameters: X9ECParameters
        try {
            if (curveName[0] >= '0' && curveName[0] <= '2') {
                val oidID = ASN1ObjectIdentifier(curveName)
                domainParameters = ECUtil.getNamedCurveByOid(oidID)
            } else {
                if (curveName.indexOf(' ') > 0) {
                    curveName = curveName.substring(curveName.indexOf(' ') + 1)
                    domainParameters = ECUtil.getNamedCurveByName(curveName)
                } else {
                    domainParameters = ECUtil.getNamedCurveByName(curveName)
                }
            }
        } catch (ex: IllegalArgumentException) {
            domainParameters = ECUtil.getNamedCurveByName(curveName)
        }
        return domainParameters
    }

    /**
     * copy from BC
     *
     * @param ecSpec
     * @param withCompression
     * @return
     */
    fun getDomainParametersFromName(
        ecSpec: ECParameterSpec?, withCompression: Boolean
    ): X962Parameters {
        val params: X962Parameters
        if (ecSpec is ECNamedCurveSpec) {
            var curveOid = ECUtil.getNamedCurveOid(
                ecSpec.name
            )
            if (curveOid == null) {
                curveOid = ASN1ObjectIdentifier(ecSpec.name)
            }
            params = X962Parameters(curveOid)
        } else if (ecSpec == null) {
            params = X962Parameters(DERNull.INSTANCE)
        } else {
            val curve = EC5Util.convertCurve(ecSpec.curve)
            val ecP = X9ECParameters(
                curve,
                X9ECPoint(EC5Util.convertPoint(curve, ecSpec.generator), withCompression),
                ecSpec.order,
                BigInteger.valueOf(ecSpec.cofactor.toLong()),
                ecSpec.curve.seed
            )

            //// 如果是1.62或更低版本的bcprov-jdk15on应该使用以下这段代码，因为高版本的EC5Util.convertPoint没有向下兼容
            /*
            X9ECParameters ecP = new X9ECParameters(
                curve,
                EC5Util.convertPoint(curve, ecSpec.getGenerator(), withCompression),
                ecSpec.getOrder(),
                BigInteger.valueOf(ecSpec.getCofactor()),
                ecSpec.getCurve().getSeed());
            */params = X962Parameters(ecP)
        }
        return params
    }

    @Throws(IOException::class)
    private fun convertEncodedDataToPEM(type: String, encodedData: ByteArray): String {
        val bOut = ByteArrayOutputStream()
        val pWrt = PemWriter(OutputStreamWriter(bOut))
        try {
            val pemObj = PemObject(type, encodedData)
            pWrt.writeObject(pemObj)
        } finally {
            pWrt.close()
        }
        return String(bOut.toByteArray())
    }

    @Throws(IOException::class)
    private fun convertPEMToEncodedData(pemString: String): ByteArray {
        val bIn = ByteArrayInputStream(pemString.toByteArray())
        val pRdr = PemReader(InputStreamReader(bIn))
        return try {
            val pemObject = pRdr.readPemObject()
            pemObject.content
        } finally {
            pRdr.close()
        }
    }
}
