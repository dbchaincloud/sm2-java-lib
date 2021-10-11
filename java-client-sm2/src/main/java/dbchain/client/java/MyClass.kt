package dbchain.client.java

import dbchain.client.java.sm2.SM2Encrypt
import org.bouncycastle.util.encoders.Hex

fun main() {
    val sm2 = SM2Encrypt()
    DBChain.init(sm2)
    val dbChainKey = MnemonicClient.generateMnemonic()
    val signData = "Hello world".toByteArray()
    val sign = sm2.sign(dbChainKey.privateKeyBytes, signData)
    val verify = sm2.verify(Hex.decode(dbChainKey.publicKey64), signData, sign)
    System.out.println("验证结果：$verify")
}