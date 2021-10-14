package dbchain.example.java.sm2

import android.app.Application
import com.gcigb.dbchain.DBChain
import com.gcigb.dbchain.ILog
import com.gcigb.dbchain.MnemonicClient
import dbchain.client.java.sm2.SM2Encrypt

class BaseApplication:Application() {

    override fun onCreate() {
        super.onCreate()
        init()
    }

    private fun init() {
        val appCode = "Your AppCode"
        val baseUrl = "http://192.168.0.19:3001/relay/"
        val chainId = "testnet"
        val debug = true
        DBChain.init(
            appCode = appCode,
            baseUrl = baseUrl,
            chainId = chainId,
            isDebug = debug,
            dbChainEncrypt = SM2Encrypt(),
            iLog = LogImpl(),
            defaultGasNumber = 200000
        )
        // val dbChainKey = MnemonicClient.generateMnemonic()
        val list = listOf(
            "drastic",
            "horse",
            "focus",
            "about",
            "know",
            "bone",
            "trophy",
            "seek",
            "insane",
            "thing",
            "clump",
            "same"
        )
        val dbChainKey = MnemonicClient.importMnemonic(list)
        DBChain.withDBChainKey(dbChainKey)
    }

    class LogImpl : ILog {
        override fun logHttp(msg: String) {
            println("http: $msg")
        }

        override fun logV(tag: String, msg: String) {
            println("$tag: $msg")
        }

        override fun logD(tag: String, msg: String) {
            println("$tag: $msg")
        }

        override fun logI(msg: String) {
            println(msg)
        }

        override fun logI(any: Any) {
            println("$any")
        }

        override fun logI(tag: String, msg: String) {
            println("$tag: $msg")
        }

        override fun logW(tag: String, msg: String) {
            println("$tag: $msg")
        }

        override fun logE(msg: String) {
            println(msg)
        }

        override fun logE(tag: String, msg: String) {
            println("$tag: $msg")
        }

    }
}