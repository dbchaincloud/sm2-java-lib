package dbchain.client.java


/**
 * @author: Xiao Bo
 * @date: 13/10/2020
 */
class DBChain {

    companion object {
        lateinit var appCode: String
            private set
        lateinit var dbChainEncrypt: IDBChainEncrypt

        fun init(
            dbChainEncrypt: IDBChainEncrypt,
        ) {
            this.dbChainEncrypt = dbChainEncrypt
        }

        fun withAppCode(appCode: String){
            this.appCode = appCode
        }
    }
}