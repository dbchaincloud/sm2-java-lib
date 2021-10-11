/*
 * Copyright 2013, 2014 Megion Research & Development GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dbchain.client.java.sm2;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Various hashing utilities used in the Bitcoin system.
 */
public class HashUtils {

    private static final String SHA256 = "SHA-256";

    private static MessageDigest getSha256Digest() {
        try {
            return MessageDigest.getInstance(SHA256);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e); //cannot happen
        }
    }

    /**
     * Calculate the RipeMd160 value of the SHA-256 of an array of bytes. This is
     * how a Bitcoin address is derived from public key bytes.
     *
     * @param pubkeyBytes A Bitcoin public key as an array of bytes.
     * @return The Bitcoin address as an array of bytes.
     */
    public static byte[] addressHash(byte[] pubkeyBytes) {
        byte[] sha256 = getSha256Digest().digest(pubkeyBytes);
        if (sha256.length < 20) {
            return new byte[]{};
        }
        byte[] out = new byte[20];
        System.arraycopy(sha256, 0, out, 0, 20);
        return out;
    }

}
