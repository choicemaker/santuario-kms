/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.choicemaker.utilcopy01;

//import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.xml.security.algorithms.JCEMapper;
//import org.apache.xml.security.encryption.XMLCipher;
//import org.apache.xml.security.utils.JavaUtils;

//import javax.crypto.Cipher;
//import javax.crypto.KeyGenerator;
//import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
//import java.security.MessageDigest;
//import java.security.NoSuchAlgorithmException;
//import java.security.NoSuchProviderException;

/**
 * Copied from wss4j-ws-security-common-2.1.5-sources.jar, and then pruned, to
 * reduce dependencies of the santuario-kms library.
 */
public final class KeyUtils {
    private static final org.slf4j.Logger LOG =
            org.slf4j.LoggerFactory.getLogger(KeyUtils.class);
    private static final int MAX_SYMMETRIC_KEY_SIZE = 1024;
//    public static final String RSA_ECB_OAEPWITH_SHA1_AND_MGF1_PADDING = "RSA/ECB/OAEPWithSHA1AndMGF1Padding";
//
//    /**
//     * A cached MessageDigest object
//     */
//    private static MessageDigest digest;
//
    private KeyUtils() {
        // complete
    }

    /**
     * Returns the length of the key in # of bytes
     *
     * @param algorithm the URI of the algorithm. See http://www.w3.org/TR/xmlenc-core1/
     * @return the key length
     */
    public static int getKeyLength(String algorithm) throws WSSecurityException {
        return JCEMapper.getKeyLengthFromURI(algorithm) / 8;
    }

    /**
     * Convert the raw key bytes into a SecretKey object of type algorithm.
     */
    public static SecretKey prepareSecretKey(String algorithm, byte[] rawKey) {
        // Do an additional check on the keysize required by the encryption algorithm
        int size = 0;
        try {
            size = getKeyLength(algorithm);
        } catch (Exception e) {
            // ignore - some unknown (to JCEMapper) encryption algorithm
            if (LOG.isDebugEnabled()) {
                LOG.debug(e.getMessage());
            }
        }
        String keyAlgorithm = JCEMapper.getJCEKeyAlgorithmFromURI(algorithm);
        SecretKeySpec keySpec;
        if (size > 0 && !algorithm.endsWith("gcm") && !algorithm.contains("hmac-")) {
            keySpec =
                new SecretKeySpec(
                    rawKey, 0, rawKey.length > size ? size : rawKey.length, keyAlgorithm
                );
        } else if (rawKey.length > MAX_SYMMETRIC_KEY_SIZE) {
            // Prevent a possible attack where a huge secret key is specified
            keySpec =
                new SecretKeySpec(
                    rawKey, 0, MAX_SYMMETRIC_KEY_SIZE, keyAlgorithm
                );
        } else {
            keySpec = new SecretKeySpec(rawKey, keyAlgorithm);
        }
        return keySpec;
    }

//    public static KeyGenerator getKeyGenerator(String algorithm) throws WSSecurityException {
//        try {
//            //
//            // Assume AES as default, so initialize it
//            //
//            String keyAlgorithm = JCEMapper.getJCEKeyAlgorithmFromURI(algorithm);
//            if (keyAlgorithm == null || "".equals(keyAlgorithm)) {
//                keyAlgorithm = JCEMapper.translateURItoJCEID(algorithm);
//            }
//            KeyGenerator keyGen = KeyGenerator.getInstance(keyAlgorithm);
//            if (algorithm.equalsIgnoreCase(XMLCipher.AES_128)
//                || algorithm.equalsIgnoreCase(XMLCipher.AES_128_GCM)) {
//                keyGen.init(128);
//            } else if (algorithm.equalsIgnoreCase(XMLCipher.AES_192)
//                || algorithm.equalsIgnoreCase(XMLCipher.AES_192_GCM)) {
//                keyGen.init(192);
//            } else if (algorithm.equalsIgnoreCase(XMLCipher.AES_256)
//                || algorithm.equalsIgnoreCase(XMLCipher.AES_256_GCM)) {
//                keyGen.init(256);
//            }
//            return keyGen;
//        } catch (NoSuchAlgorithmException e) {
//            throw new WSSecurityException(
//                WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, e
//            );
//        }
//    }
//
//    /**
//     * Translate the "cipherAlgo" URI to a JCE ID, and return a javax.crypto.Cipher instance
//     * of this type.
//     * @param cipherAlgo The cipher in it's WSS URI form,
//     *                   ref. https://www.w3.org/TR/xmlenc-core1/#sec-Algorithms
//     */
//    public static Cipher getCipherInstance(String cipherAlgo)
//        throws WSSecurityException {
//        return getCipherInstance(cipherAlgo, null);
//    }
//
//    /**
//     * Translate the "cipherAlgo" URI to a JCE ID, and request a javax.crypto.Cipher instance
//     * of this type from the given provider.
//     *
//     * @param cipherAlgo The cipher in it's WSS URI form, ref. https://www.w3.org/TR/xmlenc-core1/#sec-Algorithms
//     * @param provider   The provider which shall instantiate the cipher.
//     */
//    public static Cipher getCipherInstance(String cipherAlgo, String provider)
//            throws WSSecurityException {
//        String keyAlgorithm = JCEMapper.translateURItoJCEID(cipherAlgo);
//        if (keyAlgorithm == null) {
//            throw new WSSecurityException(
//                    WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, "unsupportedKeyTransp",
//                    new Object[]{"No such algorithm: \"" + cipherAlgo + "\""});
//        }
//
//        if (provider == null) {
//            provider = JCEMapper.getProviderId();
//        } else {
//            JavaUtils.checkRegisterPermission();
//        }
//
//        try {
//            if (provider == null) {
//                return Cipher.getInstance(keyAlgorithm);
//            } else {
//                return Cipher.getInstance(keyAlgorithm, provider);
//            }
//        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
//            if (XMLCipher.RSA_OAEP.equals(cipherAlgo)) {
//                // Check to see if an RSA OAEP MGF-1 with SHA-1 algorithm was requested
//                // Some JCE implementations don't support RSA/ECB/OAEPPadding (e.g. nCipherKM of Thales)
//                try {
//                    if (provider == null) {
//                        return Cipher.getInstance(RSA_ECB_OAEPWITH_SHA1_AND_MGF1_PADDING);
//                    } else {
//                        return Cipher.getInstance(RSA_ECB_OAEPWITH_SHA1_AND_MGF1_PADDING, provider);
//                    }
//                } catch (NoSuchProviderException ex1) {
//                    throw new WSSecurityException(
//                        WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, ex1, "unsupportedKeyTransp",
//                        new Object[]{
//                            "No such provider \"" + JCEMapper.getProviderId() + "\" for \""
//                                + RSA_ECB_OAEPWITH_SHA1_AND_MGF1_PADDING + "\""
//                        });
//                } catch (NoSuchPaddingException ex1) {
//                    throw new WSSecurityException(
//                        WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, e, "unsupportedKeyTransp",
//                        new Object[]{"No such padding: \"" + RSA_ECB_OAEPWITH_SHA1_AND_MGF1_PADDING + "\""});
//                } catch (NoSuchAlgorithmException ex1) {
//                    throw new WSSecurityException(
//                        WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, e, "unsupportedKeyTransp",
//                        new Object[]{"No such algorithm: \"" + RSA_ECB_OAEPWITH_SHA1_AND_MGF1_PADDING + "\""});
//                }
//            } else {
//                if (e instanceof NoSuchAlgorithmException) {
//                    throw new WSSecurityException(
//                        WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, e, "unsupportedKeyTransp",
//                        new Object[]{"No such algorithm: \"" + keyAlgorithm + "\""});
//                } else {
//                    throw new WSSecurityException(
//                        WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, e, "unsupportedKeyTransp",
//                        new Object[]{"No such padding: \"" + keyAlgorithm + "\""});
//                }
//            }
//        } catch (NoSuchProviderException ex) {
//            throw new WSSecurityException(
//                WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, ex, "unsupportedKeyTransp",
//                new Object[]{"No such provider \"" + JCEMapper.getProviderId() + "\" for \"" + keyAlgorithm + "\""});
//        }
//    }
//
//    /**
//     * Generate a (SHA1) digest of the input bytes. The MessageDigest instance that backs this
//     * method is cached for efficiency.
//     * @param inputBytes the bytes to digest
//     * @return the digest of the input bytes
//     * @throws WSSecurityException
//     */
//    public static synchronized byte[] generateDigest(byte[] inputBytes) throws WSSecurityException {
//        try {
//            if (digest == null) {
//                digest = MessageDigest.getInstance("SHA-1");
//            }
//            return digest.digest(inputBytes);
//        } catch (Exception e) {
//            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e, "empty",
//                                          new Object[] {"Error in generating digest"}
//            );
//        }
//    }
}
