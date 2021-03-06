/*
 *  Copyright 2006-2021 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.json;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import java.security.interfaces.ECKey;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.webpki.crypto.CryptoRandom;
import org.webpki.crypto.KeyAlgorithms;

import org.webpki.util.ArrayUtil;

/**
 * Core JEF (JSON Encryption Format) class.
 * Implements a subset of the RFC 7516 (JWE) algorithms.
 * 
 * Source configured for Android. 
 */
class EncryptionCore {

    /**
     * Return object for symmetric key encryptions.
     */
    static class SymmetricEncryptionResult {
        byte[] tag;
        byte[] cipherText;

        SymmetricEncryptionResult(byte[] tag, byte[] cipherText) {
            this.tag = tag;
            this.cipherText = cipherText;
        }

        byte[] getTag() {
            return tag;
        }

        byte[] getCipherText() {
            return cipherText;
        }
    }

    /**
     * Return object for ECDH and RSA encryptions.
     */
    static class AsymmetricEncryptionResult {

        private byte[] dataEncryptionKey;
        private byte[] encryptedKeyData;
        private PublicKey ephemeralKey;

        AsymmetricEncryptionResult(byte[] dataEncryptionKey,
                                   byte[] encryptedKeyData,
                                   PublicKey ephemeralKey) {
            this.dataEncryptionKey = dataEncryptionKey;
            this.encryptedKeyData = encryptedKeyData;
            this.ephemeralKey = ephemeralKey;
        }

        byte[] getDataEncryptionKey() {
            return dataEncryptionKey;
        }

        byte[] getEncryptedKeyData() {
            return encryptedKeyData;
        }

        PublicKey getEphemeralKey() {
            return ephemeralKey;
        }
    }
    
    private EncryptionCore() {} // Static and final class
    
    // AES CBC static
    static final int    AES_CBC_IV_LENGTH        = 16; 
    static final String AES_CBC_JCENAME          = "AES/CBC/PKCS5Padding";

    // AES GCM static
    static final int    AES_GCM_IV_LENGTH        = 12;
    static final int    AES_GCM_TAG_LENGTH       = 16;
    static final String AES_GCM_JCENAME          = "AES/GCM/NoPadding";

    // AES Key Wrap static
    static final String AES_KEY_WRAP_JCENAME      = "AESWrap";

    // NIST Concat KDF static
    static final String CONCAT_KDF_DIGEST_JCENAME = "SHA-256";
    static final int    CONCAT_KDF_DIGEST_LENGTH  = 32;
    
    // RSA OAEP
    static final String JOSE_RSA_OAEP_JCENAME     = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    static final String JOSE_RSA_OAEP_256_JCENAME = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private static Cipher getAesCipher(String algorithm) throws GeneralSecurityException {
        return Cipher.getInstance(algorithm);
    }

    private static byte[] getTag(byte[] key,
                                 byte[] cipherText,
                                 byte[] iv,
                                 byte[] authData,
                                 DataEncryptionAlgorithms dataEncryptionAlgorithm) 
    throws GeneralSecurityException {
        int tagLength = dataEncryptionAlgorithm.tagLength;
        byte[] al = new byte[8];
        int value = authData.length * 8;
        for (int q = 24, i = 4; q >= 0; q -= 8, i++) {
            al[i] = (byte) (value >>> q);
        }
        Mac mac = Mac.getInstance(dataEncryptionAlgorithm.jceNameOfTagHmac);
        mac.init(new SecretKeySpec(key, 0, tagLength, "RAW"));
        mac.update(authData);
        mac.update(iv);
        mac.update(cipherText);
        mac.update(al);
        byte[] tag = new byte[tagLength];
        System.arraycopy(mac.doFinal(), 0, tag, 0, tagLength);
        return tag;
    }
    
    private static byte[] aesCbcCore(int mode, 
                                     byte[] key, 
                                     byte[] iv, 
                                     byte[] data, 
                                     DataEncryptionAlgorithms dataEncryptionAlgorithm)
    throws GeneralSecurityException {
        Cipher cipher = getAesCipher(AES_CBC_JCENAME);
        int aesKeyLength = dataEncryptionAlgorithm.keyLength / 2;
        cipher.init(mode, new SecretKeySpec(key, aesKeyLength, aesKeyLength, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    private static byte[] aesGcmCore(int mode, byte[] key, byte[] iv, byte[] authData, byte[] data)
    throws GeneralSecurityException {
        Cipher cipher = getAesCipher(AES_GCM_JCENAME);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(AES_GCM_TAG_LENGTH * 8, iv);
        cipher.init(mode, new SecretKeySpec(key, "AES"), gcmSpec);
        cipher.updateAAD(authData);
        return cipher.doFinal(data);
    }

    private static void check(byte[] parameter,
                              String parameterName,
                              int expectedLength,
                              DataEncryptionAlgorithms dataEncryptionAlgorithm)
            throws GeneralSecurityException {
        if (parameter == null) {
            throw new GeneralSecurityException("Parameter \"" + parameterName +
                                               "\"=null for " +
                                               dataEncryptionAlgorithm);
        }
        if (parameter.length != expectedLength) {
            throw new GeneralSecurityException("Incorrect parameter \"" + parameterName +
                                               "\" length (" + parameter.length + ") for " +
                                               dataEncryptionAlgorithm);
        }
    }
 
    static byte[] createIv(DataEncryptionAlgorithms dataEncryptionAlgorithm) {
        return CryptoRandom.generateRandom(dataEncryptionAlgorithm.ivLength);
    }

    /**
     * Perform a symmetric key encryption.
     * @param dataEncryptionAlgorithm Algorithm to use
     * @param key Encryption key
     * @param iv Initialization vector
     * @param plainText The data to be encrypted
     * @param authData Additional input factor for authentication
     * @return A composite object including encrypted data
     * @throws GeneralSecurityException &nbsp;
     */
    public static SymmetricEncryptionResult 
            dataEncryption(DataEncryptionAlgorithms dataEncryptionAlgorithm,
                           byte[] key,
                           byte[] iv,
                           byte[] plainText,
                           byte[] authData) throws GeneralSecurityException {
        check(key, "key", dataEncryptionAlgorithm.keyLength, dataEncryptionAlgorithm);
        if (dataEncryptionAlgorithm.gcm) {
            byte[] cipherOutput = aesGcmCore(Cipher.ENCRYPT_MODE, key, iv, authData, plainText);
            int tagPos = cipherOutput.length - AES_GCM_TAG_LENGTH;
            byte[] cipherText = ArrayUtil.copy(cipherOutput, tagPos);
            byte[] tag = new byte[AES_GCM_TAG_LENGTH];
            System.arraycopy(cipherOutput, tagPos, tag, 0, AES_GCM_TAG_LENGTH);
            return new SymmetricEncryptionResult(tag, cipherText);
        }
        byte[] cipherText = aesCbcCore(Cipher.ENCRYPT_MODE,
                                       key,
                                       iv, 
                                       plainText, 
                                       dataEncryptionAlgorithm);
        return new SymmetricEncryptionResult(getTag(key, 
                                                    cipherText, 
                                                    iv,
                                                    authData, 
                                                    dataEncryptionAlgorithm), 
                                              cipherText);
    }

    /**
     * Decrypt using a symmetric key.
     * @param dataEncryptionAlgorithm Algorithm to use
     * @param key The encryption key
     * @param cipherText The data to be decrypted
     * @param iv Initialization Vector
     * @param authData Additional input used for authentication purposes
     * @param tag Authentication tag
     * @return The data in clear
     * @throws GeneralSecurityException &nbsp;
     */
    public static byte[] dataDecryption(DataEncryptionAlgorithms dataEncryptionAlgorithm,
                                        byte[] key,
                                        byte[] cipherText,
                                        byte[] iv,
                                        byte[] authData,
                                        byte[] tag) throws GeneralSecurityException {
        check(key, "key", dataEncryptionAlgorithm.keyLength, dataEncryptionAlgorithm);
        check(iv, "iv", dataEncryptionAlgorithm.ivLength, dataEncryptionAlgorithm);
        check(tag, "tag", dataEncryptionAlgorithm.tagLength, dataEncryptionAlgorithm);
        if (dataEncryptionAlgorithm.gcm) {
            return aesGcmCore(Cipher.DECRYPT_MODE, 
                              key, 
                              iv, 
                              authData, 
                              ArrayUtil.add(cipherText, tag));
        }
        if (!ArrayUtil.compare(tag, getTag(key, 
                                           cipherText,
                                           iv, 
                                           authData,
                                           dataEncryptionAlgorithm))) {
            throw new GeneralSecurityException("Authentication error on algorithm: " + 
                                               dataEncryptionAlgorithm);
        }
        return aesCbcCore(Cipher.DECRYPT_MODE, 
                          key, 
                          iv, 
                          cipherText, 
                          dataEncryptionAlgorithm);
    }

    private static byte[] rsaCore(int mode,
                                  Key key,
                                  byte[] data,
                                  KeyEncryptionAlgorithms keyEncryptionAlgorithm)
    throws GeneralSecurityException {
        if (!keyEncryptionAlgorithm.rsa) {
            throw new GeneralSecurityException(
                    "Unsupported RSA algorithm: " + keyEncryptionAlgorithm);
        }
        String jceName = keyEncryptionAlgorithm == KeyEncryptionAlgorithms.JOSE_RSA_OAEP_ALG_ID ?
                JOSE_RSA_OAEP_JCENAME : JOSE_RSA_OAEP_256_JCENAME;
        Cipher cipher = Cipher.getInstance(jceName);
        cipher.init(mode, key);
        return cipher.doFinal(data);
    }

    /**
     * Perform an RSA encrypt key operation.
     * @param dataEncryptionKey Also known as CEK
     * @param keyEncryptionAlgorithm The RSA encryption algorithm
     * @param publicKey The receiver's (usually static) public key
     * @return A composite object including the (plain text) data encryption key
     * @throws GeneralSecurityException &nbsp;
     */
    static AsymmetricEncryptionResult rsaEncryptKey(byte[] dataEncryptionKey,
                                                    KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                                    PublicKey publicKey)
    throws GeneralSecurityException {
        return new AsymmetricEncryptionResult(dataEncryptionKey,
                                              rsaCore(Cipher.ENCRYPT_MODE,
                                                      publicKey,
                                                      dataEncryptionKey,
                                                      keyEncryptionAlgorithm),
                                              null);
    }

    /**
     * Decrypt a symmetric key using an RSA cipher.
     * @param keyEncryptionAlgorithm The algorithm to use
     * @param encryptedKey Contains a symmetric key used for encrypting the data
     * @param privateKey The RSA private key
     * @return The key in plain text
     * @throws GeneralSecurityException &nbsp;
     */
    public static byte[] rsaDecryptKey(KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                       byte[] encryptedKey,
                                       PrivateKey privateKey) 
    throws GeneralSecurityException {
        return rsaCore(Cipher.DECRYPT_MODE,
                       privateKey,
                       encryptedKey,
                       keyEncryptionAlgorithm);
    }

    private static void addInt4(MessageDigest messageDigest, int value) {
        for (int i = 24; i >= 0; i -= 8) {
            messageDigest.update((byte) (value >>> i));
        }
    }

    private static byte[] coreKeyAgreement(KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                           DataEncryptionAlgorithms dataEncryptionAlgorithm,
                                           PublicKey receivedPublicKey,
                                           PrivateKey privateKey)
    throws GeneralSecurityException, IOException {
        // Begin by calculating Z (do the DH)
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(receivedPublicKey, true);
        byte[] Z = keyAgreement.generateSecret();

        // NIST Concat KDF
        final MessageDigest messageDigest = MessageDigest.getInstance(CONCAT_KDF_DIGEST_JCENAME);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        byte[] algorithmId = (keyEncryptionAlgorithm.keyWrap ?
                keyEncryptionAlgorithm : dataEncryptionAlgorithm).toString().getBytes("UTF-8");

        int keyLength = keyEncryptionAlgorithm.keyWrap ?
                keyEncryptionAlgorithm.keyEncryptionKeyLength : dataEncryptionAlgorithm.keyLength;

        int reps = (keyLength + CONCAT_KDF_DIGEST_LENGTH - 1) / CONCAT_KDF_DIGEST_LENGTH;

        // Concat KDF according to JWA
        for (int i = 1; i <= reps; i++) {
            // Round indicator
            addInt4(messageDigest, i);
            // Z
            messageDigest.update(Z);
            // AlgorithmID = Content encryption algorithm
            addInt4(messageDigest, algorithmId.length);
            messageDigest.update(algorithmId);
            // PartyUInfo = Empty as described in the JEF specification
            addInt4(messageDigest, 0);
            // PartyVInfo = Empty as described in the JEF specification
            addInt4(messageDigest, 0);
            // SuppPubInfo = Key length in bits
            addInt4(messageDigest, keyLength * 8);
            baos.write(messageDigest.digest());
        }

        // Only use as much of the digest that is asked for
        byte[] result = new byte[keyLength];
        System.arraycopy(baos.toByteArray(), 0, result, 0, keyLength);
        return result;
    }

    /**
     * Perform a receiver side ECDH operation.
     * @param keyEncryptionAlgorithm The ECDH algorithm
     * @param dataEncryptionAlgorithm The designated content encryption algorithm
     * @param receivedPublicKey The sender's (usually ephemeral) public key
     * @param privateKey The receiver's private key
     * @param encryptedKeyData For ECDH+KW based operations only
     * @return Shared secret
     * @throws GeneralSecurityException &nbsp;
     * @throws IOException
     */
    public static byte[] receiverKeyAgreement(KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                              DataEncryptionAlgorithms dataEncryptionAlgorithm,
                                              PublicKey receivedPublicKey,
                                              PrivateKey privateKey,
                                              byte[] encryptedKeyData)
    throws GeneralSecurityException, IOException {
        // Sanity check
        if (keyEncryptionAlgorithm.keyWrap ^ (encryptedKeyData != null)) {
            throw new GeneralSecurityException("\"encryptedKeyData\" must " + 
                    (encryptedKeyData == null ? "not be null" : "be null") + " for algoritm: " +
                    keyEncryptionAlgorithm);
        }
        byte[] derivedKey = coreKeyAgreement(keyEncryptionAlgorithm,
                                             dataEncryptionAlgorithm,
                                             receivedPublicKey,
                                             privateKey);
        if (keyEncryptionAlgorithm.keyWrap) {
            Cipher cipher = getAesCipher(AES_KEY_WRAP_JCENAME);
            cipher.init(Cipher.UNWRAP_MODE, new SecretKeySpec(derivedKey, "AES"));
            derivedKey = cipher.unwrap(encryptedKeyData, "AES", Cipher.SECRET_KEY).getEncoded();
        }
        return derivedKey;
    }

    /**
     * Perform a sender side ECDH operation.
     * @param dataEncryptionKey Also known as CEK
     * @param keyEncryptionAlgorithm The ECDH algorithm
     * @param dataEncryptionAlgorithm The designated content encryption algorithm
     * @param staticKey The receiver's (usually static) public key
     * @return A composite object including the (plain text) data encryption key
     * @throws GeneralSecurityException &nbsp;
     * @throws IOException
     */
    static AsymmetricEncryptionResult
            senderKeyAgreement(byte[] dataEncryptionKey,
                               KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                               DataEncryptionAlgorithms dataEncryptionAlgorithm,
                               PublicKey staticKey) 
    throws IOException, GeneralSecurityException {
        AlgorithmParameterSpec paramSpec = 
                new ECGenParameterSpec(KeyAlgorithms.getKeyAlgorithm(staticKey).getJceName());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(paramSpec, new SecureRandom());
        KeyPair keyPair = generator.generateKeyPair();
        byte[] derivedKey = coreKeyAgreement(keyEncryptionAlgorithm,
                                             dataEncryptionAlgorithm,
                                             staticKey,
                                             keyPair.getPrivate());
        byte[] encryptedKeyData = null;
        if (keyEncryptionAlgorithm.keyWrap) {
            Cipher cipher = getAesCipher(AES_KEY_WRAP_JCENAME);
            cipher.init(Cipher.WRAP_MODE, new SecretKeySpec(derivedKey, "AES"));
            encryptedKeyData = cipher.wrap(new SecretKeySpec(dataEncryptionKey, "AES"));
            derivedKey = dataEncryptionKey;
        }
        return new AsymmetricEncryptionResult(derivedKey, 
                                              encryptedKeyData,
                                              keyPair.getPublic());
    }
}
