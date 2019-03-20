package org.webpki.androidjsondemo;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.spongycastle.jce.provider.BouncyCastleProvider;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.MACAlgorithms;

import org.webpki.json.JSONAsymKeySigner;
import org.webpki.json.JSONDecryptionDecoder;
import org.webpki.json.JSONCryptoHelper;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONSymKeySigner;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONSymKeyVerifier;
import org.webpki.json.JSONAsymKeyEncrypter;
import org.webpki.json.DataEncryptionAlgorithms;
import org.webpki.json.KeyEncryptionAlgorithms;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;

import java.security.KeyPair;
import java.security.Security;

import java.util.Vector;

import static org.junit.Assert.*;

/**
 * Instrumentation test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class InstrumentedTest {

    static final String JEF_SYM_KEY     = "ooQSGRnwUQYbvHjCMi0zPNARka2BuksLM7UK1RHiQwI";

    Vector<JSONDecryptionDecoder.DecryptionKeyHolder> keys;


    @BeforeClass
    static public void initialize() throws Exception {
        new RawReader(InstrumentationRegistry.getTargetContext());
    }

    void decrypt(int resource, boolean inLineKey) throws Exception {
        JSONCryptoHelper.Options options =
                new JSONCryptoHelper.Options()
                    .setRequirePublicKeyInfo(inLineKey)
                    .setKeyIdOption(inLineKey ?
     JSONCryptoHelper.KEY_ID_OPTIONS.FORBIDDEN : JSONCryptoHelper.KEY_ID_OPTIONS.REQUIRED);
        assertTrue("Decrypt",
                   ArrayUtil.compare(RawReader.dataToBeEncrypted,
                                     RawReader.getJSONResource(resource)
                                             .getEncryptionObject(options)
                                             .getDecryptedData(keys)));
    }

    @Test
    public void decryption() throws Exception {

        keys = new Vector<JSONDecryptionDecoder.DecryptionKeyHolder>();

        keys.add(new JSONDecryptionDecoder.DecryptionKeyHolder(RawReader.ecKeyPair.getPublic(),
                RawReader.ecKeyPair.getPrivate(),
                KeyEncryptionAlgorithms.JOSE_ECDH_ES_ALG_ID,
                RawReader.ecKeyId));

        keys.add(new JSONDecryptionDecoder.DecryptionKeyHolder(RawReader.ecKeyPair.getPublic(),
                RawReader.ecKeyPair.getPrivate(),
                KeyEncryptionAlgorithms.JOSE_ECDH_ES_A128KW_ALG_ID,
                RawReader.ecKeyId));

        keys.add(new JSONDecryptionDecoder.DecryptionKeyHolder(RawReader.ecKeyPair.getPublic(),
                RawReader.ecKeyPair.getPrivate(),
                KeyEncryptionAlgorithms.JOSE_ECDH_ES_A192KW_ALG_ID,
                RawReader.ecKeyId));

        keys.add(new JSONDecryptionDecoder.DecryptionKeyHolder(RawReader.ecKeyPair.getPublic(),
                RawReader.ecKeyPair.getPrivate(),
                KeyEncryptionAlgorithms.JOSE_ECDH_ES_A256KW_ALG_ID,
                RawReader.ecKeyId));

        keys.add(new JSONDecryptionDecoder.DecryptionKeyHolder(RawReader.rsaKeyPair.getPublic(),
                RawReader.rsaKeyPair.getPrivate(),
                KeyEncryptionAlgorithms.JOSE_RSA_OAEP_256_ALG_ID,
                RawReader.rsaKeyId));

        keys.add(new JSONDecryptionDecoder.DecryptionKeyHolder(RawReader.rsaKeyPair.getPublic(),
                RawReader.rsaKeyPair.getPrivate(),
                KeyEncryptionAlgorithms.JOSE_RSA_OAEP_ALG_ID,
                RawReader.rsaKeyId));

        decrypt(R.raw.ecdh_es_json, true);
        decrypt(R.raw.ecdh_es2_json, false);
        decrypt(R.raw.ecdh_es3_json, false);
        decrypt(R.raw.rsa_oaep_256_json, true);
        decrypt(R.raw.rsa_oaep_json, false);

        for (int i = 0; i < 2; i++) {
            for (KeyEncryptionAlgorithms keyEncryptionAlgorithm : KeyEncryptionAlgorithms.values()) {
                for (DataEncryptionAlgorithms dataEncryptionAlgorithm : DataEncryptionAlgorithms.values()) {
                    JSONObjectWriter writer = JSONObjectWriter.createEncryptionObject(
                            RawReader.dataToBeEncrypted,
                            dataEncryptionAlgorithm,
                            new JSONAsymKeyEncrypter(
                                    (keyEncryptionAlgorithm.isRsa() ?
                                    RawReader.rsaKeyPair : RawReader.ecKeyPair).getPublic(),
                            keyEncryptionAlgorithm).setKeyId(i == 0 ? null :
                                    (keyEncryptionAlgorithm.isRsa() ? RawReader.rsaKeyId : RawReader.ecKeyId)));
                    assertTrue(keyEncryptionAlgorithm.toString(),
                            ArrayUtil.compare(RawReader.dataToBeEncrypted,
                                    JSONParser.parse(writer.toString())
                                            .getEncryptionObject(new JSONCryptoHelper.Options()
                                                    .setKeyIdOption(i == 0 ?
                                 JSONCryptoHelper.KEY_ID_OPTIONS.FORBIDDEN : JSONCryptoHelper.KEY_ID_OPTIONS.REQUIRED)).getDecryptedData(keys)));
                }
            }
        }

        assertTrue("Decrypt sym",
                   ArrayUtil.compare(RawReader.dataToBeEncrypted,
                                     RawReader.getJSONResource(R.raw.a128cbc_hs256_json)
                                         .getEncryptionObject(new JSONCryptoHelper.Options())
                                             .getDecryptedData(Base64URL.decode(JEF_SYM_KEY))));
    }

    JSONObjectWriter getData() throws Exception {
        return new JSONObjectWriter(RawReader.getJSONResource(R.raw.json_data));
    }

    @Test
    public void signatures() throws Exception {
        RawReader.getJSONResource(R.raw.json_signature).getSignature(new JSONCryptoHelper.Options());
        String signature =
                getData().setSignature(new JSONAsymKeySigner(RawReader.ecKeyPair.getPrivate(),
                                                             RawReader.ecKeyPair.getPublic(),
                                                             null)).toString();
        JSONParser.parse(signature).getSignature(new JSONCryptoHelper.Options());
        signature =
                getData().setSignature(new JSONAsymKeySigner(RawReader.rsaKeyPair.getPrivate(),
                                                             RawReader.rsaKeyPair.getPublic(),
                                                             null)).toString();
        JSONParser.parse(signature).getSignature(new JSONCryptoHelper.Options());

        try {
            JSONParser.parse(signature.replace("now", "then")).getSignature(new JSONCryptoHelper.Options());
            fail("verify");
        } catch (Exception e) {
        }
        try {
            getData().setSignature(new JSONAsymKeySigner(RawReader.rsaKeyPair.getPrivate(),
                                                         RawReader.ecKeyPair.getPublic(),
                                                         null));
            fail("rsa/ec key");
        } catch (Exception e) {
        }
        try {
            getData().setSignature(new JSONAsymKeySigner(RawReader.ecKeyPair.getPrivate(),
                                                         RawReader.rsaKeyPair.getPublic(),
                                                         null));
            fail("ec/rsa key");
        } catch (Exception e) {
        }
        try {
            getData().setSignature(new JSONAsymKeySigner(RawReader.ecKeyPair.getPrivate(),
                                                         RawReader.ecKeyPair.getPublic(),
                                                         null).setSignatureAlgorithm(AsymSignatureAlgorithms.RSA_SHA256));
            fail("ec/rsa alg");
        } catch (Exception e) {
        }

        JSONObjectReader json = JSONParser.parse(
                getData().setSignature(new JSONAsymKeySigner(RawReader.rsaKeyPair.getPrivate(),
                        RawReader.rsaKeyPair.getPublic(),
                        null)).toString());
        json.removeProperty(JSONObjectWriter.SIGNATURE_DEFAULT_LABEL_JSON);
        assertTrue("data", json.toString().equals(getData().toString()));
        assertTrue("data", json.serializeToString(JSONOutputFormats.CANONICALIZED)
                .equals(getData().serializeToString(JSONOutputFormats.CANONICALIZED)));

        signature =
                getData().setSignature(new JSONSymKeySigner(Base64URL.decode(JEF_SYM_KEY),
                                                            MACAlgorithms.HMAC_SHA256)).toString();
        JSONParser.parse(signature)
                .getSignature(new JSONCryptoHelper.Options()
                        .setRequirePublicKeyInfo(false))
                .verify(new JSONSymKeyVerifier(Base64URL.decode(JEF_SYM_KEY)));
        try {
            JSONParser.parse(signature.replace("now", "then"))
                    .getSignature(new JSONCryptoHelper.Options()
                            .setRequirePublicKeyInfo(false))
                    .verify(new JSONSymKeyVerifier(Base64URL.decode(JEF_SYM_KEY)));
            fail("verify");
        } catch (Exception e) {
        }
    }

    @Test
    public void useAppContext() throws Exception {
        assertEquals("org.webpki.androidjsondemo", RawReader.appContext.getPackageName());
    }
}
