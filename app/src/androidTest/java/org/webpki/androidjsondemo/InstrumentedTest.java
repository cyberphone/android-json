package org.webpki.androidjsondemo;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;
import android.util.Log;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.spongycastle.jce.provider.BouncyCastleProvider;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.MACAlgorithms;

import org.webpki.json.JSONAsymKeySigner;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONSignatureDecoder;
import org.webpki.json.JSONSymKeySigner;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;

import org.webpki.json.JSONSymKeyVerifier;
import org.webpki.json.encryption.DataEncryptionAlgorithms;
import org.webpki.json.encryption.DecryptionKeyHolder;
import org.webpki.json.encryption.KeyEncryptionAlgorithms;

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
    static Context appContext;

    static final byte[] JEF_TEST_STRING = {'H','e','l','l','o',' ','e','n','c','r','y',
                                           'p','t','e','d',' ','w','o','r','l','d','!'};
    static final String JEF_SYM_KEY     = "ooQSGRnwUQYbvHjCMi0zPNARka2BuksLM7UK1RHiQwI";
    static final String JEF_EC_KEY_ID   = "20170101:mybank:ec";
    static final String JEF_RSA_KEY_ID  = "20170101:mybank:rsa";

    Vector<DecryptionKeyHolder> keys;

    static KeyPair ecPrivateKey;
    static KeyPair rsaPrivateKey;

    @BeforeClass
    static public void initialize() throws Exception {
        appContext = InstrumentationRegistry.getTargetContext();
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ecPrivateKey = getResource(R.raw.ecprivatekey_jwk).getKeyPair();
        rsaPrivateKey = getResource(R.raw.rsaprivatekey_jwk).getKeyPair();
    }

    static JSONObjectReader getResource(int resource) throws Exception {
        return JSONParser.parse(ArrayUtil.getByteArrayFromInputStream(appContext.getResources()
                .openRawResource(resource)));
    }

    void decrypt(int resource) throws Exception {
        assertTrue("Decrypt",
                   ArrayUtil.compare(JEF_TEST_STRING,
                                     getResource(resource)
                                             .getEncryptionObject().getDecryptedData(keys)));
    }

    @Test
    public void decryption() throws Exception {

        keys = new Vector<DecryptionKeyHolder>();

        keys.add(new DecryptionKeyHolder(ecPrivateKey.getPublic(),
                ecPrivateKey.getPrivate(),
                KeyEncryptionAlgorithms.JOSE_ECDH_ES_ALG_ID,
                JEF_EC_KEY_ID));

        keys.add(new DecryptionKeyHolder(ecPrivateKey.getPublic(),
                ecPrivateKey.getPrivate(),
                KeyEncryptionAlgorithms.JOSE_ECDH_ES_A128KW_ALG_ID,
                JEF_EC_KEY_ID));

        keys.add(new DecryptionKeyHolder(ecPrivateKey.getPublic(),
                ecPrivateKey.getPrivate(),
                KeyEncryptionAlgorithms.JOSE_ECDH_ES_A192KW_ALG_ID,
                JEF_EC_KEY_ID));

        keys.add(new DecryptionKeyHolder(ecPrivateKey.getPublic(),
                ecPrivateKey.getPrivate(),
                KeyEncryptionAlgorithms.JOSE_ECDH_ES_A256KW_ALG_ID,
                JEF_EC_KEY_ID));

        keys.add(new DecryptionKeyHolder(rsaPrivateKey.getPublic(),
                rsaPrivateKey.getPrivate(),
                KeyEncryptionAlgorithms.JOSE_RSA_OAEP_256_ALG_ID,
                JEF_RSA_KEY_ID));

        keys.add(new DecryptionKeyHolder(rsaPrivateKey.getPublic(),
                rsaPrivateKey.getPrivate(),
                KeyEncryptionAlgorithms.JOSE_RSA_OAEP_ALG_ID,
                JEF_RSA_KEY_ID));

        decrypt(R.raw.ecdh_es_json);
        decrypt(R.raw.ecdh_es2_json);
        decrypt(R.raw.ecdh_es3_json);
        decrypt(R.raw.ecdh_es4_json);
        decrypt(R.raw.ecdh_es5_json);

        for (int i = 0; i < 2; i++) {
            for (KeyEncryptionAlgorithms keyEncryptionAlgorithm : KeyEncryptionAlgorithms.values()) {
                for (DataEncryptionAlgorithms dataEncryptionAlgorithm : DataEncryptionAlgorithms.values()) {
                    JSONObjectWriter writer = JSONObjectWriter.createEncryptionObject(
                            JEF_TEST_STRING,
                            dataEncryptionAlgorithm,
                            (keyEncryptionAlgorithm.isRsa() ?
                                    rsaPrivateKey : ecPrivateKey).getPublic(),
                            i == 0 ? null : (keyEncryptionAlgorithm.isRsa() ? JEF_RSA_KEY_ID : JEF_EC_KEY_ID),
                            keyEncryptionAlgorithm);
                    assertTrue(keyEncryptionAlgorithm.toString(),
                            ArrayUtil.compare(JEF_TEST_STRING,
                                    JSONParser.parse(writer.toString())
                                            .getEncryptionObject().getDecryptedData(keys)));
                }
            }
        }

        assertTrue("Decrypt sym",
                   ArrayUtil.compare(JEF_TEST_STRING,
                                     getResource(R.raw.a128cbc_hs256_json)
                                         .getEncryptionObject().getDecryptedData(Base64URL.decode(JEF_SYM_KEY))));
    }

    JSONObjectWriter getData() throws Exception {
        return new JSONObjectWriter(getResource(R.raw.json_data));
    }

    @Test
    public void signatures() throws Exception {
        getResource(R.raw.json_signature).getSignature(new JSONSignatureDecoder.Options());
        String signature =
                getData().setSignature(new JSONAsymKeySigner(ecPrivateKey.getPrivate(),
                                                             ecPrivateKey.getPublic(),
                                                             null)).toString();
        JSONParser.parse(signature).getSignature(new JSONSignatureDecoder.Options());
        signature =
                getData().setSignature(new JSONAsymKeySigner(rsaPrivateKey.getPrivate(),
                                                             rsaPrivateKey.getPublic(),
                                                             null)).toString();
        JSONParser.parse(signature).getSignature(new JSONSignatureDecoder.Options());

        try {
            JSONParser.parse(signature.replace("now", "then")).getSignature(new JSONSignatureDecoder.Options());
            fail("verify");
        } catch (Exception e) {
        }
        try {
            getData().setSignature(new JSONAsymKeySigner(rsaPrivateKey.getPrivate(),
                                                         ecPrivateKey.getPublic(),
                                                         null));
            fail("rsa/ec key");
        } catch (Exception e) {
        }
        try {
            getData().setSignature(new JSONAsymKeySigner(ecPrivateKey.getPrivate(),
                                                         rsaPrivateKey.getPublic(),
                                                         null));
            fail("ec/rsa key");
        } catch (Exception e) {
        }
        try {
            getData().setSignature(new JSONAsymKeySigner(ecPrivateKey.getPrivate(),
                                                         ecPrivateKey.getPublic(),
                                                         null).setSignatureAlgorithm(AsymSignatureAlgorithms.RSA_SHA256));
            fail("ec/rsa alg");
        } catch (Exception e) {
        }

        JSONObjectReader json = JSONParser.parse(
                getData().setSignature(new JSONAsymKeySigner(rsaPrivateKey.getPrivate(),
                        rsaPrivateKey.getPublic(),
                        null)).toString());
        json.removeProperty(JSONSignatureDecoder.SIGNATURE_JSON);
        assertTrue("data", json.toString().equals(getData().toString()));
        assertTrue("data", json.serializeToString(JSONOutputFormats.NORMALIZED)
                .equals(getData().serializeToString(JSONOutputFormats.NORMALIZED)));

        signature =
                getData().setSignature(new JSONSymKeySigner(Base64URL.decode(JEF_SYM_KEY),
                                                            MACAlgorithms.HMAC_SHA256)).toString();
        JSONParser.parse(signature)
                .getSignature(new JSONSignatureDecoder.Options()
                        .setRequirePublicKeyInfo(false))
                .verify(new JSONSymKeyVerifier(Base64URL.decode(JEF_SYM_KEY)));
        try {
            JSONParser.parse(signature.replace("now", "then"))
                    .getSignature(new JSONSignatureDecoder.Options()
                            .setRequirePublicKeyInfo(false))
                    .verify(new JSONSymKeyVerifier(Base64URL.decode(JEF_SYM_KEY)));
            fail("verify");
        } catch (Exception e) {
        }
    }

    @Test
    public void useAppContext() throws Exception {
        assertEquals("org.webpki.androidjsondemo", appContext.getPackageName());
    }
}
