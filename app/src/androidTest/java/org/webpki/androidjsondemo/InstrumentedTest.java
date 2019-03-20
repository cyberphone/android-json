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
    static Context appContext;

    static final String JEF_SYM_KEY     = "ooQSGRnwUQYbvHjCMi0zPNARka2BuksLM7UK1RHiQwI";
    
    static byte[] dataToBeEncrypted;

    static String rsaKeyId;

    static String ecKeyId;

    Vector<JSONDecryptionDecoder.DecryptionKeyHolder> keys;

    static KeyPair ecKeyPair;
    static KeyPair rsaKeyPair;
    static KeyPair currentKeyPair;

    static String getKeyId(int resource) throws Exception {
        JSONObjectReader jwk = getJSONResource(resource);
        String keyId = jwk.getString("kid");
        jwk.removeProperty("kid");
        currentKeyPair = jwk.getKeyPair();
        return keyId;
    }

    @BeforeClass
    static public void initialize() throws Exception {
        appContext = InstrumentationRegistry.getTargetContext();
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ecKeyId = getKeyId(R.raw.ecprivatekey_jwk);
        ecKeyPair = currentKeyPair;
        rsaKeyId = getKeyId(R.raw.rsaprivatekey_jwk);
        rsaKeyPair = currentKeyPair;
        dataToBeEncrypted = getRawResource(R.raw.data2beencrypted_txt);
    }

    static byte[] getRawResource(int resource) throws Exception {
        return ArrayUtil.getByteArrayFromInputStream(appContext.getResources()
                .openRawResource(resource));
    }

    static JSONObjectReader getJSONResource(int resource) throws Exception {
        return JSONParser.parse(getRawResource(resource));
    }

    void decrypt(int resource, boolean inLineKey) throws Exception {
        JSONCryptoHelper.Options options =
                new JSONCryptoHelper.Options()
                    .setRequirePublicKeyInfo(inLineKey)
                    .setKeyIdOption(inLineKey ?
     JSONCryptoHelper.KEY_ID_OPTIONS.FORBIDDEN : JSONCryptoHelper.KEY_ID_OPTIONS.REQUIRED);
        assertTrue("Decrypt",
                   ArrayUtil.compare(dataToBeEncrypted,
                                     getJSONResource(resource)
                                             .getEncryptionObject(options)
                                             .getDecryptedData(keys)));
    }

    @Test
    public void decryption() throws Exception {

        keys = new Vector<JSONDecryptionDecoder.DecryptionKeyHolder>();

        keys.add(new JSONDecryptionDecoder.DecryptionKeyHolder(ecKeyPair.getPublic(),
                ecKeyPair.getPrivate(),
                KeyEncryptionAlgorithms.JOSE_ECDH_ES_ALG_ID,
                ecKeyId));

        keys.add(new JSONDecryptionDecoder.DecryptionKeyHolder(ecKeyPair.getPublic(),
                ecKeyPair.getPrivate(),
                KeyEncryptionAlgorithms.JOSE_ECDH_ES_A128KW_ALG_ID,
                ecKeyId));

        keys.add(new JSONDecryptionDecoder.DecryptionKeyHolder(ecKeyPair.getPublic(),
                ecKeyPair.getPrivate(),
                KeyEncryptionAlgorithms.JOSE_ECDH_ES_A192KW_ALG_ID,
                ecKeyId));

        keys.add(new JSONDecryptionDecoder.DecryptionKeyHolder(ecKeyPair.getPublic(),
                ecKeyPair.getPrivate(),
                KeyEncryptionAlgorithms.JOSE_ECDH_ES_A256KW_ALG_ID,
                ecKeyId));

        keys.add(new JSONDecryptionDecoder.DecryptionKeyHolder(rsaKeyPair.getPublic(),
                rsaKeyPair.getPrivate(),
                KeyEncryptionAlgorithms.JOSE_RSA_OAEP_256_ALG_ID,
                rsaKeyId));

        keys.add(new JSONDecryptionDecoder.DecryptionKeyHolder(rsaKeyPair.getPublic(),
                rsaKeyPair.getPrivate(),
                KeyEncryptionAlgorithms.JOSE_RSA_OAEP_ALG_ID,
                rsaKeyId));

        decrypt(R.raw.ecdh_es_json, true);
        decrypt(R.raw.ecdh_es2_json, false);
        decrypt(R.raw.ecdh_es3_json, false);
        decrypt(R.raw.rsa_oaep_256_json, true);
        decrypt(R.raw.rsa_oaep_json, false);

        for (int i = 0; i < 2; i++) {
            for (KeyEncryptionAlgorithms keyEncryptionAlgorithm : KeyEncryptionAlgorithms.values()) {
                for (DataEncryptionAlgorithms dataEncryptionAlgorithm : DataEncryptionAlgorithms.values()) {
                    JSONObjectWriter writer = JSONObjectWriter.createEncryptionObject(
                            dataToBeEncrypted,
                            dataEncryptionAlgorithm,
                            new JSONAsymKeyEncrypter(
                                    (keyEncryptionAlgorithm.isRsa() ?
                                    rsaKeyPair : ecKeyPair).getPublic(),
                            keyEncryptionAlgorithm).setKeyId(i == 0 ? null :
                                    (keyEncryptionAlgorithm.isRsa() ? rsaKeyId : ecKeyId)));
                    assertTrue(keyEncryptionAlgorithm.toString(),
                            ArrayUtil.compare(dataToBeEncrypted,
                                    JSONParser.parse(writer.toString())
                                            .getEncryptionObject(new JSONCryptoHelper.Options()
                                                    .setKeyIdOption(i == 0 ?
                                 JSONCryptoHelper.KEY_ID_OPTIONS.FORBIDDEN : JSONCryptoHelper.KEY_ID_OPTIONS.REQUIRED)).getDecryptedData(keys)));
                }
            }
        }

        assertTrue("Decrypt sym",
                   ArrayUtil.compare(dataToBeEncrypted,
                                     getJSONResource(R.raw.a128cbc_hs256_json)
                                         .getEncryptionObject(new JSONCryptoHelper.Options())
                                             .getDecryptedData(Base64URL.decode(JEF_SYM_KEY))));
    }

    JSONObjectWriter getData() throws Exception {
        return new JSONObjectWriter(getJSONResource(R.raw.json_data));
    }

    @Test
    public void signatures() throws Exception {
        getJSONResource(R.raw.json_signature).getSignature(new JSONCryptoHelper.Options());
        String signature =
                getData().setSignature(new JSONAsymKeySigner(ecKeyPair.getPrivate(),
                                                             ecKeyPair.getPublic(),
                                                             null)).toString();
        JSONParser.parse(signature).getSignature(new JSONCryptoHelper.Options());
        signature =
                getData().setSignature(new JSONAsymKeySigner(rsaKeyPair.getPrivate(),
                                                             rsaKeyPair.getPublic(),
                                                             null)).toString();
        JSONParser.parse(signature).getSignature(new JSONCryptoHelper.Options());

        try {
            JSONParser.parse(signature.replace("now", "then")).getSignature(new JSONCryptoHelper.Options());
            fail("verify");
        } catch (Exception e) {
        }
        try {
            getData().setSignature(new JSONAsymKeySigner(rsaKeyPair.getPrivate(),
                                                         ecKeyPair.getPublic(),
                                                         null));
            fail("rsa/ec key");
        } catch (Exception e) {
        }
        try {
            getData().setSignature(new JSONAsymKeySigner(ecKeyPair.getPrivate(),
                                                         rsaKeyPair.getPublic(),
                                                         null));
            fail("ec/rsa key");
        } catch (Exception e) {
        }
        try {
            getData().setSignature(new JSONAsymKeySigner(ecKeyPair.getPrivate(),
                                                         ecKeyPair.getPublic(),
                                                         null).setSignatureAlgorithm(AsymSignatureAlgorithms.RSA_SHA256));
            fail("ec/rsa alg");
        } catch (Exception e) {
        }

        JSONObjectReader json = JSONParser.parse(
                getData().setSignature(new JSONAsymKeySigner(rsaKeyPair.getPrivate(),
                        rsaKeyPair.getPublic(),
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
        assertEquals("org.webpki.androidjsondemo", appContext.getPackageName());
    }
}
