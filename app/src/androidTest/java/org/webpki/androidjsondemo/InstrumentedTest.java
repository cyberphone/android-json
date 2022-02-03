package org.webpki.androidjsondemo;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import android.security.keystore.KeyProtection;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import android.util.Log;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.HmacAlgorithms;

import org.webpki.crypto.encryption.ContentEncryptionAlgorithms;
import org.webpki.crypto.encryption.KeyEncryptionAlgorithms;

import org.webpki.jose.jws.JWSAsymKeySigner;
import org.webpki.jose.jws.JWSAsymSignatureValidator;
import org.webpki.jose.jws.JWSDecoder;

import org.webpki.json.JSONAsymKeySigner;
import org.webpki.json.JSONAsymKeyVerifier;
import org.webpki.json.JSONDecryptionDecoder;
import org.webpki.json.JSONCryptoHelper;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONHmacSigner;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONHmacVerifier;
import org.webpki.json.JSONAsymKeyEncrypter;
import org.webpki.json.JSONX509Signer;

import org.webpki.util.ArrayUtil;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import java.util.Date;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import static org.junit.Assert.*;

/**
 * Instrumentation test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class InstrumentedTest {

    Vector<JSONDecryptionDecoder.DecryptionKeyHolder> keys;

    @BeforeClass
    static public void initialize() throws Exception {
        new RawReader(InstrumentationRegistry.getInstrumentation().getTargetContext());
    }

    void decrypt(int resource, boolean inLineKey) throws Exception {
        JSONCryptoHelper.Options options =
                new JSONCryptoHelper.Options()
                    .setPublicKeyOption(inLineKey ?
     JSONCryptoHelper.PUBLIC_KEY_OPTIONS.REQUIRED : JSONCryptoHelper.PUBLIC_KEY_OPTIONS.FORBIDDEN)
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
                KeyEncryptionAlgorithms.ECDH_ES,
                RawReader.ecKeyId));

        keys.add(new JSONDecryptionDecoder.DecryptionKeyHolder(RawReader.ecKeyPair.getPublic(),
                RawReader.ecKeyPair.getPrivate(),
                KeyEncryptionAlgorithms.ECDH_ES_A128KW,
                RawReader.ecKeyId));

        keys.add(new JSONDecryptionDecoder.DecryptionKeyHolder(RawReader.ecKeyPair.getPublic(),
                RawReader.ecKeyPair.getPrivate(),
                KeyEncryptionAlgorithms.ECDH_ES_A192KW,
                RawReader.ecKeyId));

        keys.add(new JSONDecryptionDecoder.DecryptionKeyHolder(RawReader.ecKeyPair.getPublic(),
                RawReader.ecKeyPair.getPrivate(),
                KeyEncryptionAlgorithms.ECDH_ES_A256KW,
                RawReader.ecKeyId));

        keys.add(new JSONDecryptionDecoder.DecryptionKeyHolder(RawReader.rsaKeyPair.getPublic(),
                RawReader.rsaKeyPair.getPrivate(),
                KeyEncryptionAlgorithms.RSA_OAEP_256,
                RawReader.rsaKeyId));

        keys.add(new JSONDecryptionDecoder.DecryptionKeyHolder(RawReader.rsaKeyPair.getPublic(),
                RawReader.rsaKeyPair.getPrivate(),
                KeyEncryptionAlgorithms.RSA_OAEP,
                RawReader.rsaKeyId));

        decrypt(R.raw.ecdh_es_json, true);
        decrypt(R.raw.ecdh_es2_json, false);
        decrypt(R.raw.ecdh_es3_json, false);
        decrypt(R.raw.rsa_oaep_256_json, true);
        decrypt(R.raw.rsa_oaep_json, false);

        for (int i = 0; i < 2; i++) {
            for (KeyEncryptionAlgorithms keyEncryptionAlgorithm : KeyEncryptionAlgorithms.values()) {
                for (ContentEncryptionAlgorithms dataEncryptionAlgorithm : ContentEncryptionAlgorithms.values()) {
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
                                         .getEncryptionObject(new JSONCryptoHelper.Options()
                                             .setKeyIdOption(JSONCryptoHelper.KEY_ID_OPTIONS.OPTIONAL)
                                             .setPublicKeyOption(JSONCryptoHelper.PUBLIC_KEY_OPTIONS.PLAIN_ENCRYPTION))
                                                 .getDecryptedData(RawReader.secretKey)));
    }

    JSONObjectWriter getData() throws Exception {
        return new JSONObjectWriter(RawReader.getJSONResource(R.raw.json_data));
    }

    @Test
    public void jws() throws Exception {
        String jwsString = new JWSAsymKeySigner(RawReader.ecKeyPair.getPrivate(),
                                                AsymSignatureAlgorithms.ECDSA_SHA256)
            .sign(RawReader.dataToBeEncrypted, false);
        new JWSAsymSignatureValidator(RawReader.ecKeyPair.getPublic())
            .validate(new JWSDecoder(jwsString));

        jwsString = new JWSAsymKeySigner(RawReader.ecKeyPair.getPrivate(),
            AsymSignatureAlgorithms.ECDSA_SHA256)
            .setCertificatePath(RawReader.ecCertPath)
            .sign(RawReader.dataToBeEncrypted, false);
        new JWSAsymSignatureValidator(RawReader.ecKeyPair.getPublic())
            .validate(new JWSDecoder(jwsString));

        jwsString = new JWSAsymKeySigner(RawReader.ecKeyPair.getPrivate(),
            AsymSignatureAlgorithms.ECDSA_SHA256)
            .setPublicKey(RawReader.ecKeyPair.getPublic())
            .sign(RawReader.dataToBeEncrypted, false);
        new JWSAsymSignatureValidator(RawReader.ecKeyPair.getPublic())
            .validate(new JWSDecoder(jwsString));

        jwsString = new JWSAsymKeySigner(RawReader.ecKeyPair.getPrivate(),
            AsymSignatureAlgorithms.ECDSA_SHA256)
            .setPublicKey(RawReader.ecKeyPair.getPublic())
            .sign(RawReader.dataToBeEncrypted, true);
        new JWSAsymSignatureValidator(RawReader.ecKeyPair.getPublic())
            .validate(new JWSDecoder(jwsString), RawReader.dataToBeEncrypted);

        jwsString = new JWSAsymKeySigner(RawReader.rsaKeyPair.getPrivate(),
            AsymSignatureAlgorithms.RSA_SHA256)
            .setPublicKey(RawReader.rsaKeyPair.getPublic())
            .sign(RawReader.dataToBeEncrypted, true);
        new JWSAsymSignatureValidator(RawReader.rsaKeyPair.getPublic())
            .validate(new JWSDecoder(jwsString), RawReader.dataToBeEncrypted);

        jwsString = new JWSAsymKeySigner(RawReader.rsaKeyPair.getPrivate(),
            AsymSignatureAlgorithms.RSAPSS_SHA512)
            .setPublicKey(RawReader.rsaKeyPair.getPublic())
            .sign(RawReader.dataToBeEncrypted, true);
        new JWSAsymSignatureValidator(RawReader.rsaKeyPair.getPublic())
            .validate(new JWSDecoder(jwsString), RawReader.dataToBeEncrypted);

        try {
            jwsString = new JWSAsymKeySigner(RawReader.ecKeyPair.getPrivate(),
                AsymSignatureAlgorithms.ECDSA_SHA256)
                .setPublicKey(RawReader.ecKeyPair.getPublic())
                .sign(RawReader.dataToBeEncrypted, true);
            new JWSAsymSignatureValidator(RawReader.ecKeyPair.getPublic())
                .validate(new JWSDecoder(jwsString), new byte[]{5,5});
            fail("Bad data");
        } catch (Exception e) { Log.i("XXX",e.getMessage());}

        try {
            jwsString = new JWSAsymKeySigner(RawReader.ecKeyPair.getPrivate(),
                AsymSignatureAlgorithms.ECDSA_SHA256)
                .setPublicKey(RawReader.rsaKeyPair.getPublic())
                .sign(RawReader.dataToBeEncrypted, false);
            new JWSAsymSignatureValidator(RawReader.ecKeyPair.getPublic())
                .validate(new JWSDecoder(jwsString));
            fail("Bad data");
        } catch (Exception e) { Log.i("XXX",e.getMessage());}
    }

    @Test
    public void signatures() throws Exception {
        RawReader.getJSONResource(R.raw.json_signature).getSignature(new JSONCryptoHelper.Options());
        String signature =
                getData().setSignature(new JSONAsymKeySigner(RawReader.ecKeyPair.getPrivate())
                        .setPublicKey(RawReader.ecKeyPair.getPublic())).toString();
        JSONParser.parse(signature).getSignature(new JSONCryptoHelper.Options());
        signature =
                getData().setSignature(new JSONAsymKeySigner(RawReader.rsaKeyPair.getPrivate())
                        .setPublicKey(RawReader.rsaKeyPair.getPublic())).toString();
        JSONParser.parse(signature).getSignature(new JSONCryptoHelper.Options());

        try {
            JSONParser.parse(signature.replace("now", "then"))
                    .getSignature(new JSONCryptoHelper.Options());
            fail("verify");
        } catch (Exception e) {
        }
        signature = getData().setSignature(new JSONAsymKeySigner(RawReader.rsaKeyPair.getPrivate())
                        .setPublicKey(RawReader.ecKeyPair.getPublic())).toString();
        try {
            JSONParser.parse(signature).getSignature(new JSONCryptoHelper.Options());
            fail("rsa/ec key");
        } catch (Exception e) {
        }
        signature = getData().setSignature(new JSONAsymKeySigner(RawReader.ecKeyPair.getPrivate())
                    .setPublicKey(RawReader.rsaKeyPair.getPublic())).toString();
        try {
            JSONParser.parse(signature).getSignature(new JSONCryptoHelper.Options());
            fail("ec/rsa key");
        } catch (Exception e) {
        }
        try {
            getData().setSignature(new JSONAsymKeySigner(RawReader.ecKeyPair.getPrivate())
                                                 .setPublicKey(RawReader.ecKeyPair.getPublic())
                    .setAlgorithm(AsymSignatureAlgorithms.RSA_SHA256));
            fail("ec/rsa alg");
        } catch (Exception e) {
        }

        JSONObjectReader json = JSONParser.parse(
                getData().setSignature(new JSONAsymKeySigner(RawReader.rsaKeyPair.getPrivate())
                        .setPublicKey(RawReader.rsaKeyPair.getPublic())).toString());
        json.removeProperty(JSONObjectWriter.SIGNATURE_DEFAULT_LABEL_JSON);
        assertTrue("data", json.toString().equals(getData().toString()));
        assertTrue("data", json.serializeToString(JSONOutputFormats.CANONICALIZED)
                .equals(getData().serializeToString(JSONOutputFormats.CANONICALIZED)));

        signature =
                getData().setSignature(new JSONHmacSigner(RawReader.secretKey,
                                                            HmacAlgorithms.HMAC_SHA256)).toString();
        JSONParser.parse(signature)
                .getSignature(new JSONCryptoHelper.Options()
                        .setPublicKeyOption(JSONCryptoHelper.PUBLIC_KEY_OPTIONS.FORBIDDEN))
                .verify(new JSONHmacVerifier(RawReader.secretKey));
        try {
            JSONParser.parse(signature.replace("now", "then"))
                    .getSignature(new JSONCryptoHelper.Options()
                        .setPublicKeyOption(JSONCryptoHelper.PUBLIC_KEY_OPTIONS.FORBIDDEN))
                    .verify(new JSONHmacVerifier(RawReader.secretKey));
            fail("verify");
        } catch (Exception e) {
        }
    }

    X509Certificate[] convert(Certificate[] certificates) {
        X509Certificate[] x509Certificates = new X509Certificate[certificates.length];
        int q = 0;
        for (Certificate certificate : certificates) {
            x509Certificates[q++] = (X509Certificate)certificate;
        }
        return x509Certificates;
    }

    static String ANDROID_KEYSTORE = "AndroidKeyStore";

    static String KEY_1 = "key-1";
    static String KEY_2 = "key-2";

    @Test
    public void androidKeystore() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE);
        kpg.initialize(new KeyGenParameterSpec.Builder(
                KEY_1,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(2048,RSAKeyGenParameterSpec.F4))
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS, KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setCertificateNotBefore(new Date(System.currentTimeMillis() - 600000L))
                .setCertificateSubject(new X500Principal("CN=Android, SerialNumber=5678"))
                 .build());

        KeyPair keyPair = kpg.generateKeyPair();

        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

        Log.i("CERT", keyStore.getCertificate(KEY_1).toString());

        JSONObjectWriter signedData =
            new JSONObjectWriter(RawReader.getJSONResource(R.raw.json_data)).setSignature(
                new JSONAsymKeySigner(keyPair.getPrivate()).setPublicKey(keyPair.getPublic()));
        Log.i("SIGN", signedData.toString());
        JSONObjectReader reader =
                JSONParser.parse(signedData.serializeToBytes(JSONOutputFormats.PRETTY_PRINT));
        reader.getSignature(new JSONCryptoHelper.Options())
                .verify(new JSONAsymKeyVerifier(keyPair.getPublic()));

        signedData =
            new JSONObjectWriter(RawReader.getJSONResource(R.raw.json_data)).setSignature(
                new JSONAsymKeySigner(keyPair.getPrivate()).setPublicKey(keyPair.getPublic())
            .setAlgorithm(AsymSignatureAlgorithms.RSAPSS_SHA512));
        Log.i("SIGN", signedData.toString());
        reader =
            JSONParser.parse(signedData.serializeToBytes(JSONOutputFormats.PRETTY_PRINT));
        reader.getSignature(new JSONCryptoHelper.Options())
            .verify(new JSONAsymKeyVerifier(keyPair.getPublic()));

        kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);

        kpg.initialize(new KeyGenParameterSpec.Builder(
                KEY_2,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setCertificateNotBefore(new Date(System.currentTimeMillis() - 600000L))
                .setCertificateSubject(new X500Principal("CN=Android, SerialNumber=5678"))
                .build());

        keyPair = kpg.generateKeyPair();

        keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

        Log.i("CERT", keyStore.getCertificate(KEY_2).toString());

        signedData =
                new JSONObjectWriter(RawReader.getJSONResource(R.raw.json_data)).setSignature(
                        new JSONAsymKeySigner(keyPair.getPrivate())
                            .setPublicKey(keyPair.getPublic()));
        Log.i("SIGN", signedData.toString());
        reader =
                JSONParser.parse(signedData.serializeToBytes(JSONOutputFormats.PRETTY_PRINT));
        reader.getSignature(new JSONCryptoHelper.Options())
                .verify(new JSONAsymKeyVerifier(keyPair.getPublic()));

        signedData =
                new JSONObjectWriter(RawReader.getJSONResource(R.raw.json_data)).setSignature(
                        new JSONAsymKeySigner(keyPair.getPrivate()));
        Log.i("SIGN", signedData.toString());
        reader =
                JSONParser.parse(signedData.serializeToBytes(JSONOutputFormats.PRETTY_PRINT));
        reader.getSignature(new JSONCryptoHelper.Options().setPublicKeyOption(
                JSONCryptoHelper.PUBLIC_KEY_OPTIONS.FORBIDDEN))
                .verify(new JSONAsymKeyVerifier(keyPair.getPublic()));

        keyStore.setEntry(
                KEY_2,
                new KeyStore.PrivateKeyEntry(RawReader.ecKeyPair.getPrivate(), RawReader.ecCertPath),
                new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        .build());
        signedData =
                new JSONObjectWriter(RawReader.getJSONResource(R.raw.json_data)).setSignature(
                        new JSONX509Signer((PrivateKey)keyStore.getKey(KEY_2, null),
                                           convert(keyStore.getCertificateChain(KEY_2))));
        Log.i("CERTSIGN", signedData.toString());
        reader =
                JSONParser.parse(signedData.serializeToBytes(JSONOutputFormats.PRETTY_PRINT));
        reader.getSignature(new JSONCryptoHelper.Options()
                .setPublicKeyOption(JSONCryptoHelper.PUBLIC_KEY_OPTIONS.CERTIFICATE_PATH));
    }

    @Test
    public void attestationPlay() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
        kpg.initialize(new KeyGenParameterSpec.Builder(
                KEY_1, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setAttestationChallenge("hello world".getBytes("utf-8"))
                .build());

        KeyPair keyPair = kpg.generateKeyPair();

        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);

        for (Certificate certificate : keyStore.getCertificateChain(KEY_1)) {
            Log.i("ATT", certificate.toString());
        }
    }

    @Test
    public void useAppContext() throws Exception {
        assertEquals("org.webpki.androidjsondemo", RawReader.appContext.getPackageName());
    }
}
