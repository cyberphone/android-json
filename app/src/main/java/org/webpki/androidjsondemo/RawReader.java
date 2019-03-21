package org.webpki.androidjsondemo;

import android.content.Context;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;

import java.security.KeyPair;

import java.security.cert.X509Certificate;

public class RawReader {

    static Context appContext;

    public static byte[] dataToBeEncrypted;

    public static String rsaKeyId;
    public static String ecKeyId;

    public static KeyPair rsaKeyPair;
    public static KeyPair ecKeyPair;

    public static X509Certificate[] ecCertPath;

    public static byte[] secretKey;
    public static String secretKeyId;

    static KeyPair currentKeyPair;

    static byte[] getRawResource(int resource) throws Exception {
        return ArrayUtil.getByteArrayFromInputStream(appContext.getResources()
                .openRawResource(resource));
    }

    static String getStringResource(int resource) throws Exception {
        return new String(getRawResource(resource), "utf-8");
    }

    static JSONObjectReader getJSONResource(int resource) throws Exception {
        return JSONParser.parse(getRawResource(resource));
    }

    static String getKeyId(int resource) throws Exception {
        JSONObjectReader jwk = getJSONResource(resource);
        String keyId = jwk.getString("kid");
        jwk.removeProperty("kid");
        currentKeyPair = jwk.getKeyPair();
        return keyId;
    }
    RawReader(Context appContext) throws Exception {
        this.appContext = appContext;
        ecKeyId = getKeyId(R.raw.ecprivatekey_jwk);
        ecKeyPair = currentKeyPair;
        rsaKeyId = getKeyId(R.raw.rsaprivatekey_jwk);
        rsaKeyPair = currentKeyPair;
        dataToBeEncrypted = getRawResource(R.raw.data2beencrypted_txt);
        ecCertPath = getJSONResource(R.raw.ec_certpath_json).getJSONArrayReader().getCertificatePath();
        secretKey = Base64URL.decode(getStringResource(R.raw.secretkey_b64u));
        secretKeyId = getStringResource(R.raw.secret_key_id_txt);
    }
}
