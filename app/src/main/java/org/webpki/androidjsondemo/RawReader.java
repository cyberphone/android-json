package org.webpki.androidjsondemo;

import android.content.Context;

import org.spongycastle.jce.provider.BouncyCastleProvider;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;

import java.security.KeyPair;
import java.security.Security;

import java.security.cert.X509Certificate;

public class RawReader {

    static Context appContext;

    public static byte[] dataToBeEncrypted;

    public static String rsaKeyId;
    public static String ecKeyId;

    public static KeyPair rsaKeyPair;
    public static KeyPair ecKeyPair;

    public static X509Certificate[] ecCertPath;

    static KeyPair currentKeyPair;

    static byte[] getRawResource(int resource) throws Exception {
        return ArrayUtil.getByteArrayFromInputStream(appContext.getResources()
                .openRawResource(resource));
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
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        ecKeyId = getKeyId(R.raw.ecprivatekey_jwk);
        ecKeyPair = currentKeyPair;
        rsaKeyId = getKeyId(R.raw.rsaprivatekey_jwk);
        rsaKeyPair = currentKeyPair;
        dataToBeEncrypted = getRawResource(R.raw.data2beencrypted_txt);
        ecCertPath = getJSONResource(R.raw.ec_certpath_json).getJSONArrayReader().getCertificatePath();
    }
}
