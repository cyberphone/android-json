/*
 *  Copyright 2006-2016 WebPKI.org (http://webpki.org).
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
package org.webpki.androidjsondemo;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;

import android.util.Base64;

import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;

import org.spongycastle.jce.provider.BouncyCastleProvider;

import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.AlgorithmPreferences;

import org.webpki.json.JSONAsymKeySigner;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONSignatureDecoder;
import org.webpki.json.JSONDecryptionDecoder;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONSymKeySigner;
import org.webpki.json.JSONSymKeyVerifier;
import org.webpki.json.JSONX509Signer;

import org.webpki.json.encryption.DataEncryptionAlgorithms;
import org.webpki.json.encryption.KeyEncryptionAlgorithms;

import org.webpki.util.Base64URL;

import java.security.PublicKey;
import java.security.Security;
import java.security.KeyPair;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;

/**
 * This is a demonstration and test application for the WebPKI JSON, JCS and JEF components.
 */
public class MainActivity extends AppCompatActivity {

    enum SIG_TYPES {EC_KEY, RSA_KEY, PKI, SYMMETRIC_KEY}

    enum ENC_TYPES {EC_KEY, RSA_KEY, SYMMETRIC_KEY}

    static final byte[] SYMMETRIC_KEY = {
            (byte) 0xF4, (byte) 0xC7, (byte) 0x4F, (byte) 0x33,
            (byte) 0x98, (byte) 0xC4, (byte) 0x9C, (byte) 0xF4,
            (byte) 0x6D, (byte) 0x93, (byte) 0xEC, (byte) 0x98,
            (byte) 0x18, (byte) 0x83, (byte) 0x26, (byte) 0x61,
            (byte) 0xA4, (byte) 0x0B, (byte) 0xAE, (byte) 0x4D,
            (byte) 0x20, (byte) 0x4D, (byte) 0x75, (byte) 0x50,
            (byte) 0x36, (byte) 0x14, (byte) 0x10, (byte) 0x20,
            (byte) 0x74, (byte) 0x34, (byte) 0x69, (byte) 0x09 };

    static final String MY_KEY = "mykey";

    static final String RSA_KEYPAIR = "{" +
        "\"kty\":\"RSA\"," +
        "\"n\":\"y__yOXXaisKqCW2UCcOxpZRCCIdz04074KrnQXMOjSulnaB-kBUUV49Gc8jBI1k7IP0gLd" +
                "tIPjv2WVFaewt3bm2P2tymRYNw6trisoVtSswWhPDNR12ZEhUNh4vIyJsyYsZRg2y11_gh" +
                 "mK5PeRRxSqVwdga-HOuhXhN_KyD-CL7VxHQwpeAmwWXDvPweTpLWzlVoRzOSkCbsluzCW" +
                 "9Sh0rBHPe4pBScaY2oXQsiWt8nm3p6rgfBALsP_8pEdt5W-dHMihTYfsuLNroJRngocnv" +
                 "Phv44F1ODafUwfuLPe-LpG8zIzMGHnaD4GECOatrzOqPjUCnyiHchNFap1HU8khQ\"," +
        "\"e\":\"AQAB\"," +
        "\"d\":\"licHtT-H4kayPUpIgn9mDIf5qql4magFALMKkGQNu976gfEV9xts453zr1l-v3P4T6nAu8" +
                "ABhr0_8DIvNQ4VlFRUZDWwtM2wmU0PO3N2JG3fzW4oynScLHEOikxbNzz0czuh1-h2WEat" +
                "A-KZYHepg9YN1vHTkRnmpoYXPjmEgg4UBCPZWBYqiSOYTlmyMh3OJrHlhkaqMQZID1acU1" +
                "WPf5rtl9-s3DLYjaV9sgk-4dlmUShWoa4ruK1tL4hZV77tgHzG0D4jmnjc7aHnH20aCGoG" +
                "z0SkIDH5Y-UzotG-vKvVW_9LaXSrEcfuqs2YtaXeixB1Xp_EI3yntt1z-vPC6Q\"," +
        "\"p\":\"8VLnM8VF1pW1M31jQfec0h4NUO3WuLTR8xJJA1Qn572zYC1jd5myLOYIdZ1KpSDeTtydEi" +
                "R63OMeht4Ph5GgBd8d8Mfq5ANpyhmMO8eqegzx51AuKFRrRyLVtjgwdt3Y-xzsagR1ovHg" +
                "7C0nvMoBGBC6R4HqRmX7Yeq_Me4Kb2M\"," +
        "\"q\":\"2Gf00-LjLNyHjcPZGA4mEQ_Zo-5cj9t6X2-m8Vyu40Id1OOdzhbE1jifls0piTdD2_dxGc" +
                "YLhtDxJtvRr58YsArJSKOdDAZxETfh4f3K_QEoWiVFKd2Ig2P67k4D1sEPoFjM8ri3vFst" +
                "AawQv06nwgKtNWhfkOishKjpfEPJZPc\"," +
        "\"dp\":\"oykgNLqOa3Uw3C1MrM9TciTrb-o-oQdwY93bC6sch-yUmNRXSgfalcy5r3u3eknsxHkYo" +
                 "amUgD_25czBxzFIdm_R-HfScnN0VTZMwCZRNtAFxhVJ_-6D0cbVo6v96IA6Mh3uIgf92T" +
                 "ucjVJCabxSXQkCSVKnKQ3Olvd2abW9zG0\"," +
        "\"dq\":\"Uv5baL-E_Hl_CyFnKtCSTMzVXQdXPFyh6-P4FGzFLab3peO9a4JT7ww8OCtqmJM3VS7qk" +
                 "0Xeuc98DLkVC9NqNmmMlG0bF7eIuV_DI1af-LPu89ODWPD7H9jCLY6B7mSQR6CGyTeKT5" +
                 "RwCEojChtyPvej0e27aOmy8BWPpfahUDU\"," +
        "\"qi\":\"kyWCUFH8mC4evXRP0flATYdrAPIWwuLO9945Q5FXRT41jFWzAY8NO-pzPWIfo8uOWbgAx" +
                 "G83RzKlDqNyDfU3LPIoYuBC8sGwGhU12E4A0L7IoLWi6I3eXasiX1sd3ngjRuHDiBWD5D" +
                 "HdQySfsTJI5v0Tb4Kuop0KDvf9wNdlr60\"" +
    "}";

    static final String EC_KEYPAIR = "{" +
        "\"kty\":\"EC\","+
        "\"crv\":\"P-256\","+
        "\"x\":\"o4UjRyckZkIuVPq-1pDZ7NA-m9Z9YEMm4JQr8l4CANk\","+
        "\"y\":\"EJIlckodmvDfuCIqYapf7hxdTfH__M5Bc3VTjxUDA28\","+
        "\"d\":\"Nq2G4dhDJMQmXSCi_4rIbllXMRQJn6Q1-kDP2BeRUMI\"" +
    "}";

    static final String EC_CERTIFICATE = "[" +
    "\"MIIBtTCCAVmgAwIBAgIGAU-H595vMAwGCCqGSM49BAMCBQAwLzELMAkGA1UEBhMCRVUxIDAeBgNVBA" +
      "MTF1BheW1lbnQgTmV0d29yayBTdWIgQ0EzMB4XDTE0MDEwMTAwMDAwMFoXDTIwMDcxMDA5NTk1OVow" +
      "MTELMAkGA1UEBhMCRlIxDTALBgNVBAUTBDQ1MDExEzARBgNVBAMTCm15YmFuay5jb20wWTATBgcqhk" +
      "jOPQIBBggqhkjOPQMBBwNCAASjhSNHJyRmQi5U-r7WkNns0D6b1n1gQybglCvyXgIA2RCSJXJKHZrw" +
      "37giKmGqX-4cXU3x__zOQXN1U48VAwNvo10wWzAJBgNVHRMEAjAAMA4GA1UdDwEB_wQEAwIHgDAdBg" +
      "NVHQ4EFgQUOdV3H3r6TufkQh-dqhcXMrjUY2kwHwYDVR0jBBgwFoAUy0fdXq1oJ6GFAJo10qx609KD" +
      "ARAwDAYIKoZIzj0EAwIFAANIADBFAiEAluqzuTTzVBG74AoALaWRsRn9QALg2N6C3sIlztm6sPoCID" +
      "1ZnGnTrhz-CodxuGvg7fkOVfdffdSuEdyhQXemGtT4\", " +

    "\"MIIDcjCCAVqgAwIBAgIBAzANBgkqhkiG9w0BAQ0FADAwMQswCQYDVQQGEwJVUzEhMB8GA1UEAxMYUG" +
      "F5bWVudCBOZXR3b3JrIFJvb3QgQ0ExMB4XDTEyMDcxMDEwMDAwMFoXDTI1MDcxMDA5NTk1OVowLzEL" +
      "MAkGA1UEBhMCRVUxIDAeBgNVBAMTF1BheW1lbnQgTmV0d29yayBTdWIgQ0EzMFkwEwYHKoZIzj0CAQ" +
      "YIKoZIzj0DAQcDQgAEcX8CYrYFoQhPbTci93W5qyCx0i0H-FvmXIvH5XNBlnNLfPkRacqn0PRFNn4Z" +
      "4o3BVxI3x5yob9C7FqpKslcCgKNjMGEwDwYDVR0TAQH_BAUwAwEB_zAOBgNVHQ8BAf8EBAMCAQYwHQ" +
      "YDVR0OBBYEFMtH3V6taCehhQCaNdKsetPSgwEQMB8GA1UdIwQYMBaAFELvwS_Fk7IfHMWJeu-yhGdM" +
      "-5EiMA0GCSqGSIb3DQEBDQUAA4ICAQBNQdIOSU2fB5JjCO9Q0mCfOxDXFihMKSiOanAJ_r2rxGN7Up" +
      "rw32JPsJnQhuxbrwmniKgCmBVD6Jak4GtHSLVvJPjpf_Pe7pUbyMb6iNNeV3SmJvsHoE2m5WdSGxjI" +
      "PxK4NOBv3Mm3Ib1_kxyVceegHEHRUk5IXyQUNV1sUsxIypELjC8bAIvnMj_J1FlP8nsfehbibT3XH0" +
      "4uvX9dgNGexpz8BDLa0fEpLzrKoyMtUbSwg88_WsdPnkvp1fhiwCF9GpIHwsXi3Nv-Wdgdyn-hKFQe" +
      "6sP2FmsPDiI2qWqX7fEs0VN5Uo2oI5Q2T6673JiZnkycXYLNIRpc06KSTcs8B45u5NMAyvLx3l4S8M" +
      "y-HK4nfiqbF3TPVGJkq4aXAAZnhVcQTrO71tQ0BJMibKjz6sylBEnhlFQs3ICcesaGVXV3JVbwtf_O" +
      "kAUUUduYWOmUZU5ng3vNJV0ofqfvoNcBlVsrWpFNqImy2-icUxiad_8--ortiq4WG594Ap52CqXt7K" +
      "8UcZaMLDAj2COOmo1gy9iUjzgyzSqnYye2Gqr72ts5jd8B8wkM1rM0JDM6DvCyJgHVvc8VTNE7Mt2M" +
      "u9XsofQkdLdDgrPuo6AV88g1BGk7cY0FJMJFoBAlrj98A4KslbeGBV7AUGuzvS-w1VA6dRH6_5Fv2e" +
      "SHXW6pzA_D8Q\"]";

    static final String HTML_HEADER =
        "<html><head><style type='text/css'>" +
        "body {margin:12pt;font-size:10pt;color:#000000;font-family:Roboto;background-color:white}" +
        "div {text-align:center;padding:3pt 6pt 3pt 6pt;border-width:1px;margin-bottom:15pt;" +
        "border-style:solid;border-color:#a0a0a0;box-shadow:3pt 3pt 3pt #d0d0d0;" +
        "background:linear-gradient(to bottom, #eaeaea 14%,#fcfcfc 52%,#e5e5e5 89%);" +
        "border-radius:3pt;margin-left:auto;margin-right:auto}" +
        "</style>" +
        "<script type='text/javascript'>\n" +
        "'use strict';\n";

    static final String HTML_BODY =
        "</script></head><body>" +
        "<div style='width:4em;margin-left:0pt' onclick='WebPKI.homeScreen()'>Home</div>" +
        "<h3 style='text-align:center'>";

    WebView webView;

    void loadHtml(final String javaScript, final String header, final String body) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                webView.loadUrl("about:blank");
                try {
                    String html = Base64.encodeToString(new StringBuffer(HTML_HEADER)
                                    .append(javaScript)
                                    .append(HTML_BODY)
                                    .append(header)
                                    .append("</h3>")
                                    .append(body)
                                    .append("</body></html>").toString().getBytes("utf-8"), Base64.NO_WRAP);
                    webView.loadData(html, "text/html; charset=utf-8", "base64");
                } catch (Exception e) {
                }
            }
        });
    }

    String htmlIze(String s) {
        StringBuffer res = new StringBuffer();
        for (char c : s.toCharArray()) {
            if (c == '\n') {
                res.append("&#10;");
            } else if (c == '"') {
                res.append("&quot;");
            } else if (c == '&') {
                res.append("&amp;");
            } else if (c == '>') {
                res.append("&gt;");
            } else if (c == '<') {
                res.append("&lt;");
            } else {
                res.append(c);
            }
        }
        return res.toString();
    }

    void errorViev(Exception e) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintWriter printerWriter = new PrintWriter(baos);
        e.printStackTrace(printerWriter);
        printerWriter.flush();
        String msg = "Error description not available";
        try {
            msg = htmlIze(baos.toString("utf-8"));
        } catch (Exception e2) {
        }
        loadHtml("", "ERROR", "<pre style='color:red'>" + msg + "</pre>");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        webView = (WebView) findViewById(R.id.webView);
        WebSettings webSettings = webView.getSettings();
        webSettings.setJavaScriptEnabled(true);
        webView.addJavascriptInterface (this, "WebPKI");
        homeScreen();
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        setTitle("JSON, JCS and JEF Test/Demo");
     }

    void addCommandButton(StringBuffer buffer, String button, String executor) {
        buffer.append("<div style='width:15em' onclick='WebPKI.")
                .append(executor)
                .append("'>")
                .append(button)
                .append("</div>");
    }
    String executeButton(String executor) {
        return "<div style='width:6em;margin-bottom:0pt;margin-top:15pt' onclick='WebPKI." +
                executor + "'>Execute!</div>";
    }

    @JavascriptInterface
    public void homeScreen() {
        StringBuffer s = new StringBuffer();
        addCommandButton(s, "Sign JSON Data", "signData()");
        addCommandButton(s, "Verify JSON (JCS) Signature", "verifySignature()");
        addCommandButton(s, "Encrypt Arbitrary Data", "encryptData()");
        addCommandButton(s, "Decrypt JEF Encoded Data", "decryptData()");
        loadHtml("", "JSON Signatures and Encryption", s.toString());
    }

     void verifySignature(String jsonData) {
        loadHtml("", "Verify JSON (JCS) Signature",
                 "<textarea id='jsonData' style='width:100%;height:60%;word-break:break-all'>" +
                 htmlIze(jsonData) +
                 "</textarea>" +
                 executeButton("doVerify(document.getElementById(\"jsonData\").value)"));
    }

    @JavascriptInterface
    public void verifySignature() {
        // Show a pre-defined signed object as default
        verifySignature("{\n" +
            "  \"now\": \"2017-04-16T11:23:06Z\",\n" +
            "  \"escapeMe\": \"\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\\"\\/\",\n" +
            "  \"numbers\": [1e+30,4.5,6],\n" +
            "  \"signature\": {\n" +
            "    \"algorithm\": \"ES256\",\n" +
            "    \"publicKey\": {\n" +
            "      \"kty\": \"EC\",\n" +
            "      \"crv\": \"P-256\",\n" +
            "      \"x\": \"o4UjRyckZkIuVPq-1pDZ7NA-m9Z9YEMm4JQr8l4CANk\",\n" +
            "      \"y\": \"EJIlckodmvDfuCIqYapf7hxdTfH__M5Bc3VTjxUDA28\"\n" +
            "    },\n" +
            "    \"value\": \"UuxFcJx3G5CZDwOLqViKty8KF4ABNBdPXZEDDeMRPGW9wHUHvP7Db0t30cJv4wl8FKaSNASLJ_XBKv0x4LPfhA\"\n" +
            "  }\n" +
            "}");
    }

    @JavascriptInterface
    public void doVerify(String jsonData) {
        try {
            // Normally you know what to expect so this code is a bit over-the-top
            JSONObjectReader signedData = JSONParser.parse(jsonData);
            JSONSignatureDecoder.Options options = new JSONSignatureDecoder.Options();
            String algorithm =
                    signedData.getObject(JSONSignatureDecoder.SIGNATURE_JSON)
                            .getString(JSONSignatureDecoder.ALGORITHM_JSON);
            for (MACAlgorithms macs : MACAlgorithms.values()) {
                if (algorithm.equals(macs.getAlgorithmId(AlgorithmPreferences.JOSE_ACCEPT_PREFER))) {
                    options.setRequirePublicKeyInfo(false)
                            .setKeyIdOption(JSONSignatureDecoder.KEY_ID_OPTIONS.REQUIRED);
                }
            }
            JSONSignatureDecoder signature = signedData.getSignature(options);
            String key = null;
            switch (signature.getSignatureType()) {
                case ASYMMETRIC_KEY:
                    key = signature.getPublicKey().toString();
                    break;
                case X509_CERTIFICATE:
                    key = signature.getCertificatePath()[0].toString();
                    break;
                default:
                    signature.verify(new JSONSymKeyVerifier(SYMMETRIC_KEY));
                    key = Base64URL.encode(SYMMETRIC_KEY);
            }
            loadHtml("",
                    "Valid Signature!",
                    "<p><i>Signature type:</i> " + signature.getSignatureType().toString() +
                    "</p><p><i>Signature key:</i></p><pre style='color:green'>" + htmlIze(key) + "</pre>");
        } catch (Exception e) {
            errorViev(e);
        }
    }

    @JavascriptInterface
    public void signData() {
        StringBuffer choices = new StringBuffer();
        for (SIG_TYPES sigType : SIG_TYPES.values()) {
            choices.append("<tr><td><input type='radio' name='keyType' value='")
                   .append(sigType.toString())
                   .append(sigType == SIG_TYPES.EC_KEY ? "' checked>" : "'>")
                   .append(sigType.toString())
                   .append("</td></tr>");
        }
        loadHtml("function getRadio() {\n" +
                        "  return document.querySelector('input[name = \"keyType\"]:checked').value;\n" +
                        "}",
                "Sign JSON Data using JCS",
                "<textarea id='jsonData' style='width:100%;height:40%;word-break:break-all'>" +
                htmlIze(
                        "{\n" +
                        "  \"now\": \"2017-04-16T11:23:06Z\",\n" +
                        "  \"escapeMe\": \"\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\\"\\/\",\n" +
                        "  \"numbers\": [1e+30,4.5,6]\n" +
                        "}") +
                "</textarea>" +
                "<table style='margin-top:10pt;margin-left:auto;margin-right:auto;font-size:10pt'>" +
                choices.toString() +
                "</table>" +
                executeButton("doSign(document.getElementById(\"jsonData\").value, getRadio())"));
    }

    @JavascriptInterface
    public void doSign(String jsonData, String keyType) {
        try {
            SIG_TYPES sigType = SIG_TYPES.valueOf(keyType);
            JSONObjectWriter writer = new JSONObjectWriter(JSONParser.parse(jsonData));
            switch (sigType) {
                case EC_KEY:
                case RSA_KEY:
                    KeyPair keyPair = JSONParser.parse(sigType == SIG_TYPES.RSA_KEY ?
                                                                        RSA_KEYPAIR : EC_KEYPAIR).getKeyPair();
                    writer.setSignature(new JSONAsymKeySigner(keyPair.getPrivate(), keyPair.getPublic(), null));
                    break;
                case PKI:
                    writer.setSignature(new JSONX509Signer(
                            JSONParser.parse(EC_KEYPAIR).getKeyPair().getPrivate(),
                            JSONParser.parse(EC_CERTIFICATE).getJSONArrayReader().getCertificatePath(),
                            null));
                    break;
                default:
                    writer.setSignature(new JSONSymKeySigner(SYMMETRIC_KEY,
                                                             MACAlgorithms.HMAC_SHA256).setKeyId(MY_KEY));
            }
            verifySignature(writer.toString());
        } catch (Exception e) {
            errorViev(e);
        }
    }

    @JavascriptInterface
    public void encryptData() {
        StringBuffer choices = new StringBuffer();
        for (ENC_TYPES encType : ENC_TYPES.values()) {
            choices.append("<tr><td><input type='radio' name='keyType' value='")
                    .append(encType.toString())
                    .append(encType == ENC_TYPES.EC_KEY ? "' checked>" : "'>")
                    .append(encType.toString())
                    .append("</td></tr>");
        }
        loadHtml("function getRadio() {\n" +
                        "  return document.querySelector('input[name = \"keyType\"]:checked').value;\n" +
                        "}",
                "Encrypt <i>Arbitary</i> Data using JEF",
                "<textarea id='jsonData' style='width:100%;height:40%;word-break:break-all'>" +
                htmlIze(
                        "{\n" +
                        "  \"Encryption is fun\": true,\n" +
                        "  \"Encryption is easy\": \"Well...\"\n" +
                        "}") +
                "</textarea>" +
                "<table style='margin-top:10pt;margin-left:auto;margin-right:auto;font-size:10pt'>" +
                choices.toString() +
                "</table>" +
                executeButton("doEncrypt(document.getElementById(\"jsonData\").value, getRadio())"));
    }

    @JavascriptInterface
    public void doEncrypt(String arbitraryData, String keyType) {
        try {
            byte[] unencryptedData = arbitraryData.getBytes("UTF-8");
            ENC_TYPES encType = ENC_TYPES.valueOf(keyType);
            JSONObjectWriter writer = null;
            switch (encType) {
                case EC_KEY:
                case RSA_KEY:
                    PublicKey publicKey =
                            JSONParser.parse(encType == ENC_TYPES.RSA_KEY ?
                                                              RSA_KEYPAIR : EC_KEYPAIR).getKeyPair().getPublic();
                    writer = JSONObjectWriter.createEncryptionObject(unencryptedData,
                                                                     DataEncryptionAlgorithms.JOSE_A128GCM_ALG_ID,
                                                                     publicKey,
                                                                     null,
                                                                     encType == ENC_TYPES.RSA_KEY ?
                             KeyEncryptionAlgorithms.JOSE_RSA_OAEP_256_ALG_ID : KeyEncryptionAlgorithms.JOSE_ECDH_ES_A256KW_ALG_ID);
                    break;
                default:
                    writer = JSONObjectWriter.createEncryptionObject(unencryptedData,
                                                                     DataEncryptionAlgorithms.JOSE_A128CBC_HS256_ALG_ID,
                                                                     MY_KEY,
                                                                     SYMMETRIC_KEY);
            }
            decryptData(writer.toString());
        } catch (Exception e) {
            errorViev(e);
        }
    }

    void decryptData(String jsonEncryptionObject) {
        loadHtml("", "Decrypt JEF Encoded Data",
                "<textarea id='jsonData' style='width:100%;height:60%;word-break:break-all'>" +
                htmlIze(jsonEncryptionObject) +
                "</textarea>" +
                executeButton("doDecrypt(document.getElementById(\"jsonData\").value)"));
    }

    @JavascriptInterface
    public void decryptData() {
        // Show a pre-defined encrypted object as default
        decryptData("{\n" +
            "  \"algorithm\": \"A128CBC-HS256\",\n" +
            "  \"keyId\": \"mykey\",\n" +
            "  \"iv\": \"NcKwnGyZhtjKlM0lsg4eVQ\",\n" +
            "  \"tag\": \"zR7O4N9M0y-LTUpcYL9XBw\",\n" +
            "  \"cipherText\": \"Xm2MN7Z5AL1ce7uEmHDrFqs7wPHHTvC1mmUnRsEDfws\"\n" +
            "}");
    }

    @JavascriptInterface
    public void doDecrypt(String jsonEncryptionObject) {
        try {
            JSONDecryptionDecoder encryptionObject = JSONParser.parse(jsonEncryptionObject).getEncryptionObject();
            String decryptedData = null;
            if (encryptionObject.isSharedSecret()) {
                decryptedData = new String(encryptionObject.getDecryptedData(SYMMETRIC_KEY),"UTF-8");
            } else {
                KeyPair keyPair =
                        JSONParser.parse(encryptionObject.getKeyEncryptionAlgorithm().isRsa() ?
                                RSA_KEYPAIR : EC_KEYPAIR).getKeyPair();
                decryptedData = new String(encryptionObject.getDecryptedData(keyPair.getPrivate()),"UTF-8");
            }
            loadHtml("",
                    "Decrypted Data",
                    "<p><i>Decryption type:</i> " + (encryptionObject.isSharedSecret() ? "SYMMETRIC_KEY" : "ASYMMETRIC_KEY") + "</p><pre style='color:blue'>" + htmlIze(decryptedData) + "</pre>");
        } catch (Exception e) {
            errorViev(e);
        }
    }
}
