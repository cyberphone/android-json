package org.webpki.androidjsondemo;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;

import org.spongycastle.jce.provider.BouncyCastleProvider;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.SignatureWrapper;
import org.webpki.crypto.SignerInterface;
import org.webpki.json.JSONAsymKeySigner;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONSignatureDecoder;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONSignatureTypes;
import org.webpki.json.JSONX509Signer;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.KeyPair;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.security.cert.X509Certificate;

public class MainActivity extends AppCompatActivity {

    enum SIG_TYPES {EC_KEY, RSA_KEY, PKI, SYMMETRIC_KEY};

    static final String RSA_KEYPAIR = "{" +
        "\"kty\":\"RSA\"," +
        "\"n\":\"y__yOXXaisKqCW2UCcOxpZRCCIdz04074KrnQXMOjSulnaB-kBUUV49Gc8jBI1k7IP0gLdtI" +
                "Pjv2WVFaewt3bm2P2tymRYNw6trisoVtSswWhPDNR12ZEhUNh4vIyJsyYsZRg2y11_ghmK5" +
                "PeRRxSqVwdga-HOuhXhN_KyD-CL7VxHQwpeAmwWXDvPweTpLWzlVoRzOSkCbsluzCW9Sh0r" +
                "BHPe4pBScaY2oXQsiWt8nm3p6rgfBALsP_8pEdt5W-dHMihTYfsuLNroJRngocnvPhv44F1" +
                "ODafUwfuLPe-LpG8zIzMGHnaD4GECOatrzOqPjUCnyiHchNFap1HU8khQ\"," +
        "\"e\":\"AQAB\"," +
        "\"d\":\"licHtT-H4kayPUpIgn9mDIf5qql4magFALMKkGQNu976gfEV9xts453zr1l-v3P4T6nAu8AB" +
                "hr0_8DIvNQ4VlFRUZDWwtM2wmU0PO3N2JG3fzW4oynScLHEOikxbNzz0czuh1-h2WEatA-K" +
                "ZYHepg9YN1vHTkRnmpoYXPjmEgg4UBCPZWBYqiSOYTlmyMh3OJrHlhkaqMQZID1acU1WPf5" +
                "rtl9-s3DLYjaV9sgk-4dlmUShWoa4ruK1tL4hZV77tgHzG0D4jmnjc7aHnH20aCGoGz0SkI" +
                "DH5Y-UzotG-vKvVW_9LaXSrEcfuqs2YtaXeixB1Xp_EI3yntt1z-vPC6Q\"," +
        "\"p\":\"8VLnM8VF1pW1M31jQfec0h4NUO3WuLTR8xJJA1Qn572zYC1jd5myLOYIdZ1KpSDeTtydEiR6" +
                "3OMeht4Ph5GgBd8d8Mfq5ANpyhmMO8eqegzx51AuKFRrRyLVtjgwdt3Y-xzsagR1ovHg7C0" +
                "nvMoBGBC6R4HqRmX7Yeq_Me4Kb2M\"," +
        "\"q\":\"2Gf00-LjLNyHjcPZGA4mEQ_Zo-5cj9t6X2-m8Vyu40Id1OOdzhbE1jifls0piTdD2_dxGcYL" +
                "htDxJtvRr58YsArJSKOdDAZxETfh4f3K_QEoWiVFKd2Ig2P67k4D1sEPoFjM8ri3vFstAaw" +
                "Qv06nwgKtNWhfkOishKjpfEPJZPc\"," +
        "\"dp\":\"oykgNLqOa3Uw3C1MrM9TciTrb-o-oQdwY93bC6sch-yUmNRXSgfalcy5r3u3eknsxHkYoam" +
                "UgD_25czBxzFIdm_R-HfScnN0VTZMwCZRNtAFxhVJ_-6D0cbVo6v96IA6Mh3uIgf92TucjV" +
                "JCabxSXQkCSVKnKQ3Olvd2abW9zG0\"," +
        "\"dq\":\"Uv5baL-E_Hl_CyFnKtCSTMzVXQdXPFyh6-P4FGzFLab3peO9a4JT7ww8OCtqmJM3VS7qk0X" +
                "euc98DLkVC9NqNmmMlG0bF7eIuV_DI1af-LPu89ODWPD7H9jCLY6B7mSQR6CGyTeKT5RwCE" +
                "ojChtyPvej0e27aOmy8BWPpfahUDU\"," +
        "\"qi\":\"kyWCUFH8mC4evXRP0flATYdrAPIWwuLO9945Q5FXRT41jFWzAY8NO-pzPWIfo8uOWbgAxG8" +
                "3RzKlDqNyDfU3LPIoYuBC8sGwGhU12E4A0L7IoLWi6I3eXasiX1sd3ngjRuHDiBWD5DHdQy" +
                "SfsTJI5v0Tb4Kuop0KDvf9wNdlr60\"" +
    "}";

    static final String EC_KEYPAIR = "{" +
        "\"kty\":\"EC\","+
        "\"crv\":\"P-256\","+
        "\"x\":\"o4UjRyckZkIuVPq-1pDZ7NA-m9Z9YEMm4JQr8l4CANk\","+
        "\"y\":\"EJIlckodmvDfuCIqYapf7hxdTfH__M5Bc3VTjxUDA28\","+
        "\"d\":\"Nq2G4dhDJMQmXSCi_4rIbllXMRQJn6Q1-kDP2BeRUMI\"" +
    "}";

    static final String EC_CERTIFICATE = "{\"certificatePath\": [" +
    "\"MIIBtTCCAVmgAwIBAgIGAU-H595vMAwGCCqGSM49BAMCBQAwLzELMAkGA1UEBhMCRVUxIDAeBgNVBA" +
      "MTF1BheW1lbnQgTmV0d29yayBTdWIgQ0EzMB4XDTE0MDEwMTAwMDAwMFoXDTIwMDcxMDA5NTk1OVowMTEL" +
      "MAkGA1UEBhMCRlIxDTALBgNVBAUTBDQ1MDExEzARBgNVBAMTCm15YmFuay5jb20wWTATBgcqhkjOPQ" +
      "IBBggqhkjOPQMBBwNCAASjhSNHJyRmQi5U-r7WkNns0D6b1n1gQybglCvyXgIA2RCSJXJKHZrw37giKmGq" +
      "X-4cXU3x__zOQXN1U48VAwNvo10wWzAJBgNVHRMEAjAAMA4GA1UdDwEB_wQEAwIHgDAdBgNVHQ4EFg" +
      "QUOdV3H3r6TufkQh-dqhcXMrjUY2kwHwYDVR0jBBgwFoAUy0fdXq1oJ6GFAJo10qx609KDARAwDAYIKoZI" +
    "zj0EAwIFAANIADBFAiEAluqzuTTzVBG74AoALaWRsRn9QALg2N6C3sIlztm6sPoCID1ZnGnTrhz-Codxu" +
    "Gvg7fkOVfdffdSuEdyhQXemGtT4\", " +

    "\"MIIDcjCCAVqgAwIBAgIBAzANBgkqhkiG9w0BAQ0FADAwMQswCQYDVQQGEwJVUzEhMB8GA1UEAxM" +
            "YUGF5bWVudCBOZXR3b3JrIFJvb3QgQ0ExMB4XDTEyMDcxMDEwMDAwMFoXDTI1MDcxMDA5NTk1OVowLzELMAkG" +
    "A1UEBhMCRVUxIDAeBgNVBAMTF1BheW1lbnQgTmV0d29yayBTdWIgQ0EzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEc" +
            "X8CYrYFoQhPbTci93W5qyCx0i0H-FvmXIvH5XNBlnNLfPkRacqn0PRFNn4Z4o3BVxI3" +
    "x5yob9C7FqpKslcCgKNjMGEwDwYDVR0TAQH_BAUwAwEB_zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0" +
            "OBBYEFMtH3V6taCehhQCaNdKsetPSgwEQMB8GA1UdIwQYMBaAFELvwS_Fk7IfHMWJeu-yhGdM-5EiMA0GCSqG" +
            "SIb3DQEBDQUAA4ICAQBNQdIOSU2fB5JjCO9Q0mCfOxDXFihMKSiOanAJ_r2rxGN7Uprw32JPsJnQhuxbrwmniKg" +
                    "CmBVD6Jak4GtHSLVvJPjpf_Pe7pUbyMb6iNNeV3SmJvsHoE2m5WdSGxjIPxK4NOBv3Mm3Ib1_" +
    "kxyVceegHEHRUk5IXyQUNV1sUsxIypELjC8bAIvnMj_J1FlP8nsfehbibT3XH04uvX9dgNGexpz8BDLa0fEpLzrKoyMt" +
                    "UbSwg88_WsdPnkvp1fhiwCF9GpIHwsXi3Nv-Wdgdyn-hKFQe6sP2FmsPDiI2qWqX7fEs" +
    "0VN5Uo2oI5Q2T6673JiZnkycXYLNIRpc06KSTcs8B45u5NMAyvLx3l4S8My-HK4nfiqbF3TPVGJkq4aXAAZn" +
                    "hVcQTrO71tQ0BJMibKjz6sylBEnhlFQs3ICcesaGVXV3JVbwtf_OkAUUUduYWOmUZU5ng3vNJV0o" +
    "fqfvoNcBlVsrWpFNqImy2-icUxiad_8--ortiq4WG594Ap52CqXt7K8UcZaMLDAj2COOmo1gy9iUjzgyzSqnYye2Gqr72" +
                    "ts5jd8B8wkM1rM0JDM6DvCyJgHVvc8VTNE7Mt2Mu9XsofQkdLdDgrPuo6AV88g1BGk7" +
    "cY0FJMJFoBAlrj98A4KslbeGBV7AUGuzvS-w1VA6dRH6_5Fv2eSHXW6pzA_D8Q\"]}";

    static final String HTML_HEADER = "<html><head><style type='text/css'>\n" +
                                      "body {margin:12pt;font-size:10pt;color:#000000;font-family:Roboto;background-color:white}\n" +
                                      "div {text-align:center;padding:3pt 6pt 3pt 6pt;border-width:1px;margin-bottom:15pt;" +
                                      "border-style:solid;border-color:#808080;background-color:#f0f0f0;margin-left:auto;margin-right:auto}" +
                                      "</style>\n" +
                                      "<script type='text/javascript'>\n" +
                                      "'use strict';\n";

    static final String HTML_BODY = "</script>" +
                                    "</head><body><div style='width:4em;margin-left:0pt' onclick='WebPKI.homeScreen()'>Home</div><h3 style='text-align:center'>";

    WebView webView;

    void loadHtml(final String javaScript, final String header, final String body) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                webView.loadUrl("about:blank");
                String html = new StringBuffer(HTML_HEADER)
                        .append(javaScript)
                        .append(HTML_BODY)
                        .append(header)
                        .append("</h3>")
                        .append(body)
                        .append("</body></html>").toString();
                webView.loadData(html, "text/html; charset=utf-8", null);
            }
        });
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
     }

    private void add(StringBuffer buffer, String button, String executor) {
        buffer.append("<div style='width:15em' onclick='WebPKI.")
                .append(executor)
                .append("'>")
                .append(button)
                .append("</div>");
    }
    private String executeButton(String executor) {
        return "<div style='width:6em;margin-bottom:0pt;margin-top:15pt' onclick='WebPKI." +
                executor + "'>Execute!</div>";
    }

    @JavascriptInterface
    public void homeScreen() {
        StringBuffer s = new StringBuffer();
        add(s, "Sign JSON Data", "signData()");
        add(s, "Verify JSON (JCS) Signature", "verifySignature()");
        loadHtml("", "JSON Signatures and Encryption", s.toString());
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

     private void verifySignature(String jsonData) {
        loadHtml("", "Verify JSON (JCS) Signature",
                 "<textarea id='jsonData' style='width:100%;height:60%;word-break:break-all'>" +
                 htmlIze(jsonData) +
                 "</textarea>" +
                 executeButton("doVerify(document.getElementById(\"jsonData\").value)"));
    }

    @JavascriptInterface
    public void verifySignature() {
        verifySignature("{\n" +
            "  \"now\": \"2017-04-16T11:23:06Z\",\n" +
            "  \"escapeMe\": \"\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\\"\\/\",\n" +
            "  \"numbers\": [1e+30,4.5,6],\n" +
            "  \"signature\": {\n" +
            "    \"algorithm\": \"ES256\",\n" +
            "    \"publicKey\": {\n" +
            "      \"kty\": \"EC\",\n" +
            "      \"crv\": \"P-256\",\n" +
            "      \"x\": \"vlYxD4dtFJOp1_8_QUcieWCW-4KrLMmFL2rpkY1bQDs\",\n" +
            "      \"y\": \"fxEF70yJenP3SPHM9hv-EnvhG6nXr3_S-fDqoj-F6yM\"\n" +
            "    },\n" +
            "    \"value\": \"hp6af4GTZMr2fM8A1QeanPD4IcvlV0ToiKA0NDrtsmyGxDQST24ehsAVRzVHXSGM1O1GG0xO3ev4LbvNNRpH5g\"\n" +
            "  }\n" +
            "}");
    }

    private String htmlIze(String s) {
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

    public void errorViev(Exception e) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintWriter printerWriter = new PrintWriter(baos);
        e.printStackTrace(printerWriter);
        printerWriter.flush();
        StringBuffer msg = new StringBuffer();
        try {
             for (char c : baos.toString("utf-8").toCharArray()) {
                if (c == '\n') {
                    msg.append("%0A");
                } else {
                    msg.append(c);
                }
            }
        } catch (Exception e2) {
            msg.append("N/A");
        }
        loadHtml("", "ERROR", "<pre style='color:red'>" + msg.toString() + "</pre>");
    }

    @JavascriptInterface
    public void doVerify(String jsonData) {
        try {
            JSONSignatureDecoder signature = JSONParser.parse(jsonData).getSignature();
            String key = null;
            switch (signature.getSignatureType()) {
                case ASYMMETRIC_KEY:
                    key = signature.getPublicKey().toString();
                    break;
                case X509_CERTIFICATE:
                    key = signature.getCertificatePath()[0].toString();
                    break;
                default:
                    key = "Symmetric key";
            }
            loadHtml("", "Valid Signature", "<pre>" + htmlIze(key) + "</pre>");
        } catch (Exception e) {
            errorViev(e);
        }
    }

    @JavascriptInterface
    public void doSign(String jsonData, String keyType) {
        try {
            SIG_TYPES sigType = SIG_TYPES.valueOf(keyType);
            JSONObjectWriter writer = new JSONObjectWriter(JSONParser.parse(jsonData));
            switch (sigType) {
                case EC_KEY:
                case RSA_KEY:
                    final KeyPair keyPair =
                            JSONParser.parse(sigType == SIG_TYPES.RSA_KEY ?
                                                              RSA_KEYPAIR : EC_KEYPAIR).getKeyPair();
                    writer.setSignature(new JSONAsymKeySigner(new AsymKeySignerInterface() {
                        @Override
                        public byte[] signData(byte[] data, AsymSignatureAlgorithms algorithm) throws IOException {
                            try {
                                return new SignatureWrapper(algorithm, keyPair.getPrivate()).update(data).sign();
                            } catch (GeneralSecurityException e) {
                                throw new IOException(e);
                            }
                        }
                        @Override
                        public PublicKey getPublicKey() throws IOException {
                            return keyPair.getPublic();
                        }
                    }));
                    break;
                case PKI:
                    final PrivateKey privateKey =
                            JSONParser.parse(EC_KEYPAIR).getKeyPair().getPrivate();

                    writer.setSignature(new JSONX509Signer(new SignerInterface() {
                        @Override
                        public byte[] signData(byte[] data, AsymSignatureAlgorithms algorithm) throws IOException {
                            try {
                                return new SignatureWrapper(algorithm, privateKey).update(data).sign();
                            } catch (GeneralSecurityException e) {
                                throw new IOException(e);
                            }
                        }
                        @Override
                        public X509Certificate[] getCertificatePath() throws IOException {
                            return JSONParser.parse(EC_CERTIFICATE).getCertificatePath();
                        }
                    }));
                    break;
            }
            verifySignature(writer.toString());
        } catch (Exception e) {
            errorViev(e);
        }
    }
}
