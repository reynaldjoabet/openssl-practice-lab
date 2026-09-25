package org.conscrypt;

import java.security.Provider;
import java.util.*;


/**
 * The JSSE provider.
 */
public class SunJSSE extends java.security.Provider {

    @java.io.Serial
    private static final long serialVersionUID = 3231825739635378733L;

    private static final String info = "Sun JSSE provider" +
        "(PKCS12, SunX509/PKIX key/trust factories, " +
        "SSLv3/TLSv1/TLSv1.1/TLSv1.2/TLSv1.3/DTLSv1.0/DTLSv1.2)";

    public SunJSSE() {
        super("SunJSSE", "PROVIDER_VER", info);
        registerAlgorithms();
    }

    private void ps(String type, String algo, String cn,
            List<String> a, HashMap<String, String> attrs) {
        putService(new Provider.Service(this, type, algo, cn, a, attrs));
    }

    private void registerAlgorithms() {
        ps("Signature", "MD5andSHA1withRSA",
            "sun.security.ssl.RSASignature", null, null);

        ps("KeyManagerFactory", "SunX509",
            "sun.security.ssl.KeyManagerFactoryImpl$SunX509", null, null);
        ps("KeyManagerFactory", "NewSunX509",
            "sun.security.ssl.KeyManagerFactoryImpl$X509",
            List.of("PKIX"), null);

        ps("TrustManagerFactory", "SunX509",
            "sun.security.ssl.TrustManagerFactoryImpl$SimpleFactory",
            null, null);
        ps("TrustManagerFactory", "PKIX",
            "sun.security.ssl.TrustManagerFactoryImpl$PKIXFactory",
            List.of("SunPKIX", "X509", "X.509"), null);

        ps("SSLContext", "TLSv1",
            "sun.security.ssl.SSLContextImpl$TLS10Context",
            List.of("SSLv3"), null);
        ps("SSLContext", "TLSv1.1",
            "sun.security.ssl.SSLContextImpl$TLS11Context", null, null);
        ps("SSLContext", "TLSv1.2",
            "sun.security.ssl.SSLContextImpl$TLS12Context", null, null);
        ps("SSLContext", "TLSv1.3",
            "sun.security.ssl.SSLContextImpl$TLS13Context", null, null);
        ps("SSLContext", "TLS",
            "sun.security.ssl.SSLContextImpl$TLSContext",
            List.of("SSL"), null);

        ps("SSLContext", "DTLSv1.0",
            "sun.security.ssl.SSLContextImpl$DTLS10Context", null, null);
        ps("SSLContext", "DTLSv1.2",
            "sun.security.ssl.SSLContextImpl$DTLS12Context", null, null);
        ps("SSLContext", "DTLS",
            "sun.security.ssl.SSLContextImpl$DTLSContext", null, null);

        ps("SSLContext", "Default",
            "sun.security.ssl.SSLContextImpl$DefaultSSLContext", null, null);

        /*
         * KeyStore
         */
        ps("KeyStore", "PKCS12",
            "sun.security.pkcs12.PKCS12KeyStore", null, null);
    }
}
