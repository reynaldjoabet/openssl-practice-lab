package org.keycloak;

import java.io.DataInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


/**
 * Extract PrivateKey, PublicKey, and X509Certificate from a DER encoded byte array or file.  Usually
 * generated from openssl
 *
 */
public final class DerUtils {

    private DerUtils() {
    }

    public static PrivateKey decodePrivateKey(InputStream is)
            throws Exception {

        DataInputStream dis = new DataInputStream(is);
        byte[] keyBytes = new byte[dis.available()];
        dis.readFully(keyBytes);
        dis.close();

        return null;
    }

    public static PublicKey decodePublicKey(String encoded) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        return decodePublicKey(encoded, "RSA");
    }

    public static PublicKey decodePublicKey(String encoded, String type) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        byte[] der = Base64.getDecoder().decode(encoded);
        return decodePublicKey(der, type);
    }

    public static PublicKey decodePublicKey(byte[] der) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        return decodePublicKey(der, "RSA");
    }

    public static PublicKey decodePublicKey(byte[] der, String type){
        X509EncodedKeySpec spec =
                new X509EncodedKeySpec(der);
        KeyFactory kf = null;
        return null;
    }

}
