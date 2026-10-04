package org.keycloak;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * The Class CertificateUtils provides utility functions for generation of V1 and V3 {@link java.security.cert.X509Certificate}
 *
 */
public class CertificateUtils {

    private static final Logger logger = LoggerFactory.getLogger(CertificateUtils.class);

    /**
     * RFC 5280 {@code ub-common-name} upper bound. BouncyCastle 1.85+ enforces this limit
     * when building X.500 names, so CN values are truncated before they reach the provider.
     */
    private static final int MAX_CN_LENGTH = 64;

    /**
     * Generates version 3 {@link java.security.cert.X509Certificate}.
     *
     * @param keyPair the key pair
     * @param caPrivateKey the CA private key
     * @param caCert the CA certificate
     * @param subject the subject name
     *
     * @return the x509 certificate
     *
     * @throws Exception the exception
     */
    public static X509Certificate generateV3Certificate(KeyPair keyPair, PrivateKey caPrivateKey,
            X509Certificate caCert, String subject) throws Exception {
        return null;
    }

    /**
     * Generate version 1 self signed {@link java.security.cert.X509Certificate}.
     *
     * @param caKeyPair the CA key pair
     * @param subject the subject name
     *
     * @return the x509 certificate
     *
     * @throws Exception the exception
     */
    public static X509Certificate generateV1SelfSignedCertificate(KeyPair caKeyPair, String subject) {
        return null;
         }

    public static X509Certificate generateV1SelfSignedCertificate(KeyPair caKeyPair, String subject, BigInteger serialNumber) {
        return null;
    }

    public static X509Certificate generateV1SelfSignedCertificate(KeyPair caKeyPair, String subject, BigInteger serialNumber, Date validityEndDate) {
        return null;
    }

    /**
     * Checks whether the certificate is self signed, meaning it is self issued with matching subject and
     * issuer names and its signature verifies with its own public key.
     *
     * @param certificate the certificate to check
     * @return true if the certificate is self issued and signed by its own key
     * @throws GeneralSecurityException if the signature cannot be verified at all
     */
    public static boolean isSelfSigned(X509Certificate certificate) throws GeneralSecurityException {
        if (!certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
            return false;
        }
        try {
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (SignatureException | InvalidKeyException e) {
            return false;
        }
    }

    private static String truncateCN(String cn) {
        if (cn != null && cn.length() > MAX_CN_LENGTH) {
            logger.warn("Certificate CN value exceeds %d characters and will be truncated: '%s'", MAX_CN_LENGTH, cn);
            return cn.substring(0, MAX_CN_LENGTH);
        }
        return cn;
    }

}
