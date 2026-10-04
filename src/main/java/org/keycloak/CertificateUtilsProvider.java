package org.keycloak;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * The Class CertificateUtils provides utility functions for generation of V1 and V3 {@link java.security.cert.X509Certificate}
 *
 */
public interface CertificateUtilsProvider {

    public static final String CRL_DISTRIBUTION_POINTS_OID = "2.5.29.31";

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
    public X509Certificate generateV3Certificate(KeyPair keyPair, PrivateKey caPrivateKey, X509Certificate caCert,
            String subject) throws Exception;

    /**
     * Generate version 1 self signed {@link java.security.cert.X509Certificate}..
     *
     * @param caKeyPair the CA key pair
     * @param subject the subject name
     * 
     * @return the x509 certificate
     * 
     * @throws Exception the exception
     */
    public X509Certificate generateV1SelfSignedCertificate(KeyPair caKeyPair, String subject); 

    public X509Certificate generateV1SelfSignedCertificate(KeyPair caKeyPair, String subject, BigInteger serialNumber);

    public X509Certificate generateV1SelfSignedCertificate(KeyPair caKeyPair, String subject, BigInteger serialNumber, Date validityEndDate);

    public List<String> getCertificatePolicyList(X509Certificate cert) throws GeneralSecurityException;

    public List<String> getCRLDistributionPoints(X509Certificate cert) throws IOException;

    public X509Certificate createServicesTestCertificate(String dn,
                                             Date startDate,
                                             Date expiryDate,
                                             KeyPair keyPair,
                                             String... certificatePolicyOid);
        
}
