package org.keycloak;
import java.io.IOException;


public enum ECDSAAlgorithm {
    ES256(64),
    ES384(96),
    ES512(132);

    private final int signatureLength;

    ECDSAAlgorithm(int signatureLength) {
        this.signatureLength = signatureLength;
    }

    public int getSignatureLength() {
        return this.signatureLength;
    }

    public static int getSignatureLength(String alg) {
        return valueOf(alg).getSignatureLength();
    }

}
