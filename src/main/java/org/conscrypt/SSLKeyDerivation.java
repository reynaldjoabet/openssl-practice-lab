package org.conscrypt;
import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.SecretKey;

interface SSLKeyDerivation {
    SecretKey deriveKey(String purpose) throws IOException;

    default byte[] deriveData(String purpose) throws IOException {
        throw new UnsupportedOperationException("No support for deriveData!");
    };
}
