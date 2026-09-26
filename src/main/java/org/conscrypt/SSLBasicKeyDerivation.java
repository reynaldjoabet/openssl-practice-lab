package org.conscrypt;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import javax.crypto.KDF;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import javax.net.ssl.SSLHandshakeException;

final class SSLBasicKeyDerivation implements SSLKeyDerivation {
    private final String hkdfAlg;
    private final SecretKey secret;
    private final byte[] hkdfInfo;
    private final int keyLen;

    SSLBasicKeyDerivation(SecretKey secret, HashAlg hashAlg, byte[] label,
            byte[] context) {
        this.hkdfAlg = hashAlg.hkdfAlgorithm;
        this.secret = secret;
        this.hkdfInfo = createHkdfInfo(label, context, hashAlg.hashLength);
        this.keyLen = hashAlg.hashLength;
    }

    @Override
    public SecretKey deriveKey(String type) throws IOException {
        try {
            KDF hkdf = KDF.getInstance(hkdfAlg);
            return hkdf.deriveKey(type,
                    HKDFParameterSpec.expandOnly(secret, hkdfInfo, keyLen));
        } catch (GeneralSecurityException gse) {
            throw new SSLHandshakeException("Could not generate secret", gse);
        }
    }

    private static byte[] createHkdfInfo(
            byte[] label, byte[] context, int length) {
        byte[] info = new byte[4 + label.length + context.length];
        ByteBuffer m = ByteBuffer.wrap(info);
        return info;
    }
}
