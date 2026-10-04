package org.keycloak;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class KeyUtils {

    private static final String DEFAULT_MESSAGE_DIGEST = "SHA-256";

    private KeyUtils() {
    }

    public static SecretKey loadSecretKey(byte[] secret, String javaAlgorithmName) {
        return new SecretKeySpec(secret, javaAlgorithmName);
    }

    public static KeyPair generateRsaKeyPair(int keysize) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(keysize);
            KeyPair keyPair = generator.generateKeyPair();
            return keyPair;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static PublicKey extractPublicKey(PrivateKey key) {
        if (key == null) {
            return null;
        }

        try {
            RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) key;
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(rsaPrivateCrtKey.getModulus(), rsaPrivateCrtKey.getPublicExponent());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(publicKeySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyPair generateEddsaKeyPair(String curveName) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(curveName);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyPair generateEcKeyPair(String keySpecName) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            SecureRandom randomGen = new SecureRandom();
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(keySpecName);
            keyGen.initialize(ecSpec, randomGen);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String createKeyId(Key key) {
        try {
            return Base64Url.encode(MessageDigest.getInstance(DEFAULT_MESSAGE_DIGEST).digest(key.getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }


}
