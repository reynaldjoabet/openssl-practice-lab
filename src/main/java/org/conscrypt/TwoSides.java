package org.conscrypt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HexFormat;

import javax.crypto.Cipher;
import javax.crypto.KDF;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.HKDFParameterSpec;

/** Client and server each derive "server write key" on their own, then use it in opposite directions. */
public class TwoSides {

    static SecretKey serverWriteKey(PrivateKey mine, PublicKey theirs) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(mine);
        ka.doPhase(theirs, true);
        byte[] shared = ka.generateSecret();                         // ECDHE: same on both sides

        KDF hkdf = KDF.getInstance("HKDF-SHA256");
        SecretKey secret = hkdf.deriveKey("Generic",     // stand-in for "s hs traffic"
                HKDFParameterSpec.ofExtract().addIKM(shared).thenExpand("server traffic".getBytes(), 32));
        return hkdf.deriveKey("AES",                 // stand-in for "key"
                HKDFParameterSpec.expandOnly(secret, "key".getBytes(), 16));
    }

    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
        KeyPair client = kpg.generateKeyPair();
        KeyPair server = kpg.generateKeyPair();
        // Only the PUBLIC keys cross the network.

        // --- on the server machine ---
        SecretKey serverCopy = serverWriteKey(server.getPrivate(), client.getPublic());
        // --- on the client machine ---
        SecretKey clientCopy = serverWriteKey(client.getPrivate(), server.getPublic());

        HexFormat hex = HexFormat.of();
        System.out.println("server's copy: " + hex.formatHex(serverCopy.getEncoded()));
        System.out.println("client's copy: " + hex.formatHex(clientCopy.getEncoded()));

        byte[] iv = new byte[12];
        // Server uses its copy to WRITE (encrypt)...
        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding");
        enc.init(Cipher.ENCRYPT_MODE, serverCopy, new GCMParameterSpec(128, iv));
        byte[] wire = enc.doFinal("hello from server".getBytes());
        System.out.println("on the wire:   " + hex.formatHex(wire));

        // ...client uses its copy to READ (decrypt).
        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding");
        dec.init(Cipher.DECRYPT_MODE, clientCopy, new GCMParameterSpec(128, iv));
        System.out.println("client reads:  " + new String(dec.doFinal(wire)));
    }
}
