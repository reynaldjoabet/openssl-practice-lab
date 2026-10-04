package org.conscrypt;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.DecapsulateException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KDF;
import javax.crypto.KEM;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
//import javax.crypto.spec.HPKEParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.AsymmetricKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;

public class HPKE extends CipherSpi {

    private static final byte[] HPKE = new byte[]
            {'H', 'P', 'K', 'E'};
    private static final byte[] SEC = new byte[]
            {'s', 'e', 'c'};
    private static final byte[] PSK_ID_HASH = new byte[]
            {'p', 's', 'k', '_', 'i', 'd', '_', 'h', 'a', 's', 'h'};
    private static final byte[] INFO_HASH = new byte[]
            {'i', 'n', 'f', 'o', '_', 'h', 'a', 's', 'h'};
    private static final byte[] SECRET = new byte[]
            {'s', 'e', 'c', 'r', 'e', 't'};
    private static final byte[] EXP = new byte[]
            {'e', 'x', 'p'};
    private static final byte[] KEY = new byte[]
            {'k', 'e', 'y'};
    private static final byte[] BASE_NONCE = new byte[]
            {'b', 'a', 's', 'e', '_', 'n', 'o', 'n', 'c', 'e'};

    private static final int BEGIN = 1;
    private static final int EXPORT_ONLY = 2; // init done with aead_id == 65535
    private static final int ENCRYPT_AND_EXPORT = 3; // int done with AEAD
    private static final int AFTER_FINAL = 4; // after doFinal, need reinit internal cipher

    private int state = BEGIN;
    private Impl impl;

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        throw new NoSuchAlgorithmException(mode);
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        throw new NoSuchPaddingException(padding);
    }

    @Override
    protected int engineGetBlockSize() {
        if (state == ENCRYPT_AND_EXPORT || state == AFTER_FINAL) {
            return impl.aead.cipher.getBlockSize();
        } else {
            return 0;
        }
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        if (state == ENCRYPT_AND_EXPORT || state == AFTER_FINAL) {
            return impl.aead.cipher.getOutputSize(inputLen);
        } else {
            return 0;
        }
    }

    @Override
    protected byte[] engineGetIV() {
        return (state == BEGIN || impl.kemEncaps == null)
                ? null : impl.kemEncaps.clone();
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
            throws InvalidKeyException {
        throw new InvalidKeyException("HPKEParameterSpec must be provided");
    }

    @Override
    protected void engineInit(int opmode, Key key,
            AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        impl = new Impl(opmode);
        if (!(key instanceof AsymmetricKey ak)) {
            throw new InvalidKeyException("Not an asymmetric key");
        }
        if (params == null) {
            throw new InvalidAlgorithmParameterException(
                    "HPKEParameterSpec must be provided");
        } else if (params instanceof HPKEParameterSpec hps) {
           /// impl.init(ak, hps, random);
        } else {
            throw new InvalidAlgorithmParameterException(
                    "Unsupported params type: " + params.getClass());
        }
        if (impl.hasEncrypt()) {
            impl.aead.start(impl.opmode, impl.context.k, impl.context.computeNonce());
            state = ENCRYPT_AND_EXPORT;
        } else {
            state = EXPORT_ONLY;
        }
    }

    @Override
    protected void engineInit(int opmode, Key key,
            AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        throw new InvalidKeyException("HPKEParameterSpec must be provided");
    }

    // state is ENCRYPT_AND_EXPORT after this call succeeds
    private void maybeReinitInternalCipher() {
        if (state == BEGIN) {
            throw new IllegalStateException("Illegal state: " + state);
        }
        if (state == EXPORT_ONLY) {
            throw new UnsupportedOperationException();
        }
        if (state == AFTER_FINAL) {
            impl.aead.start(impl.opmode, impl.context.k, impl.context.computeNonce());
            state = ENCRYPT_AND_EXPORT;
        }
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        maybeReinitInternalCipher();
        return impl.aead.cipher.update(input, inputOffset, inputLen);
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
            byte[] output, int outputOffset) throws ShortBufferException {
        maybeReinitInternalCipher();
        return impl.aead.cipher.update(
                input, inputOffset, inputLen, output, outputOffset);
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        maybeReinitInternalCipher();
        impl.aead.cipher.updateAAD(src, offset, len);
    }

    @Override
    protected void engineUpdateAAD(ByteBuffer src) {
        maybeReinitInternalCipher();
        impl.aead.cipher.updateAAD(src);
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        maybeReinitInternalCipher();
        impl.context.IncrementSeq();
        state = AFTER_FINAL;
        if (input == null) { // a bug in doFinal(null, ?, ?)
            return impl.aead.cipher.doFinal();
        } else {
            return impl.aead.cipher.doFinal(input, inputOffset, inputLen);
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
            byte[] output, int outputOffset) throws ShortBufferException,
            IllegalBlockSizeException, BadPaddingException {
        maybeReinitInternalCipher();
        impl.context.IncrementSeq();
        state = AFTER_FINAL;
        return impl.aead.cipher.doFinal(
                input, inputOffset, inputLen, output, outputOffset);
    }

    //@Override
    protected SecretKey engineExportKey(String algorithm, byte[] context, int length) {
        if (state == BEGIN) {
            throw new IllegalStateException("State: " + state);
        } else {
            return impl.context.exportKey(algorithm, context, length);
        }
    }

    //@Override
    protected byte[] engineExportData(byte[] context, int length) {
        if (state == BEGIN) {
            throw new IllegalStateException("State: " + state);
        } else {
            return impl.context.exportData(context, length);
        }
    }

    private static class AEAD {
        final Cipher cipher;
        final int nk, nn, nt;
        final int id;
        public AEAD(int id) throws InvalidAlgorithmParameterException {
            this.id = id;
            try {
                switch (id) {
                    case HPKEParameterSpec.AEAD_AES_128_GCM -> {
                        cipher = Cipher.getInstance("AES/GCM/NoPadding");
                        nk = 16;
                    }
                    case HPKEParameterSpec.AEAD_AES_256_GCM -> {
                        cipher = Cipher.getInstance("AES/GCM/NoPadding");
                        nk = 32;
                    }
                    case HPKEParameterSpec.AEAD_CHACHA20_POLY1305 -> {
                        cipher = Cipher.getInstance("ChaCha20-Poly1305");
                        nk = 32;
                    }
                    case HPKEParameterSpec.EXPORT_ONLY -> {
                        cipher = null;
                        nk = -1;
                    }
                    default -> throw new InvalidAlgorithmParameterException(
                            "Unknown aead_id: " + id);
                }
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new ProviderException("Internal error", e);
            }
            nn = 12; nt = 16;
        }

        void start(int opmode, SecretKey key, byte[] nonce) {
            try {
                if (id == HPKEParameterSpec.AEAD_CHACHA20_POLY1305) {
                    cipher.init(opmode, key, new IvParameterSpec(nonce));
                } else {
                    cipher.init(opmode, key, new GCMParameterSpec(nt * 8, nonce));
                }
            } catch (InvalidAlgorithmParameterException | InvalidKeyException e) {
                throw new ProviderException("Internal error", e);
            }
        }
    }

    private static class Impl {

        final int opmode;

        HPKEParameterSpec params;
        Context context;
        AEAD aead;

        byte[] suite_id;
        String kdfAlg;
        int kdfNh;

        // only used on sender side
        byte[] kemEncaps;

        class Context {
            final SecretKey k; // null if only export
            final byte[] base_nonce;
            final SecretKey exporter_secret;

            byte[] seq = new byte[aead.nn];

            public Context(SecretKey sk, byte[] base_nonce,
                    SecretKey exporter_secret) {
                this.k = sk;
                this.base_nonce = base_nonce;
                this.exporter_secret = exporter_secret;
            }

            SecretKey exportKey(String algorithm, byte[] exporter_context, int length) {
                if (exporter_context == null) {
                    throw new IllegalArgumentException("Null exporter_context");
                }
                try {
                    var kdf = KDF.getInstance(kdfAlg);
                    return null;
                } catch (NoSuchAlgorithmException e) {
                    // algorithm not accepted by HKDF, length too big or too small
                    throw new IllegalArgumentException("Invalid input", e);
                }
            }

            byte[] exportData(byte[] exporter_context, int length) {
                if (exporter_context == null) {
                    throw new IllegalArgumentException("Null exporter_context");
                }
                try {
                    var kdf = KDF.getInstance(kdfAlg);
                    return null;
                } catch (NoSuchAlgorithmException e) {
                    // algorithm not accepted by HKDF, length too big or too small
                    throw new IllegalArgumentException("Invalid input", e);
                }
            }

            private byte[] computeNonce() {
                var result = new byte[aead.nn];
                for (var i = 0; i < result.length; i++) {
                    result[i] = (byte)(seq[i] ^ base_nonce[i]);
                }
                return result;
            }

            private void IncrementSeq() {
                for (var i = seq.length - 1; i >= 0; i--) {
                    if ((seq[i] & 0xff) == 0xff) {
                        seq[i] = 0;
                    } else {
                        seq[i]++;
                        return;
                    }
                }
                // seq >= (1 << (8*aead.Nn)) - 1 when this method is called
                throw new ProviderException("MessageLimitReachedError");
            }
        }

        public Impl(int opmode) {
            this.opmode = opmode;
        }

        public boolean hasEncrypt() {
            return params.aead_id() != 65535;
        }


        private static void checkMatch(boolean inSpec, AsymmetricKey k, int kem_id)
                throws InvalidKeyException, InvalidAlgorithmParameterException {
            var p = k.getParams();
            switch (p) {
                case ECParameterSpec ecp -> {
                    if ((!ECUtil.equals(ecp, CurveDB.P_256)
                            || kem_id != HPKEParameterSpec.KEM_DHKEM_P_256_HKDF_SHA256)
                            && (!ECUtil.equals(ecp, CurveDB.P_384)
                            || kem_id != HPKEParameterSpec.KEM_DHKEM_P_384_HKDF_SHA384)
                            && (!ECUtil.equals(ecp, CurveDB.P_521)
                            || kem_id != HPKEParameterSpec.KEM_DHKEM_P_521_HKDF_SHA512)) {
                        var name = ECUtil.getCurveName(ecp);
                        throw new InvalidAlgorithmParameterException(
                                name + " does not match " + kem_id);
                    }
                }
                case NamedParameterSpec ns -> {
                    var name = ns.getName();
                    if ((!name.equalsIgnoreCase("x25519")
                            || kem_id != HPKEParameterSpec.KEM_DHKEM_X25519_HKDF_SHA256)
                            && (!name.equalsIgnoreCase("x448")
                            || kem_id != HPKEParameterSpec.KEM_DHKEM_X448_HKDF_SHA512)) {
                        throw new InvalidAlgorithmParameterException(
                                name + " does not match " + kem_id);
                    }
                }
                case null, default -> {
                    var msg = k.getClass() + " does not match " + kem_id;
                    if (inSpec) {
                        throw new InvalidAlgorithmParameterException(msg);
                    } else {
                        throw new InvalidKeyException(msg);
                    }
                }
            }
        }

        private KEM kem() {
            try {
                return KEM.getInstance("DHKEM");
            } catch (NoSuchAlgorithmException e) {
                throw new ProviderException("Internal error", e);
            }
        }
    }

    private static boolean usePSK(SecretKey psk) {
        return psk != null;
    }

    private static byte[] concat(byte[]... inputs) {
        var o = new ByteArrayOutputStream();
        Arrays.stream(inputs).forEach(o::writeBytes);
        return o.toByteArray();
    }
}
