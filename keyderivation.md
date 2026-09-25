```java

import javax.crypto.KDF;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import javax.net.ssl.SSLHandshakeException;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import sun.security.util.KeyUtil;

/**
 * A common class for creating various KeyDerivation types.
 */
public class KAKeyDerivation implements SSLKeyDerivation {

    private final String algorithmName;
    private final HandshakeContext context;
    private final PrivateKey localPrivateKey;
    private final PublicKey peerPublicKey;

    KAKeyDerivation(String algorithmName,
            HandshakeContext context,
            PrivateKey localPrivateKey,
            PublicKey peerPublicKey) {
        this.algorithmName = algorithmName;
        this.context = context;
        this.localPrivateKey = localPrivateKey;
        this.peerPublicKey = peerPublicKey;
    }

    @Override
    public SecretKey deriveKey(String type) throws IOException {
        if (!context.negotiatedProtocol.useTLS13PlusSpec()) {
            return t12DeriveKey();
        } else {
            return t13DeriveKey(type);
        }
    }

    /**
     * Handle the TLSv1-1.2 objects, which don't use the HKDF algorithms.
     */
    private SecretKey t12DeriveKey() throws IOException {
        SecretKey preMasterSecret = null;
        try {
            KeyAgreement ka = KeyAgreement.getInstance(algorithmName);
            ka.init(localPrivateKey);
            ka.doPhase(peerPublicKey, true);
            preMasterSecret = ka.generateSecret("TlsPremasterSecret");
            SSLMasterKeyDerivation mskd =
                    SSLMasterKeyDerivation.valueOf(context.negotiatedProtocol);
            if (mskd == null) {
                // unlikely
                throw new SSLHandshakeException(
                        "No expected master key derivation for protocol: "
                        + context.negotiatedProtocol.name);
            }
            SSLKeyDerivation kd = mskd.createKeyDerivation(
                    context, preMasterSecret);
            return kd.deriveKey("MasterSecret");
        } catch (GeneralSecurityException gse) {
            throw new SSLHandshakeException("Could not generate secret", gse);
        } finally {
            KeyUtil.destroySecretKeys(preMasterSecret);
        }
    }

    /**
     * Handle the TLSv1.3 objects, which use the HKDF algorithms.
     */
    private SecretKey t13DeriveKey(String type)
            throws IOException {
        SecretKey sharedSecret = null;
        SecretKey earlySecret = null;
        SecretKey saltSecret = null;
        try {
            KeyAgreement ka = KeyAgreement.getInstance(algorithmName);
            ka.init(localPrivateKey);
            ka.doPhase(peerPublicKey, true);
            sharedSecret = ka.generateSecret("TlsPremasterSecret");

            CipherSuite.HashAlg hashAlg = context.negotiatedCipherSuite.hashAlg;
            SSLKeyDerivation kd = context.handshakeKeyDerivation;
            if (kd == null) {   // No PSK is in use.
                // If PSK is not in use, Early Secret will still be
                // HKDF-Extract(0, 0).
                byte[] zeros = new byte[hashAlg.hashLength];
                KDF hkdf = KDF.getInstance(hashAlg.hkdfAlgorithm);
                earlySecret = hkdf.deriveKey("TlsEarlySecret",
                        HKDFParameterSpec.ofExtract().addSalt(zeros)
                        .addIKM(zeros).extractOnly());
                kd = new SSLSecretDerivation(context, earlySecret);
            }

            // derive salt secret
            saltSecret = kd.deriveKey("TlsSaltSecret");

            // derive handshake secret
            // NOTE: do not reuse the HKDF object for "TlsEarlySecret" for
            // the handshake secret key derivation (below) as it may not
            // work with the "sharedSecret" obj.
            KDF hkdf = KDF.getInstance(hashAlg.hkdfAlgorithm);
            return hkdf.deriveKey(type, HKDFParameterSpec.ofExtract()
                    .addSalt(saltSecret).addIKM(sharedSecret).extractOnly());
        } catch (GeneralSecurityException gse) {
            throw new SSLHandshakeException("Could not generate secret", gse);
        } finally {
            KeyUtil.destroySecretKeys(sharedSecret, earlySecret, saltSecret);
        }
    }
}

```

```sh
Client                                              Server
ClientHello  (key_share = my ephemeral public key) ─►
                                                    picks group + cipher suite
                                         ◄─ ServerHello (key_share = its public key)
      ── both compute ECDHE shared secret → handshake keys; everything below is encrypted ──
                                         ◄─ EncryptedExtensions
                                         ◄─ Certificate
                                         ◄─ CertificateVerify (signature over transcript)
                                         ◄─ Finished (HMAC over transcript)
Finished ─►
      ── both switch to application keys ──
application data  ◄──────────────────────────────►  application data
                                         ◄─ NewSessionTicket (for later resumption)
```

TLS 1.3 needs only 1 round trip. The client guesses the key-exchange group and sends its public key right away, so from the ServerHello onward everything is encrypted.

```java
    private enum SecretSchedule {
        // Note that we use enum name as the key/secret name.
        TlsSaltSecret                       ("derived"),
        TlsExtBinderKey                     ("ext binder"),
        TlsResBinderKey                     ("res binder"),
        TlsClientEarlyTrafficSecret         ("c e traffic"),
        TlsEarlyExporterMasterSecret        ("e exp master"),
        TlsClientHandshakeTrafficSecret     ("c hs traffic"),
        TlsServerHandshakeTrafficSecret     ("s hs traffic"),
        TlsClientAppTrafficSecret           ("c ap traffic"),
        TlsServerAppTrafficSecret           ("s ap traffic"),
        TlsExporterMasterSecret             ("exp master"),
        TlsResumptionMasterSecret           ("res master");

        private final byte[] label;

        SecretSchedule(String label) {
            this.label = ("tls13 " + label).getBytes();
        }
    }
```

For every secret except the salt, the context is `transcriptHash`: the hash of the handshake messages, captured when this object was constructed.

For `TlsSaltSecret (label "derived")`, the RFC says the context is `Transcript-Hash("")`, the hash of empty input. For SHA-256 that's the well-known `e3b0c442…b855`

```sh
0 ──HKDF-Extract──► Early Secret ──► "res binder", "c e traffic"   (PSK / 0-RTT)
                         │ "derived"
ECDHE ─HKDF-Extract─► Handshake Secret ──► "c hs traffic", "s hs traffic"
                         │ "derived"
0 ──HKDF-Extract──► Master Secret ──► "c ap traffic", "s ap traffic",
                                      "exp master", "res master"
```

exactly the RFC 8446 §7.1 names, each prefixed with "tls13 "

This `info` value is what makes every derived secret different. Same parent secret with a different label gives a different output, and the same label over a different transcript also gives a different output.

*KDF.getInstance(hashAlg.hkdfAlgorithm)*

This gets the `"HKDF-SHA256"` or `"HKDF-SHA384"` implementation through the `javax.crypto.KDF` 

```sh
Early   = Extract(salt=0, ikm=0)                                   KAKeyDerivation.java:118
salt1   = Derive(Early, "derived", "")            TlsSaltSecret    KAKeyDerivation.java:125
HS      = Extract(salt1, ECDHE shared secret)                      KAKeyDerivation.java:132
          ├─ Derive(HS, "c hs traffic", CH..SH)                    ServerHello.java:609
          ├─ Derive(HS, "s hs traffic", CH..SH)                    ServerHello.java:640
salt2   = Derive(HS, "derived", "")               TlsSaltSecret    Finished.java:810
Master  = Extract(salt2, 0)                                        Finished.java:816
          ├─ Derive(Master, "s ap traffic", CH..server Finished)   Finished.java:824
          ├─ Derive(Master, "c ap traffic", CH..server Finished)
          ├─ Derive(Master, "exp master",   CH..server Finished)
          └─ Derive(Master, "res master",   CH..client Finished)   ← note: longer transcript
```

Every secret in TLS 1.3 is derived from three inputs: a parent secret, a label, and a context. For most secrets the context is the hash of the handshake messages so far. `TlsSaltSecret` is the one exception, so it gets its own branch.
```java
    if (hashAlg == HashAlg.H_SHA256) {
        expandContext = sha256EmptyDigest;
    } else if (hashAlg == HashAlg.H_SHA384) {
        expandContext = sha384EmptyDigest;
    }
```    
For the salt, the context is the hash of nothing: `Hash("")`. The two arrays are just those values precomputed

```sh
SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855   ← sha256EmptyDigest
SHA-384("") = 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da
              274edebfe76f65fbd51ad2f14898b95b                                   ← sha384EmptyDigest
```
he code picks between them because the hash function is set by the negotiated cipher suite: `SHA-256` for `TLS_AES_128_GCM_SHA256` and `TLS_CHACHA20_POLY1305_SHA256`, `SHA-384` for `TLS_AES_256_GCM_SHA384`.

```sh
Early Secret ──"derived"──► salt ──Extract with ECDHE──► Handshake Secret
Handshake Secret ──"derived"──► salt ──Extract with 0──► Master Secret
```

The salt's only job is to carry the previous stage forward into the next Extract. It isn't meant to bind any handshake messages; the traffic secrets derived at each stage already do that. So RFC 8446 §7.1 defines it as `Derive-Secret(secret, "derived", "")`, where the empty messages list means `Transcript-Hash("")`

HKDF has two operations, and TLS 1.3 uses both:
- `Extract(salt, input)`: "absorb new secret material." You give it some raw secret, like the ECDHE shared secret, and it produces one clean, uniformly random key.
- `Expand(key, label, context)`: "make named children from one key." From one key you get many independent outputs, one per label: `"c hs traffic"`, `"s hs traffic"`, `"derived"`, and so on.

So the schedule has one stage per moment, and each stage starts with an `Extract` to absorb whatever is new:
```sh
Early Secret     = Extract(salt = 0,  input = PSK or zeros)
Handshake Secret = Extract(salt = ?,  input = ECDHE shared secret)
Master Secret    = Extract(salt = ?,  input = zeros)
```
What goes in the ? The previous stage's secret, so nothing is lost. If the Handshake 

Passing the previous secret in as the salt makes every stage depend on everything that came before:
```sh
Handshake Secret = Extract(salt = <from Early Secret>,     input = ECDHE)
                 → depends on PSK AND ECDHE
Master Secret    = Extract(salt = <from Handshake Secret>, input = 0)
                 → depends on everything
```                 

`salt = Expand(Early Secret, label = "derived", context = Hash(""))`

```sh
Early   = Extract(0, 0)                    ← a public constant! same for everyone
salt1   = Expand(Early, "derived", H(""))  ← also a public constant
HS      = Extract(salt1, ECDHE)            ← only ECDHE is secret here
salt2   = Expand(HS, "derived", H(""))
Master  = Extract(salt2, 0)
```
```java
/**
     * Handle the TLSv1-1.2 objects, which don't use the HKDF algorithms.
     */
    private SecretKey t12DeriveKey() throws IOException {
        SecretKey preMasterSecret = null;
        try {
            KeyAgreement ka = KeyAgreement.getInstance(algorithmName);
            ka.init(localPrivateKey);
            ka.doPhase(peerPublicKey, true);
            preMasterSecret = ka.generateSecret("TlsPremasterSecret");
            SSLMasterKeyDerivation mskd =
                    SSLMasterKeyDerivation.valueOf(context.negotiatedProtocol);
            if (mskd == null) {
                // unlikely
                throw new SSLHandshakeException(
                        "No expected master key derivation for protocol: "
                        + context.negotiatedProtocol.name);
            }
            SSLKeyDerivation kd = mskd.createKeyDerivation(
                    context, preMasterSecret);
            return kd.deriveKey("MasterSecret");
        } catch (GeneralSecurityException gse) {
            throw new SSLHandshakeException("Could not generate secret", gse);
        } finally {
            KeyUtil.destroySecretKeys(preMasterSecret);
        }
    }
```    
```java
    /**
     * Handle the TLSv1.3 objects, which use the HKDF algorithms.
     */
    private SecretKey t13DeriveKey(String type)
            throws IOException {
        SecretKey sharedSecret = null;
        SecretKey earlySecret = null;
        SecretKey saltSecret = null;
        try {
            KeyAgreement ka = KeyAgreement.getInstance(algorithmName);
            ka.init(localPrivateKey);
            ka.doPhase(peerPublicKey, true);
            sharedSecret = ka.generateSecret("TlsPremasterSecret");

            CipherSuite.HashAlg hashAlg = context.negotiatedCipherSuite.hashAlg;
            SSLKeyDerivation kd = context.handshakeKeyDerivation;
            if (kd == null) {   // No PSK is in use.
                // If PSK is not in use, Early Secret will still be
                // HKDF-Extract(0, 0).
                byte[] zeros = new byte[hashAlg.hashLength];
                KDF hkdf = KDF.getInstance(hashAlg.hkdfAlgorithm);
                earlySecret = hkdf.deriveKey("TlsEarlySecret",
                        HKDFParameterSpec.ofExtract().addSalt(zeros)
                        .addIKM(zeros).extractOnly());
                kd = new SSLSecretDerivation(context, earlySecret);
            }

            // derive salt secret
            saltSecret = kd.deriveKey("TlsSaltSecret");

            // derive handshake secret
            // NOTE: do not reuse the HKDF object for "TlsEarlySecret" for
            // the handshake secret key derivation (below) as it may not
            // work with the "sharedSecret" obj.
            KDF hkdf = KDF.getInstance(hashAlg.hkdfAlgorithm);
            return hkdf.deriveKey(type, HKDFParameterSpec.ofExtract()
                    .addSalt(saltSecret).addIKM(sharedSecret).extractOnly());
        } catch (GeneralSecurityException gse) {
            throw new SSLHandshakeException("Could not generate secret", gse);
        } finally {
            KeyUtil.destroySecretKeys(sharedSecret, earlySecret, saltSecret);
        }
    }
```

The cipher suite picks the hash: `TLS_AES_128_GCM_SHA256` means 32, and `TLS_AES_256_GCM_SHA384` means 48. The TLS 1.3 key schedule sizes everything to that one number.

Extract naturally produces a hash-sized output, because it's one HMAC. Expand is asked for the same size, so Early, Handshake, Master and every traffic secret are all 32 bytes (SHA-256) or 48 bytes (SHA-384)

bytes: 32 for SHA-256, 48 for SHA-384.

SHA-256 processes data 64 bytes at a time. HMAC pads its key to this size internally

So shrinking does happen, but only when you ask for less than one block:
- AES-128 "key" is 16 bytes, first 16 bytes of the block
- ChaCha20 / AES-256 "key" is 32 bytes( 1 block)
- Every secret (hs traffic, ap traffic, derived, …)  is 32 bytes( 1 block)

With SHA-384 (48-byte blocks), the AES-256 key (32) and the IV (12) are both cut down from one 48-byte block.

In TLS 1.3 nothing ever needs more than one block, so every derivation is a single HMAC call. It's either used whole (the secrets) or truncated (keys and IVs).

A hash function can't process a message of arbitrary length all at once. It chops the input into fixed-size chunks and processes them one at a time. The block size is the size of those chunks.

Each step of SHA-256 is a function that takes the current state plus one block of message, and outputs a new state:

```sh
f( state [32 bytes], block [64 bytes] ) → new state [32 bytes]
       ▲                     ▲                    ▲
  carries everything     new input          same size as
  absorbed so far        this round         the old state
```  
It's called a compression function because it turns 96 bytes into 32.

A connection is only as strong as its weakest part, so the parts are paired to match:

```sh
TLS_AES_128_GCM_SHA256  →  AES-128 (128-bit) + SHA-256 (128-bit collision) + X25519 (~128-bit)
TLS_AES_256_GCM_SHA384  →  AES-256 (256-bit) + SHA-384 (192-bit collision) + P-384 (~192-bit)
```
Using SHA-512 with AES-128 and X25519 would make nothing stronger. An attacker would just target the 128-bit parts

```sh
person 1: 365/365 = 1.000
person 2: 364/365 = 0.997
person 3: 363/365 = 0.995
person 4: 362/365 = 0.992
person 5: 361/365 = 0.989   ← the number you calculated
```
no match among all 5 = 1.000 × 0.997 × 0.995 × 0.992 × 0.989 = 0.973
The 0.973 is the chance that all five people avoided everyone before them. For that, every step has to succeed, so the step chances multiply. Each multiplication pulls the total down a little more

The same applies further down the table. At 23 people the newest person alone has 343/365 ≈ 0.94. That still looks safe on its own. But it's multiplied by the 22 fractions before it, and the product is 0.493, below 50%.

RFC 8446 defines five TLS 1.3 cipher suites, and the JDK implements three of them:

| Suite | ID | JDK | Where |
|---|---|---|---|
| `TLS_AES_128_GCM_SHA256` | `0x1301` | ✅ supported | `CipherSuite.java:68` |
| `TLS_AES_256_GCM_SHA384` | `0x1302` | ✅ supported | `CipherSuite.java:65` |
| `TLS_CHACHA20_POLY1305_SHA256` | `0x1303` | ✅ supported | `CipherSuite.java:71` |
| `TLS_AES_128_CCM_SHA256` | `0x1304` | ❌ name only | `CipherSuite.java:555` |
| `TLS_AES_128_CCM_8_SHA256` | `0x1305` | ❌ name only | `CipherSuite.java:557` |

```java
    // TLS 1.3 cipher suites.
    TLS_AES_256_GCM_SHA384(
            0x1302, true, "TLS_AES_256_GCM_SHA384",
            ProtocolVersion.PROTOCOLS_OF_13, B_AES_256_GCM_IV, H_SHA384),
    TLS_AES_128_GCM_SHA256(
            0x1301, true, "TLS_AES_128_GCM_SHA256",
            ProtocolVersion.PROTOCOLS_OF_13, B_AES_128_GCM_IV, H_SHA256),
    TLS_CHACHA20_POLY1305_SHA256(
            0x1303, true, "TLS_CHACHA20_POLY1305_SHA256",
            ProtocolVersion.PROTOCOLS_OF_13, B_CC20_P1305, H_SHA256),
```            