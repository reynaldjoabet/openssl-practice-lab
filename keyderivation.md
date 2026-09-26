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

 A key derivation function (KDF) is a basic and essential component of
   cryptographic systems.  Its goal is to take some source of initial
   keying material and derive from it one or more cryptographically
   strong secret keys

    HKDF follows the "extract-then-expand" paradigm, where the KDF
   logically consists of two modules.  The first stage takes the input
   keying material and "extracts" from it a fixed-length pseudorandom
   key K.  The second stage "expands" the key K into several additional
   pseudorandom keys (the output of the KDF).


   In many applications, the input keying material is not necessarily
   distributed uniformly, and the attacker may have some partial
   knowledge about it (for example, a Diffie-Hellman value computed by a
   key exchange protocol) or even partial control of it (as in some
   entropy-gathering applications).  Thus, the goal of the "extract"
   stage is to "concentrate" the possibly dispersed entropy of the input
   keying material into a short, but cryptographically strong,
   pseudorandom key.  In some applications, the input may already be a
   good pseudorandom key; in these cases, the "extract" stage is not
   necessary, and the "expand" part can be used alone.

   The second stage "expands" the pseudorandom key to the desired
   length; the number and lengths of the output keys depend on the
   specific cryptographic algorithms for which the keys are needed

```java
// derive salt secret
   saltSecret = kd.deriveKey("TlsSaltSecret");
   // derive application secrets
   HashAlg hashAlg = shc.negotiatedCipherSuite.hashAlg;
   KDF hkdf = KDF.getInstance(hashAlg.hkdfAlgorithm);
   byte[] zeros = new byte[hashAlg.hashLength];
   SecretKey masterSecret = hkdf.deriveKey("TlsMasterSecret",
           HKDFParameterSpec.ofExtract().addSalt(saltSecret)
           .addIKM(zeros).extractOnly());
   SSLKeyDerivation secretKD =
           new SSLSecretDerivation(shc, masterSecret);
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

```java
      try {
            CipherSuite.HashAlg hashAlg = hc.negotiatedCipherSuite.hashAlg;
            KDF hkdf = KDF.getInstance(hashAlg.hkdfAlgorithm);
            SecretKey earlySecret = hkdf.deriveKey("TlsEarlySecret",
                    HKDFParameterSpec.ofExtract().addIKM(psk)
                    .addSalt(new byte[hashAlg.hashLength]).extractOnly());
            hc.handshakeKeyDerivation =
                    new SSLSecretDerivation(hc, earlySecret);
        } catch (GeneralSecurityException gse) {
            throw new SSLHandshakeException("Could not generate secret", gse);
        }
```

```java
 private static byte[] LabeledExpand(KDF hkdf, byte[] suite_id,
            SecretKey prk, byte[] label, byte[] info, int L)
            throws InvalidKeyException {
        byte[] labeled_info = concat(I2OSP(L, 2), HPKE_V1, suite_id, label,
                info);
        try {
            return hkdf.deriveData(HKDFParameterSpec.expandOnly(
                    prk, labeled_info, L));
        } catch (InvalidAlgorithmParameterException iape) {
            throw new InvalidKeyException(iape.getMessage(), iape);
        }
    }
```

```java
 // this usage depicts the initialization of an HKDF-Expand AlgorithmParameterSpec
 AlgorithmParameterSpec derivationSpec =             HKDFParameterSpec.expandOnly(prk, info, 32);

 // this usage depicts the initialization of an HKDF-ExtractExpand AlgorithmParameterSpec
AlgorithmParameterSpec derivationSpec =
HKDFParameterSpec.ofExtract()
.addIKM(ikm)
.addSalt(salt).thenExpand(info, 32);
 
 ```

 ```java
     private static SecretKey derivePreSharedKey(CipherSuite.HashAlg hashAlg,
            SecretKey resumptionMasterSecret, byte[] nonce) throws IOException {
        try {
            KDF hkdf = KDF.getInstance(hashAlg.hkdfAlgorithm);

            byte[] hkdfInfo = SSLSecretDerivation.createHkdfInfo(
                    "tls13 resumption".getBytes(), nonce, hashAlg.hashLength);
            // SSLSessionImpl.write() uses the PreSharedKey encoding for
            // the stateless session ticket; use SecretKeySpec instead of opaque
            // Key objects
            return new SecretKeySpec(hkdf.deriveData(
                    HKDFParameterSpec.expandOnly(resumptionMasterSecret,
                    hkdfInfo, hashAlg.hashLength)), "TlsPreSharedKey");
        } catch (GeneralSecurityException gse) {
            throw new SSLHandshakeException("Could not derive PSK", gse);
        }
    }
```

```java
     KDF hkdf = KDF.getInstance(hashAlg.hkdfAlgorithm);
     byte[] label = ("tls13 finished").getBytes();
     byte[] hkdfInfo = SSLSecretDerivation.createHkdfInfo(
             label, new byte[0], hashAlg.hashLength);
     SecretKey finishedKey = hkdf.deriveKey("TlsBinderKey",
             HKDFParameterSpec.expandOnly(binderKey, hkdfInfo,
             hashAlg.hashLength));
```                 

The test is whether the input is already uniformly random:
- `Uniform random bytes (a PRK)`, such as the output of an earlier `Extract` or of `Expand` → go straight to `Expand`.
- Secret, but with structure or bias: an ECDHE output, raw random-number-generator samples, a key from somewhere you don't control → `Extract` first.

### TLS 1.3: one Expand call per key, each with its own label
Every secret, key and IV comes from its own Expand call with a different label:
```sh
c hs traffic = Expand(HS, "tls13 c hs traffic", transcript)
s hs traffic = Expand(HS, "tls13 s hs traffic", transcript)
key          = Expand(s hs traffic, "tls13 key", "")   → 16 or 32 bytes
iv           = Expand(s hs traffic, "tls13 iv",  "")   → 12 bytes
```
In the code, `deriveKey("TlsKey")` and `deriveData("TlsIv")` are separate calls. Each builds its own `hkdfInfo` from its `label` and calls expandOnly (SSLTrafficKeyDerivation.java:150-170). Getting a `server write key `and `IV` takes two Expand calls, each a single HMAC.


### TLS 1.2: one long output, sliced into pieces
TLS 1.2 ran its PRF once to produce a long key_block, then cut it up:

```sh
key_block = PRF(master_secret, "key expansion", randoms)  → e.g. 104 bytes
          = [client MAC key | server MAC key | client key | server key | client IV | server IV]
```          
```java

        @Override
        public SecretKey deriveKey(String type) throws IOException {
            switch (type) {
                case "clientMacKey":
                    return keyMaterialSpec.getClientMacKey();
                case "serverMacKey":
                    return keyMaterialSpec.getServerMacKey();
                case "clientWriteKey":
                    return keyMaterialSpec.getClientCipherKey();
                case "serverWriteKey":
                    return keyMaterialSpec.getServerCipherKey();
                default:
                    throw new SSLHandshakeException(
                            "Cannot deriveKey for " + type);
            }
        }
```        

you can Expand once and slice the output, which is what TLS 1.2 effectively did. TLS 1.3 Expands once per key, with a distinct label for each
```sh
keyBlockLen <<= 1; is the same as keyBlockLen = keyBlockLen * 2;
```
*The syntax*
- `<<` is shift left: it moves every bit one place to the left and fills in a 0 on the right. In binary, shifting left by 1 doubles the number, just as appending a 0 in decimal multiplies by 10.
- `<<=` is the compound form, like `+=`: shift the variable and store the result back into it.

```sh
before:  20  = 0001 0100
after:   40  = 0010 1000     (every bit moved one place left)
```

```sh
255      = 00000000 00000000 00000000 11111111
255 << 1 = 00000000 00000000 00000001 11111110  = 510
```
```sh
1111 1111  (255)
1111 1110  (254)   ← the top 1 is lost, a 0 comes in on the right
```

```sh
int  a = 255 << 1;              // 510
byte b = (byte) (255 << 1);     // cast keeps only the low 8 bits → 0xFE → -2
```

That's −2 rather than 254 because Java's byte is signed (−128..127). The bit pattern `1111 1110` means −2.

TLS uses separate keys in each direction: the client encrypts with one set and the server with another. So the block has to hold two sets, one for the client and one for the server.


```sh
keyBlock = [ client MAC | server MAC | client key | server key | client IV | server IV ]
```

```sh
if (salt.length == 0) {
    salt = new byte[hmacLen];      // no salt supplied → hashLength zero bytes
}
```

In TLS 1.3, only the first of the three Extracts uses a zero salt

For the Early Stage without a PSK, both inputs are zero, so the Early Secret is a public constant. Real secrecy begins at the Handshake stage, when the ECDHE shared secret enters.

he RFC makes it optional and the JDK fills in zeros. But HMAC always needs something in its key slot, so "no salt" really means "a fixed, known key of zeros". Extract still works that way.

A salt is recommended because it adds four things.
- `A stronger security guarantee`. With a fixed key (zeros), the claim that "Extract output looks random" relies on assuming SHA-256's internals behave well on your particular input. With a random salt, HKDF's security proof needs much weaker assumptions. It's closer to a mathematical guarantee than a hope about SHA-256. The RFC puts it as: a salt "adds significantly to the strength of HKDF".
- An attacker can't prepare an input against a known function. With a zero salt, everyone uses the same extraction function, known in advance. An attacker who can influence the input has unlimited time to search for inputs that come out badly under that one function. A random salt that's chosen after the attacker's input is fixed takes that away: they don't know which function they're up against.
- Separate outputs for separate uses. If two systems, or two users, could end up with the same input key material, different salts guarantee different keys:

```sh
Extract(salt = "app-A", IKM) ≠ Extract(salt = "app-B", IKM)
```

Without a salt, the same IKM always gives the same PRK wherever it's used.


Chaining makes the final keys depend on every secret that entered the handshake, not just the latest one. Then an attacker has to break all of them, not just one

```sh
In a resumed connection (PSK + ECDHE, the psk_dhe_ke mode), two independent secrets go in:


Early     = Extract(0,                 PSK)
Handshake = Extract(salt ← Early,      ECDHE)     ← depends on PSK and ECDHE
Master    = Extract(salt ← Handshake,  0)         ← depends on both
```
Chaining means the keys are at least as strong as the stronger of the two inputs.

- The PSK binder has to go inside the ClientHello, before the client knows the server's ECDHE share. It's derived from the Early Secret.
- Handshake keys are needed right after ServerHello, before the handshake is authenticated.
- Application keys should only exist after both Finished messages.

The Master Secret is the parent of the application secrets. It never encrypts anything itself. The application traffic secrets are derived from it by Expand, and the actual encryption keys are one level further down:

```sh
Master Secret = Extract(salt = Derive(Handshake, "derived"), IKM = 0)     Finished.java:816
   │
   ├─ Expand "c ap traffic" → client application traffic secret
   │                              ├─ Expand "key" → client write key   (AES / ChaCha20)
   │                              └─ Expand "iv"  → client write IV
   │
   ├─ Expand "s ap traffic" → server application traffic secret          Finished.java:824
   │                              ├─ Expand "key" → server write key
   │                              └─ Expand "iv"  → server write IV
   │
   ├─ Expand "exp master"   → exporter secret   (for exportKeyingMaterial)
   └─ Expand "res master"   → resumption secret (→ PSK for session tickets)
```

The application traffic secret is already a uniform pseudorandom key (it came out of Expand from the Master Secret),It only needs Expand to derive children:
```sh
client write key = Expand(c ap traffic, HkdfLabel(keyLen, "tls13 key", ""))   → 16 or 32 bytes
client write iv  = Expand(c ap traffic, HkdfLabel(12,     "tls13 iv",  ""))   → 12 bytes
```

Extract only at the three stages, where raw material comes in. Everything below them is Expand.

```java
        private static byte[] createHkdfInfo(
                byte[] label, int length) {
            byte[] info = new byte[4 + label.length];
            ByteBuffer m = ByteBuffer.wrap(info);
            try {
                Record.putInt16(m, length);
                Record.putBytes8(m, label);
                Record.putInt8(m, 0x00);    // zero-length context
            } catch (IOException ioe) {
                // unlikely
                throw new RuntimeException("Unexpected exception", ioe);
            }
            return info;
        }
```

The RFC defines:

```sh
struct {
    uint16 length;              // how many bytes Expand should output
    opaque label<7..255>;       // 1-byte length prefix + "tls13 " + label
    opaque context<0..255>;     // 1-byte length prefix + context bytes
} HkdfLabel;
```

```java
            // derive salt secret
                saltSecret = kd.deriveKey("TlsSaltSecret");

                // derive application secrets
                HashAlg hashAlg = chc.negotiatedCipherSuite.hashAlg;
                KDF hkdf = KDF.getInstance(hashAlg.hkdfAlgorithm);
                byte[] zeros = new byte[hashAlg.hashLength];
                SecretKey masterSecret = hkdf.deriveKey("TlsMasterSecret",
                        HKDFParameterSpec.ofExtract()
                                         .addSalt(saltSecret)
                                         .addIKM(zeros).extractOnly());

                SSLKeyDerivation secretKD =
                        new SSLSecretDerivation(chc, masterSecret);

                // update the handshake traffic read keys.
                SecretKey readSecret = secretKD.deriveKey(
                        "TlsServerAppTrafficSecret");
                SSLKeyDerivation writeKD =
                        kdg.createKeyDerivation(chc, readSecret);
                SecretKey readKey = writeKD.deriveKey("TlsKey");
                IvParameterSpec readIv =
                        new IvParameterSpec(writeKD.deriveData("TlsIv"));
                SSLReadCipher readCipher =
                        chc.negotiatedCipherSuite.bulkCipher.createReadCipher(
                                Authenticator.valueOf(chc.negotiatedProtocol),
                                chc.negotiatedProtocol, readKey, readIv,
                                chc.sslContext.getSecureRandom());
                            ```    

```java
/**
 * A common class for creating various KeyDerivation types.
 */
public class KAKeyDerivation implements SSLKeyDerivation {


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
}                           ```


```java
     // derive salt secret
            saltSecret = kd.deriveKe("TlsSaltSecret");
            // derive application secrets
            HashAlg hashAlg = shcnegotiatedCipherSuite.hashAlg;
            KDF hkdf = KDF.getInstanc(hashAlg.hkdfAlgorithm);
            byte[] zeros = new byte[hashAlghashLength];
            SecretKey masterSecret = hkdfderiveKey("TlsMasterSecret",
                    HKDFParameterSpecofExtract().addSal(saltSecret)
                    .addIKM(zeros).extractOnl());
            SSLKeyDerivation secretKD =
                    new SSLSecretDerivatio(shc, masterSecret);
            // update the handshake trafficwrite keys.
            SecretKey writeSecret = secretKDderiveKey(
                    "TlsServerAppTrafficSecre");
            SSLKeyDerivation writeKD =
                    kdg.createKeyDerivatio(shc, writeSecret);
            SecretKey writeKey = writeKD.deriveKey("TlsKey");
                IvParameterSpec writeIv =
                        new IvParameterSpec(writeKD.deriveData("TlsIv"));
```                        

```java
    
        // derive salt secret
        saltSecret = kd.deriveKey("TlsSaltSecret");

        // derive application secrets
        HashAlg hashAlg = chc.negotiatedCipherSuite.hashAlg;
        KDF hkdf = KDF.getInstance(hashAlg.hkdfAlgorithm);
        byte[] zeros = new byte[hashAlg.hashLength];
        SecretKey masterSecret = hkdf.deriveKey("TlsMasterSecret",
                HKDFParameterSpec.ofExtract()
                                 .addSalt(saltSecret)
                                 .addIKM(zeros).extractOnly());

        SSLKeyDerivation secretKD =
                new SSLSecretDerivation(chc, masterSecret);

        // update the handshake traffic read keys.
        SecretKey readSecret = secretKD.deriveKey(
                "TlsServerAppTrafficSecret");
                 // should be readKD
        SSLKeyDerivation writeKD =
                kdg.createKeyDerivation(chc, readSecret);
        SecretKey readKey = writeKD.deriveKey("TlsKey");
        IvParameterSpec readIv =
                new IvParameterSpec(writeKD.deriveData("TlsIv"));
```     

Every secret appears twice, once on each side. Both peers derive the same value independently, and one side's write key is the other side's read key.

*`s hs traffic`, server → client during the handshake*
Server, in `T13ServerHelloProducer` (ServerHello.java:639-667):
```java
SecretKey writeSecret = kd.deriveKey("TlsServerHandshakeTrafficSecret");   // 639
SecretKey writeKey    = writeKD.deriveKey("TlsKey");                         // 643
IvParameterSpec ...   = writeKD.deriveData("TlsIv");                         // 645
...createWriteCipher(...)                                                    // 649
shc.conContext.outputRecord.changeWriteCiphers(...)                          // 667  ← OUTPUT
Client, in T13ServerHelloConsumer (ServerHello.java:1314-1343):
```
```java
SecretKey readSecret = secretKD.deriveKey("TlsServerHandshakeTrafficSecret"); // 1314
SecretKey readKey    = readKD.deriveKey("TlsKey");                            // 1319
IvParameterSpec ...  = readKD.deriveData("TlsIv");                            // 1321
...createReadCipher(...)                                                      // 1325
chc.conContext.inputRecord.changeReadCiphers(readCipher);                     // 1343  ← INPUT
```

*`c ap traffic`, client → server application data*
Client, in `T13FinishedProducer` (Finished.java:719-740):

```java
kd.deriveKey("TlsClientAppTrafficSecret");                                   // 719
SecretKey writeKey = writeKD.deriveKey("TlsKey");                             // 723
...createWriteCipher(...)                                                     // 727
chc.conContext.outputRecord.changeWriteCiphers(...)                           // 740  ← OUTPUT
Server, in T13FinishedConsumer (Finished.java:1092-1114):
```
```java
SecretKey readSecret = kd.deriveKey("TlsClientAppTrafficSecret");             // 1092
SecretKey readKey    = readKD.deriveKey("TlsKey");                            // 1097
...createReadCipher(...)                                                      // 1101
shc.conContext.inputRecord.changeReadCiphers(readCipher);                     // 1114  ← INPUT
```

- Same string, same inputs. Both sides call `deriveKey` with the same name. That means the same label, the same parent secret (both computed it from the same ECDHE exchange), and the same transcript hash (both hashed the same messages). HKDF is deterministic, so both get identical bytes, and no key is ever sent over the network.
- Opposite destinations. The sender's result goes to `createWriteCipher` / `outputRecord.changeWriteCiphers`, and the receiver's goes to `createReadCipher` / `inputRecord.changeReadCiphers`.
- The names in each secret tell you the direction. "Client" or "Server" in the secret's name says who writes with it. The writer puts it in its output; the other side puts it in its input.

```sh
              client                               server
send:   client write key  ───────────────►  client write key   :receive
receive:   server write key  ◄───────────────  server write key   :send
```
The client's write key (from c ap traffic) is the server's read key.
The server's write key (from s ap traffic) is the client's read key.

each connection holds them in two separate places: `conContext.outputRecord` gets the write cipher (via `changeWriteCiphers`) and `conContext.inputRecord` gets the read cipher (via `changeReadCiphers`).


TLS 1.2 names its keys by who writes with them, not by read or write:
```sh
key_block = client_write_MAC | server_write_MAC | client_write_key | server_write_key | client_write_IV | server_write_IV
```

```java
SecretKey writeKey = tkd.deriveKey(hc.sslConfig.isClientMode ? "clientWriteKey" : "serverWriteKey");
byte[]    writeIv  = tkd.deriveData(hc.sslConfig.isClientMode ? "clientWriteIv"  : "serverWriteIv");
```

```java
SecretKey readKey = tkd.deriveKey(hc.sslConfig.isClientMode ? "serverWriteKey" : "clientWriteKey");
byte[]    readIv  = tkd.deriveData(hc.sslConfig.isClientMode ? "serverWriteIv"  : "clientWriteIv");
```

The idea is the same in TLS 1.3: `c … traffic` and `s … traffic` are named by who writes, and each side uses its own for writing and the peer's for reading.

The client's write cipher uses `c … traffic`. `s … traffic` goes into the client's read cipher.

The letter says who writes with it: `c` means the client writes (sends) with it, and `s` means the server writes with it.

| Client call | Secret used |
|---|---|
| `changeWriteCiphers` (sending, handshake) | `c hs traffic` |
| `changeWriteCiphers` (sending, application) | `c ap traffic` |
| `changeReadCiphers` (receiving, handshake) | `s hs traffic` |
| `changeReadCiphers` (receiving, application) | `s ap traffic` |

The server is the mirror image: it writes with `s … traffic` and reads with `c … traffic`.
```sh
Handshake Secret
   │  ① kd.deriveKey("TlsSaltSecret")                     Expand, label "derived", context Hash("")
   ▼
saltSecret
   │  ② hkdf.deriveKey("TlsMasterSecret", Extract(salt, zeros))
   ▼
Master Secret
   │  ③ new SSLSecretDerivation(shc, masterSecret)        takes a transcript snapshot: ClientHello … server Finished
   │  ④ secretKD.deriveKey("TlsServerAppTrafficSecret")  Expand, "s ap traffic"
   ▼
s ap traffic
   │  ⑤ kdg.createKeyDerivation(shc, writeSecret)         T13TrafficKeyDerivation
   │  ⑥ writeKD.deriveKey("TlsKey")                      Expand, "key" → 16/32 bytes
   │     writeKD.deriveData("TlsIv")                     Expand, "iv"  → 12 bytes
   ▼
writeKey + writeIv
```

Every javax.crypto.SecretKey has getAlgorithm(), which says what the key is meant to be used with:

```java
new SecretKeySpec(bytes, "AES").getAlgorithm()          // "AES": for an AES cipher
new SecretKeySpec(bytes, "HmacSHA256").getAlgorithm()   // "HmacSHA256": for an HMAC
```
For keys like these, the label happens to name a real algorithm, which is where the API name comes from. But a SecretKeySpec is really just bytes plus a label, and it accepts any non-empty string.

*The JDK uses it as a tag for TLS secrets*

The TLS code reuses that label slot to record what kind of secret the bytes are:

```sh
hkdf.deriveKey("TlsEarlySecret", ...)   // → SecretKeySpec(bytes, "TlsEarlySecret")
```
"TlsEarlySecret", "TlsHandshakeSecret", "TlsMasterSecret" and "TlsSaltSecret" aren't registered algorithms anywhere.

```java
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
```

The Early Secret has a short life. In the JDK it's used for only two things: the PSK binder and the "derived" salt for the Handshake Secret. Where it's created depends on whether the connection resumes a previous session.

- *fresh connection, no PSK*
```sh
ServerHello.java:592 (server) / :1300 (client)
  handshakeKD.deriveKey("TlsHandshakeSecret")
      │
      ▼
KAKeyDerivation.t13DeriveKey
  kd = context.handshakeKeyDerivation   → null (no PSK)
  earlySecret = Extract(salt = 0, IKM = 0)             line 118   "TlsEarlySecret"
  kd = new SSLSecretDerivation(context, earlySecret)   line 121
  saltSecret = kd.deriveKey("TlsSaltSecret")           line 125   Expand "derived"
  return Extract(saltSecret, ECDHE)                    line 132   → Handshake Secret
  finally: destroySecretKeys(sharedSecret, earlySecret, saltSecret)
```
Here the Early Secret is a public constant, `HKDF-Extract(0, 0)`, identical for every connection. It exists only so the key schedule has the same shape as the PSK case. Its only use is producing the salt.

- *resumption with a PSK*
The PSK comes from a session ticket issued in an earlier connection (the r`es master → NewSessionTicket` path). There are three steps.

① The client sends a binder in its ClientHello 

```sh
binder key = Expand(Extract(0, PSK), "tls13 res binder", Hash(""))   ← Early Secret computed inside, not named
binder     = HMAC(finished key from binder key, hash of partial ClientHello)
```

This proves the client actually holds the PSK, not just a copied ticket. The code computes the Early Secret inline here with a combined Extract-then-Expand call, because it's needed before ServerHello exists.

② The server checks the binder and accepts the PSK.

```sh
setUpPskKD(shc, shc.resumingSession.consumePreSharedKey());
```
The client does the same when it reads ServerHello and sees the PSK was accepted 

```java
            KDF hkdf = KDF.getInstance(hashAlg.hkdfAlgorithm);
            SecretKey earlySecret = hkdf.deriveKey("TlsEarlySecret",
                    HKDFParameterSpec.ofExtract().addIKM(psk)
                    .addSalt(new byte[hashAlg.hashLength]).extractOnly());
            hc.handshakeKeyDerivation =
                    new SSLSecretDerivation(hc, earlySecret);
```                    

`consumePreSharedKey() `removes the PSK from the session, so each ticket's PSK can only be used once.

③ The Handshake Secret is derived the same way as in Case 1, except that in `t13DeriveKey`, `kd` is now not null. The if (`kd == null`) block is skipped, and the salt comes from the PSK-based Early Secret:
```sh
Early Secret (from PSK) ──"derived"──► salt ──Extract(salt, ECDHE)──► Handshake Secret
```

RFC 8446 also derives `c e traffic` and `e exp master` from it, for 0-RTT early data: sending application data inside the first flight, encrypted with keys based on the PSK. JSSE doesn't implement 0-RTT, which is why those `SecretSchedule` constants are never used.

```sh
Handshake Secret ─┬─ c hs traffic ─┬─ key, iv   ← client → server, during handshake
                  │                 
                  └─ s hs traffic ─┬─ key, iv   ← server → client, during handshake

Master Secret ────┬─ c ap traffic ─┬─ key, iv   ← client → server, application data
                  │                 
                  └─ s ap traffic ─┬─ key, iv   ← server → client, application data
```

A traffic secret is never used to encrypt anything directly. It's the root for one direction of one phase. To actually encrypt records in that direction, you need an AEAD key and an IV, and those are Expanded from the traffic secret. So wherever a traffic secret is created, `TlsKey` and `TlsIv` follow straight away, to build the cipher that gets swapped in.

A normal handshake creates four traffic secrets, so there are four key and IV pairs:

| Traffic secret | Encrypts |
|---|---|
| `s hs traffic` | EncryptedExtensions, Certificate, CertificateVerify, server Finished |
| `c hs traffic` | client Finished (plus client Certificate for mTLS) |
| `s ap traffic` | server's application data |
| `c ap traffic` | client's application data |


In TLS 1.3 the handshake messages after `ServerHello` are encrypted too, so the handshake phase needs its own keys, before the Master Secret even exists. That's why `TlsKey`/`TlsIv` show up in `ServerHello.java` as well as `Finished.java`


```java
   SSLHandshake[] probableHandshakeMessages = new SSLHandshake[] {
                SSLHandshake.SERVER_HELLO,

                // full handshake messages
                SSLHandshake.ENCRYPTED_EXTENSIONS,
                SSLHandshake.CERTIFICATE_REQUEST,
                SSLHandshake.CERTIFICATE,
                SSLHandshake.CERTIFICATE_VERIFY,
                SSLHandshake.FINISHED
            };
```

`pre_shared_key` is the name of the `ClientHello` extension that says which `PSK` the client wants to use. The `PSK` itself is never sent.

Every TLS 1.3 client makes a fresh ephemeral key pair for every connection: browsers, curl, mobile apps, the JDK. The protocol depends on it, and it's the source of forward secrecy. The private key exists only in memory for the handshake and is thrown away afterwards, so recording the traffic and stealing the server's certificate key later doesn't let anyone decrypt it

A client can send key shares for several groups in one `ClientHello`, guessing which one the server will pick:

- The JDK sends up to two: its most-preferred group of the `X25519/X448` kind and its most-preferred NIST curve (P-256 etc.). The comment at `KeyShareExtension.java:248-262` says: "take the most-preferred group from two categories (i.e. XDH and ECDHE)". In practice that's usually an X25519 key and a P-256 key.
- Browsers (Chrome, Firefox, Safari, Edge) currently send a `post-quantum` hybrid share, `X25519MLKEM768`, plus a plain `X25519` share as a fallback. The hybrid share adds about 1.1 KB to the `ClientHello`, which is why browsers send so few shares.
- If none of the client's guesses suit the server, the server replies with a `HelloRetryRequest` naming a group, and the client generates a key for that group and tries again

When browsers resume, they use `psk_dhe_ke` mode, which still sends a fresh key share, so a resumed session gets new forward secrecy as well. 

The `pre_shared_key` extension contains 

```sh
ClientHello pre_shared_key:
    identities: [ { identity = <session ticket bytes>, obfuscated_ticket_age }, ... ]   ← PskIdentity
    binders:    [ HMAC proving "I know the PSK for this ticket", ... ]
```    

The server replies with its own `pre_shared_key` in `ServerHello` containing only `selected_identity`: the index of the ticket it accepted 

### How the server gets the PSK back from a ticket
Two options:

- `Stateful`: the ticket is just an ID, and the server looks up the PSK in its session cache.
- `Stateless`: the ticket is the session state, including the PSK, encrypted with a key only the server knows. The JDK supports this (`SessionTicketExtension.java`, StatelessKey, which rotates periodically). The server decrypts the ticket and recovers the PSK, with no cache needed.

### Why a key share is needed
To agree on a secret with ECDHE, each side needs the other's public key:
```sh
client:  shared = ECDH(client private key, server public key)
server:  shared = ECDH(server private key, client public key)
         → the same value on both sides; everything else is derived from it
```         
The public keys have to travel across the network somehow, and `key_share` is the extension that carries them. The client's goes in the ClientHello, the server's in the ServerHello. Without it there's no shared secret, so no Handshake Secret and no traffic keys.

*Why it's in the very first message*: in TLS 1.2 the public keys were sent in separate later messages (`ServerKeyExchange`, then `ClientKeyExchange`). That meant an extra round trip before any encryption could start. TLS 1.3 has the client guess the group and send its public key immediately. So after one round trip (`ClientHello → ServerHello`), both sides already have the shared secret, and everything after ServerHello can be encrypted. If the guess is wrong, a `HelloRetryRequest` costs one extra round trip

The client generates the key pair first, then puts its public half into `key_share`

```java
SSLPossession[] poses = ke.createPossessions(chc);   // ① generate the key pair
for (SSLPossession pos : poses) {
    chc.handshakePossessions.add(pos);               // ② keep it, private key included, for later
    if (pos instanceof NamedGroupPossession) {
        return pos.encode();                         // ③ return only the PUBLIC key bytes → key_share
    }
}
```
`createPossessions` creates an `XDHEPossession` or `ECDHEPossession`, whose constructor does the actual generation (XDHKeyExchange.java:102-105):

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance(namedGroup.algorithm);   // "X25519"
kpg.initialize(namedGroup.keAlgParamSpec, random);
KeyPair kp = kpg.generateKeyPair();
```
For `P-256`, it's the same code with "EC" (`ECDHKeyExchange.java`:116-118).
```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(namedGroup.keAlgParamSpec, random);
                KeyPair kp = kpg.generateKeyPair();
                privateKey = kp.getPrivate();
                publicKey = (ECPublicKey)kp.getPublic();
```                

When `ServerHello` arrives with the server's public key, `KAKeyDerivation` combines the stored private key with the server's public key. That's the `ka.init(localPrivateKey); ka.doPhase(peerPublicKey, true)` in `t13DeriveKey`.

The server does the same thing in reverse. It reads the client's `key_share`, generates its own key pair (`SHKeyShareProducer`, `KeyShareExtension.java:507`), sends its public key in `ServerHello`, and computes the same shared secret.

The `-Djdk.tls.namedGroups`=... system property, read once at startup

```java
  // default groups
 NamedGroup[] groups = new NamedGroup[] {

         // Primary XDH (RFC 7748) curves
         X25519,

         // Primary NIST Suite B curves
         SECP256_R1,
         SECP384_R1,
         SECP521_R1,

         // Secondary XDH curves
         X448,

         // FFDHE (RFC 7919)
         FFDHE_2048,
         FFDHE_3072,
         FFDHE_4096,
         FFDHE_6144,
         FFDHE_8192,
     };
```        

`CHKeyShareProducer` (the lines you selected earlier, `KeyShareExtension.java:248-262`) walks `clientRequestedNamedGroups` and generates a key pair for the first group of each family (XDH, NIST ECDHE, FFDHE), stopping after two.

With the defaults, that means:
```sh
X25519      ← first XDH group     → key pair generated, public key in key_share
secp256r1   ← first ECDHE group   → key pair generated, public key in key_share
(stop: two families covered)
```
So a Java client normally sends `supported_groups` = the full filtered list, plus `key_share` = `X25519` and `P-256` public keys

The server looks at the client's key shares (`KeyShareExtension.java:345`, in the client's order) and uses one it supports. If it supports none of them, but does support something else in `supported_groups`, it sends a `HelloRetryRequest` naming that group. The client then generates a key for just that group
```sh
CH_SUPPORTED_VERSIONS   (0x002B, "supported_versions", ...)   // ClientHello
SH_SUPPORTED_VERSIONS   (0x002B, "supported_versions", ...)   // ServerHello
HRR_SUPPORTED_VERSIONS  (0x002B, "supported_versions", ...)   // HelloRetryRequest
MH_SUPPORTED_VERSIONS   (0x002B, "supported_versions", ...)   // message_hash
```
The class names follow the same scheme: `CHKeyShareProducer`, `SHKeyShareConsumer`, `HRRKeyShareProducer`, `CHPreSharedKeySpec`, `SHPreSharedKeySpec`, and so on

ECDHE gives you a secret shared with whoever is on the other end, but it doesn't tell you who that is. An attacker in the middle could do one ECDHE exchange with you and another with the real server, then relay and read everything in between. Both exchanges would work fine.

The server has to sign the handshake with a private key that matches a certificate your `TrustManager` trusts for that hostname. An attacker doesn't have that private key, so it can't produce a valid signature

Private key: the server signs (CertificateVerify.java:899-939, T13CertificateVerifyMessage producer):

```java
SignatureScheme.getSignerOfPreferableAlgorithm(..., x509Possession, ...)  // x509Possession.popPrivateKey
signer.update(contentCovered);   // 64 spaces + "TLS 1.3, server CertificateVerify" + 0x00 + transcript hash
temporary = signer.sign();       // ← the only thing the certificate's private key does in the handshake
```
Public key: the client verifies (same class, lines 987-1013):

```java
signatureScheme.getVerifier(x509Credentials.popPublicKey);   // public key from the server's certificate
if (!signer.verify(signature)) { ... fatal alert ... }
```

The public key reaches the client inside the Certificate message. The client first checks that certificate with `checkServerCerts → TrustManager` (trusted chain, correct hostname, not expired), then uses its public key to check the signature above

## TLS 1.2
TLS 1.2 had an RSA key exchange mode, where the client encrypted the premaster secret with the server's certificate public key and the server decrypted it with its private key. The certificate key then protected the secret directly. If that private key leaked later, every recorded session could be decrypted: there was no forward secrecy.

TLS 1.3 removed that mode. The certificate key now only signs and never protects a secret, so a leaked certificate key lets an attacker impersonate the server from then on, but it can't decrypt past traffic.

```java
   private static X509Certificate[] checkClientCerts(
                ServerHandshakeContext shc,
                List<CertificateEntry> certEntries) throws IOException {
            X509Certificate[] certs =
                    new X509Certificate[certEntries.size()];
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                int i = 0;
                for (CertificateEntry entry : certEntries) {
                    certs[i++] = (X509Certificate)cf.generateCertificate(
                                    new ByteArrayInputStream(entry.encoded));
                }
            } catch (CertificateException ce) {
                throw shc.conContext.fatal(Alert.BAD_CERTIFICATE,
                    "Failed to parse client certificates", ce);
            }

            // find out the types of client authentication used
            String keyAlgorithm = certs[0].getPublicKey().getAlgorithm();
            String authType;
            switch (keyAlgorithm) {
                case "RSA":
                case "DSA":
                case "EC":
                case "RSASSA-PSS":
                    authType = keyAlgorithm;
                    break;
                default:
                    // unknown public key type
                    authType = "UNKNOWN";
            }

            try {
                X509TrustManager tm = shc.sslContext.getX509TrustManager();
                if (tm instanceof X509ExtendedTrustManager) {
                    if (shc.conContext.transport instanceof SSLEngine engine) {
                        ((X509ExtendedTrustManager)tm).checkClientTrusted(
                            certs.clone(),
                            authType,
                            engine);
                    } else {
                        SSLSocket socket = (SSLSocket)shc.conContext.transport;
                        ((X509ExtendedTrustManager)tm).checkClientTrusted(
                            certs.clone(),
                            authType,
                            socket);
                    }
                } else {
                    // Unlikely to happen, because we have wrapped the old
                    // X509TrustManager with the new X509ExtendedTrustManager.
                    throw new CertificateException(
                            "Improper X509TrustManager implementation");
                }

                // Once the client certificate chain has been validated, set
                // the certificate chain in the TLS session.
                shc.handshakeSession.setPeerCertificates(certs);
            } catch (CertificateException ce) {
                throw shc.conContext.fatal(Alert.CERTIFICATE_UNKNOWN, ce);
            }

            return certs;
        }

        private static X509Certificate[] checkServerCerts(
                ClientHandshakeContext chc,
                List<CertificateEntry> certEntries) throws IOException {
            X509Certificate[] certs =
                    new X509Certificate[certEntries.size()];
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                int i = 0;
                for (CertificateEntry entry : certEntries) {
                    certs[i++] = (X509Certificate)cf.generateCertificate(
                                    new ByteArrayInputStream(entry.encoded));
                }
            } catch (CertificateException ce) {
                throw chc.conContext.fatal(Alert.BAD_CERTIFICATE,
                    "Failed to parse server certificates", ce);
            }

            // find out the types of server authentication used
            //
            // Note that the "UNKNOWN" authentication type is sufficient to
            // check the required digitalSignature KeyUsage for TLS 1.3.
            String authType = "UNKNOWN";

            try {
                X509TrustManager tm = chc.sslContext.getX509TrustManager();
                if (tm instanceof X509ExtendedTrustManager) {
                    if (chc.conContext.transport instanceof SSLEngine engine) {
                        ((X509ExtendedTrustManager)tm).checkServerTrusted(
                            certs.clone(),
                            authType,
                            engine);
                    } else {
                        SSLSocket socket = (SSLSocket)chc.conContext.transport;
                        ((X509ExtendedTrustManager)tm).checkServerTrusted(
                            certs.clone(),
                            authType,
                            socket);
                    }
                } else {
                    // Unlikely to happen, because we have wrapped the old
                    // X509TrustManager with the new X509ExtendedTrustManager.
                    throw new CertificateException(
                            "Improper X509TrustManager implementation");
                }

                // Once the server certificate chain has been validated, set
                // the certificate chain in the TLS session.
                chc.handshakeSession.setPeerCertificates(certs);
            } catch (CertificateException ce) {
                throw chc.conContext.fatal(getCertificateAlert(chc, ce), ce);
            }

            return certs;
        }
```        

A client is allowed to send an empty `Certificate` message, meaning "I have no certificate". Whether that's acceptable depends on server configuratio

```java
Validator v = checkTrustedInit(chain, authType, checkClientTrusted);   // PKIX validator over your truststore
...
trustedChain = v.validate(chain, null, responseList,                   // ① chain validation
        constraints, checkClientTrusted ? null : authType);

String identityAlg = sslSocket.getSSLParameters().getEndpointIdentificationAlgorithm();
if (identityAlg != null && !identityAlg.isEmpty()) {
    checkIdentity(session, trustedChain, identityAlg, checkClientTrusted);   // ② hostname check
}
```
In JVM process `-Djdk.tls.namedGroups="secp256r1,secp384r1,ffdhe2048,ffdhe3072"` is set (fips)

```sh
$ openssl list -tls-groups -tls1_3
secp256r1:secp384r1:secp521r1:x25519:x448:brainpoolP256r1tls13:brainpoolP384r1tls13:
brainpoolP512r1tls13:curveSM2:ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192:
MLKEM512:MLKEM768:MLKEM1024:SecP256r1MLKEM768:X25519MLKEM768:SecP384r1MLKEM1024:curveSM2MLKEM768
```

`openssl s_client -connect www.cloudflare.com:443 -tls1_3 -trace </dev/null`

```sh
extension_type=supported_groups(10)
    X25519MLKEM768 (4588)          ← post-quantum hybrid first
    SecP256r1MLKEM768 (4587)
    curveSM2MLKEM768 (4590)
    ecdh_x25519 (29)
    secp256r1 (P-256) (23)
    ecdh_x448, secp384r1, secp521r1, curveSM2, ffdhe2048, ffdhe3072
extension_type=key_share(51), length=1258
    NamedGroup: X25519MLKEM768     key_exchange (len=1216)   ← the hybrid key is 1216 bytes
    NamedGroup: ecdh_x25519        key_exchange (len=32)     ← plain X25519 is 32 bytes
...
ServerHello … key_share: NamedGroup: X25519MLKEM768
Negotiated TLS1.3 group: X25519MLKEM768
```

```sh
openssl s_client -connect www.cloudflare.com:443 -tls1_3 -trace </dev/null 

Connecting to 104.16.123.96
CONNECTED(00000006)
Sent TLS Record
Header:
  Version = TLS 1.0 (0x301)
  Content Type = Handshake (22)
  Length = 1473
    ClientHello, Length=1469
      client_version=0x303 (TLS 1.2)
      Random:
        gmt_unix_time=0x6ADD4337
        random_bytes (len=28): B9129FCD2FC96C4D7CE62FE42DF6F2FD03C8A23314B8275449DDDC98
      session_id (len=32): 63969AD493E88C59CE077BA98E1472B89492B6E1F23ACD98DE14635C0CAF25BC
      cipher_suites (len=6)
        {0x13, 0x02} TLS_AES_256_GCM_SHA384
        {0x13, 0x03} TLS_CHACHA20_POLY1305_SHA256
        {0x13, 0x01} TLS_AES_128_GCM_SHA256
      compression_methods (len=1)
        No Compression (0x00)
      extensions, length = 1390
        extension_type=supported_groups(10), length=24
          X25519MLKEM768 (4588)
          SecP256r1MLKEM768 (4587)
          curveSM2MLKEM768 (4590)
          ecdh_x25519 (29)
          secp256r1 (P-256) (23)
          ecdh_x448 (30)
          secp384r1 (P-384) (24)
          secp521r1 (P-521) (25)
          curveSM2 (41)
          ffdhe2048 (256)
          ffdhe3072 (257)
        extension_type=session_ticket(35), length=0
        extension_type=encrypt_then_mac(22), length=0
        extension_type=extended_master_secret(23), length=0
        extension_type=signature_algorithms(13), length=44
          mldsa65 (0x0905)
          mldsa87 (0x0906)
          mldsa44 (0x0904)
          ecdsa_secp256r1_sha256 (0x0403)
          ecdsa_secp384r1_sha384 (0x0503)
          ecdsa_secp521r1_sha512 (0x0603)
          ed25519 (0x0807)
          ed448 (0x0808)
          ecdsa_brainpoolP256r1tls13_sha256 (0x081a)
          ecdsa_brainpoolP384r1tls13_sha384 (0x081b)
          ecdsa_brainpoolP512r1tls13_sha512 (0x081c)
          rsa_pss_pss_sha256 (0x0809)
          rsa_pss_pss_sha384 (0x080a)
          rsa_pss_pss_sha512 (0x080b)
          rsa_pss_rsae_sha256 (0x0804)
          rsa_pss_rsae_sha384 (0x0805)
          rsa_pss_rsae_sha512 (0x0806)
          rsa_pkcs1_sha256 (0x0401)
          rsa_pkcs1_sha384 (0x0501)
          rsa_pkcs1_sha512 (0x0601)
          sm2sig_sm3 (0x0708)
        extension_type=supported_versions(43), length=3
          TLS 1.3 (772)
        extension_type=psk_key_exchange_modes(45), length=2
          psk_dhe_ke (1)
        extension_type=key_share(51), length=1258
            NamedGroup: X25519MLKEM768 (4588)
            key_exchange:  (len=1216): 7CCACA31C99CC00701A981A6A67BA96A40219F37B00A5000A8295B9B84967BF3252796B3AD108C58476FE56451BDD37C8B496054686F5178AB3D7435B413C24A367E581950ED09C382C931C5663B32690D69C4A2B7A3CA9F960E3803B40CC5AC609C1E8A375BDCC54E162B7EC6219C0FD0244F916924F63D71D99FF5D69A6B613D72D7926A4758D5138CE0C65757C866C1EC6974F734DAB14635B7453552BDE5C72856873CFCBB16F8602284793FBD781EA2786E162BA61FE34E57858E5E36A83893181EC73504307935889B62B69294017AFD5A5B34B3B85E9431A0358703678661B3078EE0CACCDB3662A5A0F7E9B9B108074FE775CAC7BF7B6A60207961AEBACDBDDCCE2C895E3A9A9844C05EE40A573B5CB6E456788FF6C680F66E78B9A10EA339A195B40F0799D9F265FA7571AE69702CABBCBB039FAD2CB5712868AC963F1A026A90C21362BA8537CC7D9E842750F5514D4A9BBD313927E523C36B503C0761EEAA90C33405C7564797604313C63DEA1C1E7F83078C731C67B85602324825430C52F90EFD30278CE007B4460B5A3AA44B47B2625435BB807C3BDC0D97684B9B65429A681620B1B529D4C1C8A34600016BE7FC1C0B5C40470A9BA7976EDAC6AB9DE026C271B4046C67F8962D7B487192FBC0A17B9042895B96C1766FFB48767233FA21AAB7021D1827CB2DF36FBBE7186D1847C9DCC4A76696CA750C60A43EB8C9757D982E6B72C3D59BA7AEB03F6ED374CA306891968141B751D4462E96BA538BA342104B61A4C18848426500058D10E286D29522115C1A8260AC33447C7F73BE33A5A5741B2093B8899479C11AA83E9791CEB91BC23460BA57E08BE1AB0245BBC8AE9655DE71268A9C7180349BB9187DF9EABE8C2CA67271538668AECE47379146361CA311D312A31BB433DC35555363B2ADE0560C23B7A9660D5951822166272345C6A2F96E07769057E12575235219364416DBB0F8036E04FC81C45A40F78075A9FC1E339A37F374022FEC525796A24C1841CE457BD8D018FC296320E62151D608C05C1554D924AAABC2B90394DFEC6BA88B0B2167016FCA1BA3C04F60B44E0D915CB0A27870266A100293F4025794EC3099E3A6BA32A20AD7BAB1698126B6A9FEB5A8B4142AD6E5C57390117846543D5993EEEC374EAB244834C4379C75E531CE84B5003B9BA99941B265B178ABBA5E627651EAD11F9B331033625E089B80D028C026C44275AA06B9337120B7C7570680675B044C609D6931933F1B901CC3786EBC85EBA615A36300797BABD4322DA292AB82ACBD367A44DEC9100388AC16C46F18F3A1DCA05198E567EAD15ADC52B89D456247BCC089138D92F80688683E27095CB450A192FA305E43AB83612E774CCB88E88C7D661E95C995FD225E38978A4C66697A867F75768147DC0D59157AFBECBAC0CC361F389310B03955E422738314CD394B14A8B8FFDA1795AA361E541A7EF2392BC396620422E6D988BE695A1903B485154FFC8CB388491D09761E40E1B7F26A776F5228FC14AD8973C03E80901EBA168F16C1B7D8A623E1312A0CB829D6B492490C3530511DC1168944B31BC070B3476403DB1A1FB42465F1154650A0B23822259978A26A52E5F579814FBE0A34EF5625007FC6922E1993957D58FB009BE34F24D77A21966332015D1439D8DCA93D606656F14A6655C90E9D29247DC496874C5A4AB77F1C8DB85115
            NamedGroup: ecdh_x25519 (29)
            key_exchange:  (len=32): B5488A13DF9739826C551F144DED7A388CAA38E1669884D170AD96AA7F93627E
        extension_type=server_name(0), length=23
          0000 - 00 15 00 00 12 77 77 77-2e 63 6c 6f 75 64 66   .....www.cloudf
          000f - 6c 61 72 65 2e 63 6f 6d-                       lare.com

Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 1210
    ServerHello, Length=1206
      server_version=0x303 (TLS 1.2)
      Random:
        gmt_unix_time=0xFC7E55CA
        random_bytes (len=28): 61D603927F842F210CC51277FC1F521B4DE0D43CD0130D83BD525CA3
      session_id (len=32): 63969AD493E88C59CE077BA98E1472B89492B6E1F23ACD98DE14635C0CAF25BC
      cipher_suite {0x13, 0x02} TLS_AES_256_GCM_SHA384
      compression_method: No Compression (0x00)
      extensions, length = 1134
        extension_type=key_share(51), length=1124
            NamedGroup: X25519MLKEM768 (4588)
            key_exchange:  (len=1120): D338D552A6CBD7A219774C7CAAF4C679F898B055A28E277022913F0D36BB3802E63FC5FA620375F7DA9878DDAA9F69D4F78461C8B0AD0A8212055F2B1CEE2E380C0D58873F35E1EF6859579CA4E768ED1C31A6840080FBF54CD7F06967D80F8ABFE3E6F43A80354AE8E478B372E1AB4900ED4CD040EAB6D2D73504988D837613A0151C30DFD8CA23090D11666B96E1E7EB5A00FAA295B64944AE76B6B3257F1D6B01B6EF2F32E0799B6AB690693AA511F1075D41FAC37F49D346D83CF00B7AC7C0327F6E4F80A4FDDD0461F17C86A4D28AD0E94F04296462ECAC94E5E658190DCE56E3DF41377A3DFDCB2569FE0977F42AA8945B438A8F89E1840C14016A6E85CB6E82F1AB13BF7E2FAA1A95BF162F246116A49C4CBABFF6654BE848F2D523F61F212A79504A1FFCB93128E185173A71BA1DB5499AD76C4D711B9778D7FDD03DB6D2C66658BB5487DFA1C9FEDFF287DE5B1D9B51C598FEF58057F38513B164DD493A8FC8BD8D7F4732AE1FA05365AA794BB1D9AA1587D356C886714BA1DA34FC30A6A7D3C8191DD957D3A12E5DBF967A1C98380809C4DFC121EBF7DB18C9B41B888D360ED9F5AE0CD9C9580559599843264562FDADB6CD2DB0D65A783A6E042BF6880BD87CB5F2952FF314854F26BD8593F57583D36700486C5379BDD14603B368400664AF207C10CCD511C645DCE750C923CA0F79874212218CFCBDCBB2D5BEFC524EFFAEE215F2F22278F4EC966786EAC5D9135DE75229C50806BCB9E2ECD890FB709E515FFE03A65AB98D83629DBAF02C49AA0E2D8F9D81653678CD274EA257C5287B1BEBF96FEE3BB9CDB18B1C527927F4331843AEBEF0EDA00AB99ADA248BC006865819EA3FA017D58D30A114CEF49823229C1133A9210E4267E1CC9D7E60F248AA68D5082E9CC755985DB8C9BACD213E40A4A644ADBFC71B17F7BA6F4CDE8A302F0FE7E94F2EBE1120DE0D35621FB44D9887A0A0D27CC89D624EBABBFFAB10841F06B3030FD551A6C8479AAFF4A65189E32F442421D2425EB54AA5A99D42A36890824F311ECCF0EEA5712B8C2D0670ED5CEF4C2510F5ABAC3C9FD149310D9BAB430C9D5778D26A7E9AB35770DD7D03F30F30C463C8506386487385FE68B38A21975E79B6E5C953B82F0B52AC0BB012C660D6AC38CEC5741505438D41B88C8C3FB623775C353907A20417F194ADCB987FAA8B43B8EFE4600EC0518FCFC284928F4B57B499225B23CF683027B313C11A42411973703AC3D78D43A871D1C01B417ED1E1D2235D77A84528F4626D09E685A5752EC38AD3654D8A1D0D6D5A9135826C5435C02DE90709526A6D6C9C1596242097F5258541617A8DDEAB889A96B0DE3EB1FEEA90E4F50089F0A6D5A97CAD6B6A6DCED41CB948CAA2E1CA9544FBC2C752CA2C143F70E81BC4B451E698510AC5828FE67E28EC50D30C54F485D9C7C2CB390F9648F0C41492AA78F20878C5EFD9D042C06758CFC29B47601FD1E47F4415DE6E14415F1DEA3497A9B963E3879E9BE6AA438E2D1C719FD3E5E786BD119C23C4C3B762B3A8A756829965452B9CCA5AD126CD8998BE5258D672D848CF17
        extension_type=supported_versions(43), length=2
            TLS 1.3 (772)

Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ChangeCipherSpec (20)
  Length = 1
    change_cipher_spec (1)

Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 2674
  Inner Content Type = Handshake (22)
    EncryptedExtensions, Length=6
      extensions, length = 4
        extension_type=server_name(0), length=0

    Certificate, Length=2511
      context (len=0): 
      certificate_list, length=2507
        ASN.1Cert, length=923
------details-----
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            94:8b:98:d3:26:10:07:8c:13:84:8b:58:6d:e3:b2:3f
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C = US, O = Google Trust Services, CN = WE1
        Validity
            Not Before: Sep 16 13:01:15 2026 GMT
            Not After : Dec 15 14:00:55 2026 GMT
        Subject: CN = www.cloudflare.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit field, 128 bit security level)
                pub:
                    04:2a:33:29:fa:ac:f5:5f:92:9c:a0:8f:1a:7a:7e:7b:
                    51:5a:d2:07:9a:41:b1:47:16:72:76:cd:b1:4d:fb:99:
                    03:cf:c0:08:15:ec:23:3e:f6:7d:cf:fa:1c:88:b8:16:
                    17:c8:d5:e7:af:fa:d4:af:84:76:0a:c7:00:2f:5c:bc:
                    22
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                74:87:DE:56:DA:DC:08:50:CE:84:68:3D:D1:94:19:F3:84:6B:0B:C4
            X509v3 Authority Key Identifier: 
                90:77:92:35:67:C4:FF:A8:CC:A9:E6:7B:D9:80:79:7B:CC:93:F9:38
            Authority Information Access: 
                CA Issuers - URI:http://i.pki.goog/we1.crt
            X509v3 Subject Alternative Name: 
                DNS:www.cloudflare.com, DNS:timeline.www.cloudflare.com
            X509v3 Certificate Policies: 
                Policy: 2.23.140.1.2.1
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:http://c.pki.goog/we1/7TkJBJfK_Y8.crl

            CT Precertificate SCTs: 
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : D7:6D:7D:10:D1:A7:F5:77:C2:C7:E9:5F:D7:00:BF:F9:
                                82:C9:33:5A:65:E1:D0:B3:01:73:17:C0:C8:C5:69:77
                    Timestamp : Sep 16 14:01:15.573 2026 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:44:02:20:14:04:B1:E0:8B:C1:1B:33:89:D2:74:1C:
                                CD:86:03:D5:E6:A0:AD:B7:0F:00:EF:A5:0E:86:16:44:
                                F7:61:2B:23:02:20:3B:8D:B1:28:81:6C:5B:87:31:DD:
                                48:23:1D:BC:24:38:57:04:8F:8B:C3:86:2D:87:25:DC:
                                DB:33:98:2A:D3:B3
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : C8:A3:C4:7F:C7:B3:AD:B9:35:6B:01:3F:6A:7A:12:6D:
                                E3:3A:4E:43:A5:C6:46:F9:97:AD:39:75:99:1D:CF:9A
                    Timestamp : Sep 16 14:01:15.589 2026 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:45:02:20:00:F6:12:BE:85:79:D7:E6:AE:8E:48:DD:
                                24:EF:F6:49:FA:0D:89:95:EF:47:CE:84:90:B7:E5:CB:
                                BB:5C:D7:C1:02:21:00:C7:65:D3:55:8F:B5:2D:BF:AC:
                                F1:72:8F:69:E6:2F:5D:AF:AF:16:8F:8C:5B:5C:63:AF:
                                BE:65:F6:E8:B4:15:AE
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:80:67:03:11:66:d9:dc:79:4c:53:4a:e7:02:a4:79:2e:1c:68:00:
        f3:f5:91:9d:3c:02:e6:46:55:82:22:63:49:02:20:0f:fc:7e:43:10:38:8f:68:04:
        82:66:81:45:f4:01:e0:2d:d6:cc:05:02:96:04:b9:5f:30:2b:f8:ec:f2:bb:05
-----BEGIN CERTIFICATE-----
MIIDlzCCAz2gAwIBAgIRAJSLmNMmEAeME4SLWG3jsj8wCgYIKoZIzj0EAwIwOzEL
MAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczEMMAoG
A1UEAxMDV0UxMB4XDTI2MDkxNjEzMDExNVoXDTI2MTIxNTE0MDA1NVowHTEbMBkG
A1UEAxMSd3d3LmNsb3VkZmxhcmUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAEKjMp+qz1X5KcoI8aen57UVrSB5pBsUcWcnbNsU37mQPPwAgV7CM+9n3P+hyI
uBYXyNXnr/rUr4R2CscAL1y8IqOCAj4wggI6MA4GA1UdDwEB/wQEAwIHgDATBgNV
HSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBR0h95W2twI
UM6EaD3RlBnzhGsLxDAfBgNVHSMEGDAWgBSQd5I1Z8T/qMyp5nvZgHl7zJP5ODA1
BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUHMAKGGWh0dHA6Ly9pLnBraS5nb29nL3dl
MS5jcnQwOgYDVR0RBDMwMYISd3d3LmNsb3VkZmxhcmUuY29tght0aW1lbGluZS53
d3cuY2xvdWRmbGFyZS5jb20wEwYDVR0gBAwwCjAIBgZngQwBAgEwNgYDVR0fBC8w
LTAroCmgJ4YlaHR0cDovL2MucGtpLmdvb2cvd2UxLzdUa0pCSmZLX1k4LmNybDCC
AQMGCisGAQQB1nkCBAIEgfQEgfEA7wB1ANdtfRDRp/V3wsfpX9cAv/mCyTNaZeHQ
swFzF8DIxWl3AAABoKqFkjUAAAQDAEYwRAIgFASx4IvBGzOJ0nQczYYD1eagrbcP
AO+lDoYWRPdhKyMCIDuNsSiBbFuHMd1IIx28JDhXBI+Lw4YthyXc2zOYKtOzAHYA
yKPEf8ezrbk1awE/anoSbeM6TkOlxkb5l605dZkdz5oAAAGgqoWSRQAABAMARzBF
AiAA9hK+hXnX5q6OSN0k7/ZJ+g2Jle9HzoSQt+XLu1zXwQIhAMdl01WPtS2/rPFy
j2nmL12vrxaPjFtcY6++ZfbotBWuMAoGCCqGSM49BAMCA0gAMEUCIQCAZwMRZtnc
eUxTSucCpHkuHGgA8/WRnTwC5kZVgiJjSQIgD/x+QxA4j2gEgmaBRfQB4C3WzAUC
lgS5XzAr+OzyuwU=
-----END CERTIFICATE-----
------------------
        No extensions
        ASN.1Cert, length=675
------details-----
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            7f:f3:19:77:97:2c:22:4a:76:15:5d:13:b6:d6:85:e3
        Signature Algorithm: ecdsa-with-SHA384
        Issuer: C = US, O = Google Trust Services LLC, CN = GTS Root R4
        Validity
            Not Before: Dec 13 09:00:00 2023 GMT
            Not After : Feb 20 14:00:00 2029 GMT
        Subject: C = US, O = Google Trust Services, CN = WE1
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit field, 128 bit security level)
                pub:
                    04:6f:cd:3a:fe:67:57:47:4c:21:03:85:40:c2:47:5d:
                    bb:58:47:0f:40:c1:5c:17:85:c6:19:37:e7:d5:7c:ed:
                    86:4b:9b:81:d9:d7:1a:13:a5:0a:03:f8:98:c4:c6:e8:
                    9e:ff:10:59:8f:2c:26:98:f5:e6:26:25:bb:0f:02:fa:
                    56
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                90:77:92:35:67:C4:FF:A8:CC:A9:E6:7B:D9:80:79:7B:CC:93:F9:38
            X509v3 Authority Key Identifier: 
                80:4C:D6:EB:74:FF:49:36:A3:D5:D8:FC:B5:3E:C5:6A:F0:94:1D:8C
            Authority Information Access: 
                CA Issuers - URI:http://i.pki.goog/r4.crt
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:http://c.pki.goog/r/r4.crl

            X509v3 Certificate Policies: 
                Policy: 2.23.140.1.2.1
    Signature Algorithm: ecdsa-with-SHA384
    Signature Value:
        30:65:02:31:00:e7:02:ab:51:d6:f7:43:95:ce:75:fe:d1:11:94:d5:cc:40:41:7a:
        26:be:d8:0c:f3:32:2d:3d:90:ae:15:0f:23:48:12:52:8f:3e:64:79:13:af:f5:a6:
        2c:02:6e:55:b1:02:30:26:89:cc:68:01:62:e7:89:ab:7e:17:e8:14:d6:44:7e:e3:
        4c:49:0e:bf:6c:80:62:34:b8:b2:a1:7e:3a:16:88:50:bc:a7:88:a0:9f:7d:73:1e:
        ec:52:41:4d:ee:e2:56
-----BEGIN CERTIFICATE-----
MIICnzCCAiWgAwIBAgIQf/MZd5csIkp2FV0TttaF4zAKBggqhkjOPQQDAzBHMQsw
CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU
MBIGA1UEAxMLR1RTIFJvb3QgUjQwHhcNMjMxMjEzMDkwMDAwWhcNMjkwMjIwMTQw
MDAwWjA7MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZp
Y2VzMQwwCgYDVQQDEwNXRTEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARvzTr+
Z1dHTCEDhUDCR127WEcPQMFcF4XGGTfn1XzthkubgdnXGhOlCgP4mMTG6J7/EFmP
LCaY9eYmJbsPAvpWo4H+MIH7MA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggr
BgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU
kHeSNWfE/6jMqeZ72YB5e8yT+TgwHwYDVR0jBBgwFoAUgEzW63T/STaj1dj8tT7F
avCUHYwwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzAChhhodHRwOi8vaS5wa2ku
Z29vZy9yNC5jcnQwKwYDVR0fBCQwIjAgoB6gHIYaaHR0cDovL2MucGtpLmdvb2cv
ci9yNC5jcmwwEwYDVR0gBAwwCjAIBgZngQwBAgEwCgYIKoZIzj0EAwMDaAAwZQIx
AOcCq1HW90OVznX+0RGU1cxAQXomvtgM8zItPZCuFQ8jSBJSjz5keROv9aYsAm5V
sQIwJonMaAFi54mrfhfoFNZEfuNMSQ6/bIBiNLiyoX46FohQvKeIoJ99cx7sUkFN
7uJW
-----END CERTIFICATE-----
------------------
        No extensions
        ASN.1Cert, length=894
------details-----
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            7f:e5:30:bf:33:13:43:be:dd:82:16:10:49:3d:8a:1b
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = BE, O = GlobalSign nv-sa, OU = Root CA, CN = GlobalSign Root CA
        Validity
            Not Before: Nov 15 03:43:21 2023 GMT
            Not After : Jan 28 00:00:42 2028 GMT
        Subject: C = US, O = Google Trust Services LLC, CN = GTS Root R4
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit field, 192 bit security level)
                pub:
                    04:f3:74:73:a7:68:8b:60:ae:43:b8:35:c5:81:30:7b:
                    4b:49:9d:fb:c1:61:ce:e6:de:46:bd:6b:d5:61:18:35:
                    ae:40:dd:73:f7:89:91:30:5a:eb:3c:ee:85:7c:a2:40:
                    76:3b:a9:c6:b8:47:d8:2a:e7:92:91:6a:73:e9:b1:72:
                    39:9f:29:9f:a2:98:d3:5f:5e:58:86:65:0f:a1:84:65:
                    06:d1:dc:8b:c9:c7:73:c8:8c:6a:2f:e5:c4:ab:d1:1d:
                    8a
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier: 
                80:4C:D6:EB:74:FF:49:36:A3:D5:D8:FC:B5:3E:C5:6A:F0:94:1D:8C
            X509v3 Authority Key Identifier: 
                60:7B:66:1A:45:0D:97:CA:89:50:2F:7D:04:CD:34:A8:FF:FC:FD:4B
            Authority Information Access: 
                CA Issuers - URI:http://i.pki.goog/gsr1.crt
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:http://c.pki.goog/r/gsr1.crl

            X509v3 Certificate Policies: 
                Policy: 2.23.140.1.2.1
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        18:42:bb:0f:06:d6:03:87:96:e3:3f:63:81:0f:09:a4:a1:68:48:0c:39:22:73:9e:
        f8:cb:4e:2d:7f:31:e9:9f:e7:09:a1:d2:36:0f:84:ac:79:eb:10:e9:b0:eb:6a:b6:
        7b:0b:7d:1d:74:b8:9b:65:ab:68:2a:2c:2c:dd:42:fd:c6:71:0b:cf:87:2d:f7:6b:
        c8:0f:6e:05:7d:56:e2:23:58:58:f9:25:ba:16:85:47:90:d7:96:20:fd:06:09:b6:
        8c:e0:2e:ae:55:d1:79:75:35:2c:31:5b:3f:65:bc:cd:9c:87:42:a7:91:b1:9b:1e:
        5e:8e:f1:1a:bb:ca:2d:47:f0:ac:90:63:7e:86:bf:d6:e4:6b:d3:d6:d3:01:8e:05:
        8a:67:58:b8:ff:f7:a6:84:0d:49:1b:50:5b:3f:3a:0b:25:0b:f2:12:8b:5c:d3:79:
        57:8d:36:82:ce:ff:26:11:b7:a9:f1:1a:99:ed:ad:82:3e:c8:11:6e:eb:d3:3c:1c:
        1c:38:c0:41:9a:e1:5e:53:cf:3e:15:20:57:eb:ee:e2:3f:48:a5:f1:be:19:d1:01:
        6a:23:0c:0c:1d:fb:3f:2f:a2:b5:bd:ea:6e:a3:1b:46:ce:2e:02:67:af:33:26:98:
        aa:d5:4b:d2:a9:36:c5:26:3b:5b:0f:8b:1e:88:c1:e5
-----BEGIN CERTIFICATE-----
MIIDejCCAmKgAwIBAgIQf+UwvzMTQ77dghYQST2KGzANBgkqhkiG9w0BAQsFADBX
MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEQMA4GA1UE
CxMHUm9vdCBDQTEbMBkGA1UEAxMSR2xvYmFsU2lnbiBSb290IENBMB4XDTIzMTEx
NTAzNDMyMVoXDTI4MDEyODAwMDA0MlowRzELMAkGA1UEBhMCVVMxIjAgBgNVBAoT
GUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBMTEMxFDASBgNVBAMTC0dUUyBSb290IFI0
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE83Rzp2iLYK5DuDXFgTB7S0md+8Fhzube
Rr1r1WEYNa5A3XP3iZEwWus87oV8okB2O6nGuEfYKueSkWpz6bFyOZ8pn6KY019e
WIZlD6GEZQbR3IvJx3PIjGov5cSr0R2Ko4H/MIH8MA4GA1UdDwEB/wQEAwIBhjAd
BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUgEzW63T/STaj1dj8tT7FavCUHYwwHwYDVR0jBBgwFoAUYHtmGkUN
l8qJUC99BM00qP/8/UswNgYIKwYBBQUHAQEEKjAoMCYGCCsGAQUFBzAChhpodHRw
Oi8vaS5wa2kuZ29vZy9nc3IxLmNydDAtBgNVHR8EJjAkMCKgIKAehhxodHRwOi8v
Yy5wa2kuZ29vZy9yL2dzcjEuY3JsMBMGA1UdIAQMMAowCAYGZ4EMAQIBMA0GCSqG
SIb3DQEBCwUAA4IBAQAYQrsPBtYDh5bjP2OBDwmkoWhIDDkic574y04tfzHpn+cJ
odI2D4SseesQ6bDrarZ7C30ddLibZatoKiws3UL9xnELz4ct92vID24FfVbiI1hY
+SW6FoVHkNeWIP0GCbaM4C6uVdF5dTUsMVs/ZbzNnIdCp5Gxmx5ejvEau8otR/Cs
kGN+hr/W5GvT1tMBjgWKZ1i4//emhA1JG1BbPzoLJQvyEotc03lXjTaCzv8mEbep
8RqZ7a2CPsgRbuvTPBwcOMBBmuFeU88+FSBX6+7iP0il8b4Z0QFqIwwMHfs/L6K1
vepuoxtGzi4CZ68zJpiq1UvSqTbFJjtbD4seiMHl
-----END CERTIFICATE-----
------------------
        No extensions

depth=2 C=US, O=Google Trust Services LLC, CN=GTS Root R4
verify return:1
depth=1 C=US, O=Google Trust Services, CN=WE1
verify return:1
depth=0 CN=www.cloudflare.com
verify return:1
    CertificateVerify, Length=76
      Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
      Signature (len=72): 3046022100A645F7B4A950707961BA0DF83316CB9439D1FB445773D2D6309E773ACAC4E52C022100C093CE901B686F0107DEF0B9F76CABA0B264B53D3C48A578558094947675CF22

    Finished, Length=48
      verify_data (len=48): C83EA5E61D401E05B1563393BD560568C07E6819A2C54BF7CFF8C427045F3BACB682C865F45D8E6742DC41939F839CAE

Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ChangeCipherSpec (20)
  Length = 1
    change_cipher_spec (1)

Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 69
  Inner Content Type = Handshake (22)
    Finished, Length=48
      verify_data (len=48): 4E4DCE9DB0986BA9696A56680EFA2D7869AF8690DFD6CB1F15EB23C1CE627B30599D6CBB05281EB85781D91E86FCE948

---
Certificate chain
 0 s:CN=www.cloudflare.com
   i:C=US, O=Google Trust Services, CN=WE1
   a:PKEY: EC, (prime256v1); sigalg: ecdsa-with-SHA256
   v:NotBefore: Sep 16 13:01:15 2026 GMT; NotAfter: Dec 15 14:00:55 2026 GMT
 1 s:C=US, O=Google Trust Services, CN=WE1
   i:C=US, O=Google Trust Services LLC, CN=GTS Root R4
   a:PKEY: EC, (prime256v1); sigalg: ecdsa-with-SHA384
   v:NotBefore: Dec 13 09:00:00 2023 GMT; NotAfter: Feb 20 14:00:00 2029 GMT
 2 s:C=US, O=Google Trust Services LLC, CN=GTS Root R4
   i:C=BE, O=GlobalSign nv-sa, OU=Root CA, CN=GlobalSign Root CA
   a:PKEY: EC, (secp384r1); sigalg: sha256WithRSAEncryption
   v:NotBefore: Nov 15 03:43:21 2023 GMT; NotAfter: Jan 28 00:00:42 2028 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIDlzCCAz2gAwIBAgIRAJSLmNMmEAeME4SLWG3jsj8wCgYIKoZIzj0EAwIwOzEL
MAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczEMMAoG
A1UEAxMDV0UxMB4XDTI2MDkxNjEzMDExNVoXDTI2MTIxNTE0MDA1NVowHTEbMBkG
A1UEAxMSd3d3LmNsb3VkZmxhcmUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAEKjMp+qz1X5KcoI8aen57UVrSB5pBsUcWcnbNsU37mQPPwAgV7CM+9n3P+hyI
uBYXyNXnr/rUr4R2CscAL1y8IqOCAj4wggI6MA4GA1UdDwEB/wQEAwIHgDATBgNV
HSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBR0h95W2twI
UM6EaD3RlBnzhGsLxDAfBgNVHSMEGDAWgBSQd5I1Z8T/qMyp5nvZgHl7zJP5ODA1
BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUHMAKGGWh0dHA6Ly9pLnBraS5nb29nL3dl
MS5jcnQwOgYDVR0RBDMwMYISd3d3LmNsb3VkZmxhcmUuY29tght0aW1lbGluZS53
d3cuY2xvdWRmbGFyZS5jb20wEwYDVR0gBAwwCjAIBgZngQwBAgEwNgYDVR0fBC8w
LTAroCmgJ4YlaHR0cDovL2MucGtpLmdvb2cvd2UxLzdUa0pCSmZLX1k4LmNybDCC
AQMGCisGAQQB1nkCBAIEgfQEgfEA7wB1ANdtfRDRp/V3wsfpX9cAv/mCyTNaZeHQ
swFzF8DIxWl3AAABoKqFkjUAAAQDAEYwRAIgFASx4IvBGzOJ0nQczYYD1eagrbcP
AO+lDoYWRPdhKyMCIDuNsSiBbFuHMd1IIx28JDhXBI+Lw4YthyXc2zOYKtOzAHYA
yKPEf8ezrbk1awE/anoSbeM6TkOlxkb5l605dZkdz5oAAAGgqoWSRQAABAMARzBF
AiAA9hK+hXnX5q6OSN0k7/ZJ+g2Jle9HzoSQt+XLu1zXwQIhAMdl01WPtS2/rPFy
j2nmL12vrxaPjFtcY6++ZfbotBWuMAoGCCqGSM49BAMCA0gAMEUCIQCAZwMRZtnc
eUxTSucCpHkuHGgA8/WRnTwC5kZVgiJjSQIgD/x+QxA4j2gEgmaBRfQB4C3WzAUC
lgS5XzAr+OzyuwU=
-----END CERTIFICATE-----
subject=CN=www.cloudflare.com
issuer=C=US, O=Google Trust Services, CN=WE1
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: ecdsa_secp256r1_sha256
Negotiated TLS1.3 group: X25519MLKEM768
---
SSL handshake has read 3900 bytes and written 1558 bytes
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
Server public key is 256 bit
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
ECH: NOT CONFIGURED: -103
---
DONE
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 19
  Inner Content Type = Alert (21)
    Level=warning(1), description=close notify(0)
```    

