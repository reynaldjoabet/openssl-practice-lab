## PEM 
A common way to exchange keys or certifates is to use the text-based PEM format. The JDk comes with all the building blocks to turn these texts into cryptographic material or objects. In JDK 25,there is an api that makes these transformations much easier
- You create a `PEMEncoder`, then call `encode` with an instance of the new interface `DEREncodable`, which types like `AsymmetricKey` and `X509Certifcate` extend

PEM is specified by RFC 7468, it's a textual representation of cryptographic material like private and public keys, certificates and certifcate revocation list. The text's body is the cryptographic object's base64-encoded binary representation

`DEREncodable` direct subtypes:
- AsymmetricKey( with subtypes for private/public key keys for DH,DSA,EC,RSA etc)
- KeyPair
- PKCS8EncodedKeySpec
- X509EncodedKeySpec
- EncryptedPrivateKeyInfo
- X509Certifcate
- X509CRL
- PEMRecord: captures the PEM texts of cryptographic objects that the JDK doesn't have a type for: such as PKCS10 certificate requests, those enabling you to process them as well

Applications often send and receive representations of cryptographic objects, whether via user interfaces, over the network, or to and from storage devices. The Privacy-Enhanced Mail (PEM) format, defined by RFC 7468, is often used for this purpose.

This textual format was originally designed for sending cryptographic objects via e-mail, but over time it has been used and extended for other purposes. Certificate authorities issue certificate chains in the PEM format. Cryptographic libraries such as OpenSSL provide operations for generating and converting PEM-encoded cryptographic objects. Security-sensitive applications such as OpenSSH store communication keys in the PEM format. Hardware authentication devices such as Yubikeys ingest and dispense PEM-encoded cryptographic objects.

Here is an example of a PEM-encoded cryptographic object, in this case an elliptic curve public key:
```pem
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi/kRGOL7wCPTN4KJ2ppeSt5UYB6u
cPjjuKDtFTXbguOIFDdZ65O/8HTUqS/sVzRF+dg7H3/tkQ/36KdtuADbwQ==
-----END PUBLIC KEY-----
```
A PEM text contains a Base64-encoded representation of the key's binary representation surrounded by a header and footer containing the words BEGIN and END, respectively. The remaining text in the header and the footer identifies the type of the cryptographic object, in this case a PUBLIC KEY. Details of the key, such as its algorithm and content, can be obtained by parsing the Base64-encoded binary representation.


## DER-encodable cryptographic objects

PEM is a textual format for binary data. To encode a cryptographic object into PEM text, or to decode PEM text into a cryptographic object, we need a way to convert such objects to and from binary data. Fortunately, the Java APIs for cryptographic keys, certificates, and certificate revocation lists all provide the means to convert their instances to and from byte arrays in the Distinguished Encoding Rules (DER) format. Unfortunately, these APIs are not hierarchically related, and the manner in which they expose these conversions is not uniform.

We thus introduce a new interface, `DEREncodable`, to identify the cryptographic APIs that provide such conversions and whose instances can therefore be encoded to, and decoded from, the PEM format. This empty interface is sealed; its permitted classes and interfaces are `AsymmetricKey`, `X509Certificate`, `X509CRL`, `KeyPair`, `EncryptedPrivateKeyInfo`, `PKCS8EncodedKeySpec`, `X509EncodedKeySpec`, and `PEMRecord`:
```java
public sealed interface DEREncodable
    permits AsymmetricKey, KeyPair,
            PKCS8EncodedKeySpec, X509EncodedKeySpec,
            EncryptedPrivateKeyInfo, X509Certificate, X509CRL,
            PEMRecord
{ }
```
We make corresponding adjustments to some of the permitted classes and interfaces:
```java
public non-sealed interface AsymmetricKey { ... }
public non-sealed class PKCS8EncodedKeySpec { ... }
public non-sealed class X509EncodedKeySpec { ... }
public non-sealed class EncryptedPrivateKeyInfo { ... }
public non-sealed abstract class X509Certificate { ... }
public non-sealed abstract class X509CRL { ... }
```

### The PEMRecord class

The PEMRecord class implements DEREncodable. Its instances can hold any type of PEM data. It thus enables you to encode and decode PEM texts representing cryptographic objects for which no Java Platform API exists

```java
public record PEMRecord(String type, String content, byte[] leadingData)
    implements DEREncodable
{
    public PEMRecord(String type, String content);
    public PEMRecord(String type, String content, byte[] leadingData);
    String type();           // Cryptographic object type, from the header text
                             // (e.g., "PRIVATE KEY")
    String content();            // Base64-encoded PEM content
    byte[] leadingData();    // Any content preceding the PEM header
}
```

A disadvantage of a binary data format is that it cannot be interchanged in textual transports, such as email or text documents.One advantage with text-based encodings is that they are easy to modify using common text editors; for example, a user may concatenate several certificates to form a certificate chain with copy-and-paste operations

*Textual Encoding of Certificates*
Public-key certificates are encoded using the "CERTIFICATE" label.The encoded data MUST be a BER (DER strongly preferred;)

To promote interoperability and to separate DER encodings from textual encodings, the extension ".crt" SHOULD be used for the textual encoding of a certificate

*Textual Encoding of Certificate Revocation Lists*

Certificate Revocation Lists (CRLs) are encoded using the "X509 CRL" label.  The encoded data MUST be a BER (DER strongly preferred; )

*Textual Encoding of PKCS #10 Certification Request Syntax*
PKCS #10 Certification Requests are encoded using the "CERTIFICATE REQUEST" label.  The encoded data MUST be a BER (DER strongly preferred;)

*Textual Encoding of PKCS #7 Cryptographic Message Syntax*

PKCS #7 Cryptographic Message Syntax structures are encoded using the "PKCS7" label.  The encoded data MUST be a BER-encoded ASN.1 ContentInfo structure

Cryptographic Message Syntax structures are encoded using the "CMS" label.  The encoded data MUST be a BER-encoded ASN.1 ContentInfo structure

*Textual Encoding of Cryptographic Message Syntax* 
PKCS #7 is an old specification that has long been superseded by CMS

The CMS describes an encapsulation syntax for data protection.  It supports digital signatures and encryption.  The syntax allows multiple encapsulations; one encapsulation envelope can be nested inside another.  Likewise, one party can digitally sign some previously encapsulated data.  It also allows arbitrary attributes, such as signing time, to be signed along with the message content, and it provides for other attributes such as countersignatures to be associated with a signature

The CMS can support a variety of architectures for certificate-based key management, such as the one defined by the PKIX (Public Key Infrastructure using X.509)

*One Asymmetric Key and the Textual Encoding of PKCS #8 Private Key Info*

Unencrypted PKCS #8 Private Key Information Syntax structures (`PrivateKeyInfo`), renamed to Asymmetric Key Packages (OneAsymmetricKey), are encoded using the "PRIVATE KEY" label.  The encoded data MUST be a BER (DER preferred;) encoded ASN.1 `PrivateKeyInfo` structure as described in PKCS #8 [RFC5208], or a `OneAsymmetricKey` structure as described in [RFC5958].  The two are semantically identical and can be distinguished by version number.

This document defines the syntax for private-key information and a content type for it.  Private-key information includes a private key for a specified public-key algorithm and a set of attributes.  The Cryptographic Message Syntax (CMS), as defined in RFC 5652, can be used to digitally sign, digest, authenticate, or encrypt the asymmetric key format content type

*Textual Encoding of PKCS #8 Encrypted Private Key Info*

Encrypted PKCS #8 Private Key Information Syntax structures (`EncryptedPrivateKeyInfo`), called the same in [RFC5958], are encoded using the "ENCRYPTED PRIVATE KEY" label.  The encoded data MUST be a BER (DER preferred;) encoded ASN.1 `EncryptedPrivateKeyInfo` structure as described in PKCS #8 [RFC5208] and [RFC5958].

*Textual Encoding of Attribute Certificates*

Attribute certificates are encoded using the "ATTRIBUTE CERTIFICATE" label.  The encoded data MUST be a BER (DER strongly preferred;) encoded ASN.1 `AttributeCertificate` structure

*Textual Encoding of Subject Public Key Info*

Public keys are encoded using the "PUBLIC KEY" label.  The encoded data MUST be a BER (DER preferred;) encoded ASN.1 `SubjectPublicKeyInfo` structure

DER is a restricted profile of BER [X.690]; thus, all DER encodings of data values are BER encodings, but just one of the BER encodings is the DER encoding for a data value.

- `Certificate`: A type that binds an entity's distinguished name to a public key with a digital signature. This type is defined in X.509. This type also contains the distinguished name of the certificate issuer (the signer), an issuer-specific serial number, the issuer's signature algorithm identifier, and a validity period.

- `CertificateSerialNumber`: A type that uniquely identifies a certificate (and thereby an entity and a public key) among those signed by a particular certificate issuer. This type is defined in X.509.

Along with the certificate the server will also send to the client proof that it knows the private key associated with the public key in the certificate. It does this by digitally signing a message to the client using that private key. The client can verify the signature using the public key from the certificate. If the signature verifies successfully then the client knows that the server is in possession of the correct private key.

```sh          
# openssl s_client www.openssl.org:443
Connecting to 34.49.79.89
CONNECTED(00000005)
depth=2 C=US, O=Google Trust Services LLC, CN=GTS Root R1
verify return:1
depth=1 C=US, O=Google Trust Services, CN=WR3
verify return:1
depth=0 CN=openssl.org
verify return:1
---
Certificate chain
 0 s:CN=openssl.org
   i:C=US, O=Google Trust Services, CN=WR3
   a:PKEY: RSA, 2048 (bit); sigalg: sha256WithRSAEncryption
   v:NotBefore: Aug 18 23:07:47 2026 GMT; NotAfter: Nov 17 00:00:19 2026 GMT
 1 s:C=US, O=Google Trust Services, CN=WR3
   i:C=US, O=Google Trust Services LLC, CN=GTS Root R1
   a:PKEY: RSA, 2048 (bit); sigalg: sha256WithRSAEncryption
   v:NotBefore: Dec 13 09:00:00 2023 GMT; NotAfter: Feb 20 14:00:00 2029 GMT
 2 s:C=US, O=Google Trust Services LLC, CN=GTS Root R1
   i:C=BE, O=GlobalSign nv-sa, OU=Root CA, CN=GlobalSign Root CA
   a:PKEY: RSA, 4096 (bit); sigalg: sha256WithRSAEncryption
   v:NotBefore: Jun 19 00:00:42 2020 GMT; NotAfter: Jan 28 00:00:42 2028 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIFCTCCA/GgAwIBAgIQaFMl5zFhK+4J1i9vCEXFCDANBgkqhkiG9w0BAQsFADA7
MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMQww
CgYDVQQDEwNXUjMwHhcNMjYwODE4MjMwNzQ3WhcNMjYxMTE3MDAwMDE5WjAWMRQw
EgYDVQQDEwtvcGVuc3NsLm9yZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBALL5LKfR9XlkNWh4Zjl1LPWJ/AjfuKHtZS4PNX1lzncjZh4FRVB27HP4aPq1
5ONUHJ7z39qBrRyCZA92V7OpbPUpD4NgzFYaL/APZ1gOgIB/ncVskj86oiRZF8Su
pCmJCOGemFqEz02/odSk0GHV4U/2+4G04Le4xmWzkPRnTqYDdyns6JxXglaoSm+q
YQrmfTW2cLMTl7pMQ7QbAKyAl6lKuhIV//OY/IsZ4a45+5OKqApx/JKGqXESU6F6
O1r12cbuGvtsTq6aql9e+5jXhL5iQBYPyvHdh6jOzT5Er72DnLIih3tQ+Uw/FJhg
IrvWP9ryHYb/fREEyZzXI2EyRncCAwEAAaOCAiwwggIoMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSk
bieDmiQRW6xCuFa5lqmGWlk45TAfBgNVHSMEGDAWgBTHgfX9jojZADxNY6JQMSSg
ziP+IzA1BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUHMAKGGWh0dHA6Ly9pLnBraS5n
b29nL3dyMy5jcnQwJwYDVR0RBCAwHoILb3BlbnNzbC5vcmeCD3d3dy5vcGVuc3Ns
Lm9yZzATBgNVHSAEDDAKMAgGBmeBDAECATA2BgNVHR8ELzAtMCugKaAnhiVodHRw
Oi8vYy5wa2kuZ29vZy93cjMvZnFsdWJlQlJzeUkuY3JsMIIBBAYKKwYBBAHWeQIE
AgSB9QSB8gDwAHYAwjF+V0UZo0XufzjespBB68fCIVoiv3/Vta12mtkOUs0AAAGg
F1hz9AAABAMARzBFAiAakNaMQFDKk+CcO6/pwLcz03RE6BONjXXclUEVJ1rrPgIh
ALx2svoY6hLpGyGO1jmlLP+/gtB3rQlNw9cc+hj38i7IAHYA2AlVO5RPev/IFhlv
lE+Fq7D4/F6HVSYPFdEucrtFSxQAAAGgF1h0aAAABAMARzBFAiEAk2kpLs77K8to
BPh2Drq1MDG/PoB36g8KRHLt4HHbcOoCIG8hKjiSJmnbBqlosHpnTOX/I194ci8A
WODe4UOnbTb2MA0GCSqGSIb3DQEBCwUAA4IBAQAAHYy1B4OLV+N0V8NOOUiVmI8X
kvHBMNzybUFCBqEmp4AUeCMGWzya+6KV/CXkdxl8bwd6PbLTr4R8PVd89kr0Qndu
/5kVCxTl7whJQ34TCNlo9hcbKpSmTeoyutaIdoj2Ce5D0/L6qLxBjeiZ5R4LPzFt
/qTpSwALqO3fQxKKZSScMLIygLgM2h1ci824pU8iuM8VGQhaMuH7ylBNHQ3556dx
2OXRkiV1opanmajTVxnk26tdWijUidD9VuRaVhBsnT5cj0a+y53vObKaNNjXRxnI
PJ6/ZbrheO0cQw+v9DC2z0OpjfO0PWP63fqzI6PThxMuGrOiw0C5qDbrRdiF
-----END CERTIFICATE-----
subject=CN=openssl.org
issuer=C=US, O=Google Trust Services, CN=WR3
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: rsa_pss_rsae_sha256
Peer Temp Key: X25519, 253 bits
---
SSL handshake has read 4474 bytes and written 1634 bytes
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
Server public key is 2048 bit
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
ECH: NOT CONFIGURED: -103
```

## Block Cipher GCM


## Stream Cipher ChaCha



Support for hybrid ML-KEM key exchange, ML-DSA and SLH-DSA authentication, together with additional integrity-only and ShangMi cipher suites, provides a strong foundation for organizations preparing for future cryptographic requirements

## PEM
- A text encoding, not a keystore. It is base64-encoded DER data wrapped in header and footer lines such as `-----BEGIN CERTIFICATE-----` and `-----BEGIN PRIVATE KEY-----`.
- Contents: each file normally holds one or a few items: a certificate, a certificate chain, or a private key. You can concatenate several in one file.
- Protection: none by default. A private key can be encrypted, but the file as a whole is not.
- Readability: you can open it in a text editor and copy and paste it.

```pem
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAET9q6u86RKq2Og1/2IrezaFJeT9UQ
Nl1ARJhhT2ZL9A9bxIIN1C1VGzHrLjR2FtcPxWfikli9WBjF4M1kn6AjQQ==
-----END PUBLIC KEY-----
```
It's a label line, Base64 text wrapped at 64 characters, and an end line. The label says what's inside.

Layer 2: decode the Base64 and you get DER bytes
```sh
3059 3013 0607 2a86 48ce 3d02 0106 082a 8648 ce3d 0301 0703 4200 044f daba ...

```
DER (Distinguished Encoding Rules) is the binary encoding. Each item is tag, length, value: `30 59` means "a SEQUENCE, 89 bytes long".

Layer 1: parse the DER and you get the actual ASN.1 structure
```sh
SEQUENCE                              ← SubjectPublicKeyInfo
  SEQUENCE                            ← AlgorithmIdentifier
    OBJECT :id-ecPublicKey            ← "this is an EC key"
    OBJECT :prime256v1                ← "on curve P-256"
  BIT STRING (66 bytes)               ← 04 || X (32 bytes) || Y (32 bytes): the public point
```

```sh
ASN.1 structure ──DER──► binary bytes ──Base64──► text ──add BEGIN/END labels──► PEM
```

Common labels
The label tells you which ASN.1 structure is inside:

| Label | Contents | Notes |
| --- | --- | --- |
| CERTIFICATE | X.509 certificate | like the three in your Cloudflare trace; public |
| PUBLIC KEY | SubjectPublicKeyInfo | any algorithm; public |
| PRIVATE KEY | PKCS#8 private key, any algorithm | modern standard; unencrypted |
| ENCRYPTED PRIVATE KEY | PKCS#8, encrypted with a password | what you should store |
| RSA PRIVATE KEY | PKCS#1, RSA only | older OpenSSL format |
| EC PRIVATE KEY | SEC1, EC only | older OpenSSL format |
| CERTIFICATE REQUEST | CSR (PKCS#10) | sent to a CA to obtain a certificate |
| X509 CRL | certificate revocation list |

### Encoding is not encryption
Base64 isn't protection. Anyone can decode a `-----BEGIN PRIVATE KEY-----` block. To store a private key as PEM, encrypt it:
```sh
openssl pkcs8 -topk8 -in key.pem -v2 aes-256-cbc      →   -----BEGIN ENCRYPTED PRIVATE KEY-----
```
The key bytes are then protected with AES and a password-derived key, using PBKDF2 , via the PBES2 scheme

- PEM itself never encrypts anything. It only does Base64 plus BEGIN/END lines.
- What PEM wraps can already be encrypted. The encryption happens before the PEM wrapping, in the ASN.1 data inside

Unencrypted private key:
```sh
PKCS#8 PrivateKeyInfo  ──DER──►  bytes  ──Base64 + labels──►  -----BEGIN PRIVATE KEY-----
(the key itself)                                               ← anyone can decode it
```


Encrypted private key:
```sh
PKCS#8 PrivateKeyInfo ──AES with password──► EncryptedPrivateKeyInfo ──DER──► bytes ──Base64 + labels──► -----BEGIN ENCRYPTED PRIVATE KEY-----
                       ↑ encryption happens HERE                                    ↑ PEM still just wraps
```

Running `openssl pkcs8 -topk8 -v2 aes-256-cbc` does the encryption step (PKCS#8 + PBES2). `PEM` then wraps the encrypted bytes, exactly as it would wrap anything else. Decoding the Base64 gets you only ciphertext; you still need the password. So it's encrypted content in a `PEM` wrapper

Alternatives

| Format | What it is | Typical use |
| --- | --- | --- |
| DER | The same bytes, without Base64 or labels | Binary files (`.der`, `.cer`); inside protocols (TLS sends certificates as DER, not PEM) |
| PKCS#12 (`.p12`, `.pfx`) | One password-protected bundle: private key + certificate chain | Java's default keystore type since JDK 9; importing client certificates into browsers and OSes |
| JKS (`.jks`) | Java's old proprietary keystore | Legacy; prefer PKCS#12 |
| JWK / JWKS | JSON representation of keys | OAuth / OpenID Connect |
| OpenSSH format | `ssh-ed25519 AAAA…` public keys; `-----BEGIN OPENSSH PRIVATE KEY-----` | SSH only |
| PKCS#11 / HSM / cloud KMS | The key never leaves the hardware; you only get a handle | Production signing keys, banks, CAs;|

For comparison, here's the same public key as above, as a JWK:

```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "T9q6u86RKq2Og1_2IrezaFJeT9UQNl1ARJhhT2ZL9A8",
  "y": "W8SCDdQtVRsx6y40dhbXD8Vn4pJYvVgYxeDNZJ-gI0E"
}
```

### Which to use
- Certificates and public keys in config files or for sharing: PEM.
- Inside protocols: DER (TLS) or JWK (OAuth/OIDC/JOSE).
- A private key with its certificate chain for a Java server: PKCS#12.
- Private keys at rest, if they must be files: encrypted PKCS#8 PEM or PKCS#12. In production, prefer an HSM or KMS, so the key can't be copied at all.

A `.p12` file is protected as a whole: the contents are encrypted, and the bundle has a password-based MAC, so tampering with any part is detected. That's one reason Java uses PKCS#12 as its default keystore format.

```sh
$ openssl pkcs12 -in demo.p12 -info -noout

MAC: sha256, Iteration 2048                       ← ② integrity: covers the WHOLE file
MAC length: 32, salt length: 16
PKCS7 Encrypted data: PBES2, PBKDF2, AES-256-CBC  ← ① confidentiality: container holding…
Certificate bag                                       …the certificate (encrypted)
PKCS7 Data                                        ← a plain container holding…
Shrouded Keybag: PBES2, PBKDF2, AES-256-CBC           …the private key, encrypted on its own
```

### ② Integrity: a MAC over everything
The MAC (HMAC-SHA256 here) is computed over the entire contents with another key derived from the password. If anyone changes, swaps or removes any part (a certificate, the key, a bag), the MAC check fails when the file is opened. PEM has nothing like this.

Both usually come from the same password. A weak password breaks both protections at once. The iteration count ;2048 for OpenSSL; 10,000 by default  JDK 25

## ① Encryption keys: PBKDF2 (via PBES2)
Every encrypted item (the key bag, the certificate container) gets its own random salt:

```sh
AES-256 key = PBKDF2-HMAC-SHA256(password, salt_item, iterations, 32 bytes)
IV          = random, stored in the file next to the salt   ← not derived from the password
```

## ② The MAC key: the PKCS#12 KDF
The MAC key comes from an older KDF defined in the PKCS#12 standard itself (RFC 7292, Appendix B), not from PBKDF2. Its distinctive feature is a "purpose byte" mixed into the derivation

```java
static final int CIPHER_KEY = 1;
static final int CIPHER_IV  = 2;
static final int MAC_KEY    = 3;
```

```java
derivedKey = PKCS12PBECipherCore.derive(password, salt, iterations, keyLength,               PKCS12PBECipherCore.MAC_KEY, algorithm, blockLength);


```
Purposes 1 and 2 were used by the legacy PKCS#12 ciphers (the old 3DES/RC2 ones), which derived both their key and their IV from the password. Modern files use PBES2 for encryption, so in practice only purpose 3 (the MAC) still uses this KDF.

Every key in the file comes from the one password, so its strength sets an upper limit on everything. The iteration counts are low compared with password-storage advice: OpenSSL used 2048 in the file we inspected, and the JDK defaults to 10,000. OWASP recommends about 600,000 for PBKDF2 when hashing user passwords. That's a trade-off for how quickly the file opens, so use a long, random password for any `.p12` that holds a real private key. Better still, keep production keys in an HSM or KMS, where no password-derived key exists to attack.

A newer standard, RFC 9579 (PBMAC1), lets the MAC use PBKDF2 as well, so both protections share the stronger, configurable KDF


RFC 9579, "Use of Password-Based Message Authentication Code 1 (PBMAC1) in PKCS #12 Syntax" (May 2024), updates PKCS #12 so the integrity MAC can use PBKDF2-based PBMAC1 instead of the legacy PKCS #12 KDF.

Problem it solves

Classic PKCS #12 (RFC 7292) derives the MAC key with its own KDF (Appendix B), which is a weak, SHA-1-era construction with a fixed iteration scheme. It's not approved by NIST SP 800-132 and is a poor fit for FIPS environments.
PBMAC1 (defined in PKCS #5 v2.1 / RFC 8018) uses PBKDF2 to derive the key and then an HMAC. That's the standard, FIPS-friendly approach.

## Creating the file (openssl pkcs12 -export, or Java's KeyStore.store)
```sh
                                 your password: "demo"
                                          │
          ┌───────────────────────────────┼────────────────────────────────┐
          │                               │                                │
          ▼                               ▼                                ▼
 ┌─────────────────────┐        ┌─────────────────────┐        ┌───────────────────────┐
 │ PBKDF2-HMAC-SHA256  │        │ PBKDF2-HMAC-SHA256  │        │ PKCS#12 KDF (SHA-256) │
 │ salt₁ (random)      │        │ salt₂ (random)      │        │ salt₃ (random)        │
 │ 2048 iterations     │        │ 2048 iterations     │        │ 2048 iterations       │
 │                     │        │                     │        │ purpose byte = 3 (MAC)│
 └──────────┬──────────┘        └──────────┬──────────┘        └───────────┬───────────┘
            ▼                              ▼                               ▼
     AES-256 key K₁                 AES-256 key K₂                  HMAC key K₃
            │                              │                               │
            ▼                              ▼                               │
 ┌─────────────────────┐        ┌─────────────────────┐                    │
 │ AES-256-CBC(K₁, IV₁)│        │ AES-256-CBC(K₂, IV₂)│                    │
 │ ← private key       │        │ ← certificate(s)     │                    │
 │ (IV₁ random)        │        │ (IV₂ random)        │                    │
 └──────────┬──────────┘        └──────────┬──────────┘                    │
            ▼                              ▼                               │
   "Shrouded Keybag"              "PKCS7 Encrypted data"                   │
   (encrypted private key)        (encrypted certificate bag)               │
            │                              │                               │
            └──────────────┬───────────────┘                               │
                           ▼                                               │
                 ┌───────────────────┐                                     │
                 │ AuthenticatedSafe │ ◄──── HMAC-SHA256(K₃, all of it)  ──┘
                 │ (all the bags)    │                    │
                 └─────────┬─────────┘                    ▼
                           │                         32-byte MAC
                           ▼                              │
 ┌─────────────────────────────────────────────────────────────────────────┐
 │ demo.p12                                                                │
 │  • AuthenticatedSafe: encrypted key bag + encrypted cert bag            │
 │  • stored in the clear next to each item: salt₁/IV₁, salt₂/IV₂, iterations│
 │  • MacData: MAC value + salt₃ + iterations                              │
 └─────────────────────────────────────────────────────────────────────────┘
```

Stored in the file: salts, IVs, iteration counts, algorithm names, the ciphertexts, and the MAC.

## Opening the file (KeyStore.load(in, password))
```sh
password ──► PKCS#12 KDF(salt₃, purpose 3) ──► K₃ ──► recompute HMAC over AuthenticatedSafe
                                                              │
                                              matches stored MAC?
                                       ┌──────────────┴──────────────┐
                                       ▼ no                          ▼ yes
                         "wrong password or file was          file is intact
                          tampered with" → stop                       │
                                                                       ▼
            password ──► PBKDF2(salt₂) ──► K₂ ──► decrypt ──► certificate(s)
            password ──► PBKDF2(salt₁) ──► K₁ ──► decrypt ──► private key
```

A `.p12` is a binary file, and its bytes use exactly the same encoding as the inside of a PEM file: ASN.1 in DER. A whole family of standards uses it: X.509 certificates, PKCS#8 keys, PKCS#12, and the certificates in TLS. Once you can read DER, you can read all of them.

```sh
PFX  SEQUENCE (1012 bytes)
├── INTEGER 3                                        version
├── ContentInfo  "pkcs7-data"
│   └── OCTET STRING (911 bytes)  ── contains, DER inside DER ──┐
│                                                               ▼
│       AuthenticatedSafe  SEQUENCE                    ◄── the HMAC covers all of this
│       ├── ContentInfo "pkcs7-encryptedData"          [encrypted certificate bag]
│       │   ├── algorithm: PBES2
│       │   │   ├── PBKDF2
│       │   │   │   ├── salt₂       7DC69CF2847274C19A65732826A94B49
│       │   │   │   ├── iterations  0x0800 = 2048
│       │   │   │   └── PRF         hmacWithSHA256
│       │   │   └── aes-256-cbc
│       │   │       └── IV₂         48E96E0BF7B65C0259800323053763AF
│       │   └── [0] ciphertext      432 bytes   ← your certificate, encrypted with K₂
│       │
│       └── ContentInfo "pkcs7-data"                   [plain container …]
│           └── OCTET STRING (310 bytes)
│               └── SafeBag "pkcs8ShroudedKeyBag"      […holding the encrypted private key]
│                   ├── PBES2 / PBKDF2: salt₁, 2048, hmacWithSHA256 / aes-256-cbc: IV₁
│                   └── ciphertext                 ← your private key, encrypted with K₁
│
└── MacData  SEQUENCE                                [integrity]
    ├── DigestInfo
    │   ├── algorithm  sha256
    │   └── MAC        67ADFAB9074736556A9CD284B95BFC5DC24240877C9A…  (32 bytes)
    ├── salt₃          38DA8B3EFB4793F6029C73F1AC5B574C
    └── iterations     0x0800 = 2048
```

RFC 7292 defines MacData the same way for everyone:

```sh
MacData ::= SEQUENCE {
    mac         DigestInfo,     -- { algorithm (e.g. sha256), MAC value }
    macSalt     OCTET STRING,
    iterations  INTEGER DEFAULT 1
}
```
Every tool (OpenSSL, Java, Windows, browsers) writes and reads these same fields, which is why a `.p12` made by one tool opens in another.

```sh
$ keytool -list -keystore multi.p12
Your keystore contains 4 entries
client-rsa,      PrivateKeyEntry      ← RSA key + its certificate
hmac-secret,     SecretKeyEntry       ← a symmetric HMAC key (no certificate)
server-ec,       PrivateKeyEntry      ← EC P-256 key + its certificate
trusted-demo-ca, trustedCertEntry     ← a CA certificate only, no key
```
### How they're stored: bags inside containers
```sh
PFX
└── AuthenticatedSafe = SEQUENCE OF containers
    ├── container 1 (plain "PKCS7 Data")
    │   ├── Shrouded Keybag   ← server-ec private key   (individually encrypted)
    │   ├── Shrouded Keybag   ← client-rsa private key  (individually encrypted)
    │   └── Secret bag        ← hmac-secret             (contains an encrypted key)
    └── container 2 ("PKCS7 Encrypted data")
        ├── Certificate bag   ← CN=server
        ├── Certificate bag   ← CN=client
        └── Certificate bag   ← CN=demo (trusted CA)
└── MacData                   ← one MAC over everything

```

```
# openssl pkcs12 -info 

PKCS7 Data
Shrouded Keybag ...        ← server-ec key
Shrouded Keybag ...        ← client-rsa key
Secret bag                 ← hmac-secret
PKCS7 Encrypted data ...
Certificate bag            ← 1
Certificate bag            ← 2
Certificate bag            ← 3
```

The possible bag types (RFC 7292):

| Bag | Holds | In the demo |
|---|---|---|
| keyBag | an unencrypted PKCS#8 private key | (avoid) |
| pkcs8ShroudedKeyBag | an encrypted private key | server-ec, client-rsa |
| certBag | a certificate | the 3 certificates |
| secretBag | anything else, e.g. a symmetric key | hmac-secret |
| crlBag | a revocation list | |
| safeContentsBag | a nested set of bags | |

How keys are matched with their certificates
Every bag can carry attributes. Two of them link the entries together:

```sh
friendlyName: server-ec                                  ← the alias you use in Java
localKeyID:   54 69 6D 65 20 31 37 39 30 39 30 34 …      ← same value on the key AND its certificate
```
`friendlyName` is the alias: `keyStore.getKey("server-ec", …)`.
`localKeyID` pairs a private key with its certificate. The key bag and certificate bag for server-ec carry the same ID, so a tool can rebuild the pair

`-genkeypair` creates a certificate: a Java PrivateKeyEntry must always hold a private key plus a certificate chain (at least one certificate). A bare key pair isn't allowed.

## The important one: trusted certificates
I made a certificate-only .p12 with OpenSSL, the obvious way to build a truststore:
```sh
$ openssl pkcs12 -export -nokeys -in demo-cert.pem -out certonly.p12
$ keytool -list -keystore certonly.p12
Your keystore contains 0 entries          ← Java ignores the certificate
```
The JDK explains why (PKCS12KeyStore.java:81-84):
```sh
"a localKeyId is required to match the private key with the certificate. Trusted certificate entries are identified by the presence of an trustedKeyUsage attribute."
```
A certificate bag with no matching key and no `trustedKeyUsage` isn't counted as an entry at all


Java's keystore doesn't allow a private key to be stored on its own. Every private key must come with a certificate that carries its public key, a bit like a key that must always be stored with its ID card.

So for each `-genkeypair`, keytool does three things:

```sh
1. generate a key pair          (private key + public key)
2. create a certificate for it  (subject: CN=server, contains the public key)
3. sign that certificate with the same private key   → "self-signed"
```

```sh
box (.p12) ─────────────────────────────── tamper seal (MAC) over the whole box
├── envelope 1: NOT locked (pkcs7-data)
│   ├── 🔒 server-ec key      ← each item locked separately
│   ├── 🔒 client-rsa key
│   └── 🔒 hmac-secret
└── envelope 2: LOCKED (pkcs7-encryptedData)
    ├── certificate CN=server  ← items not locked themselves,
    ├── certificate CN=client     the envelope protects them all
    └── certificate CN=demo
```

```java
// keys: already individually encrypted → plain container
byte[] safeContentData = createSafeContent();              // builds the shrouded key bags
ContentInfo dataContentInfo = new ContentInfo(safeContentData);   // pkcs7-data

// certificates: "Storing N certificate(s) in a PKCS#7 encryptedData"
byte[] certsData = getCertificateData();
if (password != null && !certProtectionAlgorithm.equalsIgnoreCase("NONE")) {
    encrData.writeBytes(encryptContent(certsData, password));     // encrypt the whole cert list
    new ContentInfo(ContentInfo.ENCRYPTED_DATA_OID, ...);          // pkcs7-encryptedData
} else {
    new ContentInfo(certsData);                                    // NONE → plain container
}
```

```java
   // Create Encapsulated ContentInfo
        ContentInfo contentInfo = new ContentInfo(authenticatedSafe);
        contentInfo.encode(authSafe);
        byte[] authSafeData = authSafe.toByteArray();
        pfx.writeBytes(authSafeData);

        // -- MAC
        if (macAlgorithm == null) {
            macAlgorithm = defaultMacAlgorithm();
        }
        if (macIterationCount < 0) {
            macIterationCount = defaultMacIterationCount();
        }
        if (password != null && !macAlgorithm.equalsIgnoreCase("NONE")) {
            byte[] macData = calculateMac(password, authenticatedSafe);
            pfx.write(macData);
        }
```

```sh
demo.p12 bytes
   │
   ▼
① parse PFX                                                   lines 1965-1971
   SEQUENCE → INTEGER version   (must be 3, else "not in version 3 format")
   │
   ▼
② open the outer ContentInfo → authSafeData                  lines 1979-1986
   must be pkcs7-data, else "public key protected PKCS12 not supported"
   authSafeData = the exact bytes the MAC was computed over  ◄──────────────┐
   │                                                                        │
   ▼                                                                        │
③ for each container in the AuthenticatedSafe                              │
   ├── pkcs7-data (keys) ──► loadSafeContents()                             │
   │     key bags are stored STILL ENCRYPTED                                │
   │     (just parsed, with alias = friendlyName, keyId = localKeyID)       │
   │                                                                        │
   └── pkcs7-encryptedData (certificates)                                    │
         if password == null → SKIP it (certificates lost, no error!)        │
         read PBES2 params: salt₂, IV₂, iterations                          │
         iterations > MAX_ITERATION_COUNT? → reject                         │
         password ──PBKDF2(salt₂)──► K₂ ──AES decrypt──► certificate bags    │
         wrong password → "keystore password was incorrect"   (line 2109)   │
   │                                                                        │
   ▼                                                                        │
④ MacData present?                                                          
   ├── no  → macAlgorithm = "NONE", carry on (no integrity check!)          │
   └── yes (and password != null)                                           │
         read MacData: algorithm (sha256), MAC value, salt₃, iterations     │
         iterations > MAX_ITERATION_COUNT? → reject                         │
         password ──PKCS#12 KDF(salt₃, purpose 3)──► K₃                     │
         HMAC-SHA256(K₃, authSafeData) ─────────────────────────────────────┘
         MessageDigest.isEqual(stored MAC, computed MAC)?      (constant time)
         ├── no  → "Integrity check failed"                     (line 2174)
         └── yes → continue
   │
   ▼
⑤ match keys to certificates                                 lines 2184+
   for each key: find the certificate with the same localKeyID,
   then follow issuer links to build the chain (with loop detection)
   │
   ▼
KeyStore loaded: aliases, certificates, encrypted keys in memory
```
### KDF 1: PBKDF2, which makes K₁ and K₂ (the encryption keys)
```java
private static byte[] deriveKey(Mac prf, byte[] password, byte[] salt,
                                int iterCount, int keyLengthInBit) {
    int keyLength = keyLengthInBit / 8;              // 32 bytes for AES-256
    int hlen = prf.getMacLength();                   // 32 for HMAC-SHA256
    int intL = (keyLength + hlen - 1) / hlen;        // how many 32-byte blocks: here 1
    ...
    prf.init(macKey);                                // HMAC KEYED WITH THE PASSWORD

    for (int i = 1; i <= intL; i++) {                // one round per output block
        prf.update(salt);
        prf.update(ibytes);                          // block number i, 4 bytes big-endian
        prf.doFinal(ui, 0);                          // U₁ = HMAC(password, salt || i)
        System.arraycopy(ui, 0, ti, 0, ui.length);   // T = U₁

        for (int j = 2; j <= iterCount; j++) {       // ← the slow part: 2048 times here
            prf.update(ui);
            prf.doFinal(ui, 0);                      // Uⱼ = HMAC(password, Uⱼ₋₁)
            for (int k = 0; k < ui.length; k++) {
                ti[k] ^= ui[k];                      // T = U₁ ⊕ U₂ ⊕ … ⊕ U₂₀₄₈
            }
        }
        System.arraycopy(ti, 0, key, (i-1)*hlen, ...);  // T is (part of) the key
    }
    return key;
}
```
In words: HMAC the salt with the password as the key, then keep HMACing the result, XORing every intermediate value together. Every one of the 2048 rounds affects the final key, so an attacker can't skip any of them.

```sh
salt₂      = 7dc69cf2847274c19a65732826a94b49     (read from the file)
iterations = 2048                                  (read from the file)
K₂ = PBKDF2-HMAC-SHA256("demo", salt₂, 2048, 32)
   = 55611972c554cf7c4517c38d8cc52ac86c9a08dbc4761b03782643121db641c8
```

```
openssl enc -d -aes-256-cbc -K <K₂> -iv <IV₂>  →  certBag / x509Certificate / localKeyID   ✓
```
### KDF 2: the PKCS#12 KDF, which makes K₃ (the MAC key)

```sh
static byte[] derive(char[] chars, byte[] salt, int ic, int n, int type,
                     String hashAlgo, int blockLength) {
    // ① password → UTF-16 big-endian ("BMPString") + 2-byte NUL terminator
    int length = chars.length * 2 + 2;
    for (...) {
        passwd[j]   = (byte) ((chars[i] >>> 8) & 0xFF);
        passwd[j+1] = (byte) (chars[i] & 0xFF);
    }
    MessageDigest sha = MessageDigest.getInstance(hashAlgo);   // SHA-256: plain hash, NOT HMAC
    int v = blockLength;                       // 64: SHA-256's block size
    int u = sha.getDigestLength();             // 32: SHA-256's output size

    // ② the purpose block: 64 copies of the purpose byte
    Arrays.fill(D, (byte) type);               // type = 3 → MAC_KEY

    // ③ salt and password each repeated to fill 64-byte blocks, then joined
    concat(salt,   I, 0, s);
    concat(passwd, I, s, p);

    for (;; i++, n -= u) {
        sha.update(D);
        sha.update(I);
        Ai = sha.digest();                     // A = SHA-256(D || I)
        for (int r = 1; r < ic; r++)
            Ai = sha.digest(Ai);               // ← the slow part: hash it again, 2048 times in total
        System.arraycopy(Ai, 0, key, u * i, Math.min(n, u));
        if (i + 1 == c) break;                 // enough bytes → done

        // ④ need more output: modify I and go round again
        concat(Ai, B, 0, v);  addOne(v, B);    // B = (A repeated to 64 bytes) + 1
        for (int j = 0; j < I.length; j += v)
            addTwo(v, B, I, j);                // add B into every 64-byte block of I
    }
    return key;
}
```

```sh
salt₃      = 38da8b3efb4793f6029c73f1ac5b574c     (from MacData)
K₃ = PKCS12-KDF("demo", salt₃, 2048 iterations, 32 bytes, purpose 3)
HMAC-SHA256(K₃, AuthenticatedSafe) = 67adfab9074736556a9cd284b95bfc5d…
stored MAC in the file             = 67adfab9074736556a9cd284b95bfc5d…   ✓ match

same with password "Demo"           = cb27081b4458560fd707f6327c1da6ff…   ✗ (one capital letter → completely different)
```

```sh
your password: "demo"  ── encoded as UTF-8 bytes (legacy KDF used UTF-16BE BMPString)
                                          │
          ┌───────────────────────────────┼────────────────────────────────┐
          │                               │                                │
          ▼                               ▼                                ▼
 ┌─────────────────────┐        ┌─────────────────────┐        ┌───────────────────────┐
 │ PBKDF2-HMAC-SHA256  │        │ PBKDF2-HMAC-SHA256  │        │ PBKDF2-HMAC-SHA256    │
 │ salt₁ (random)      │        │ salt₂ (random)      │        │ salt₃ (random)        │
 │ N iterations        │        │ N iterations        │        │ N iterations          │
 │ keyLength = 32      │        │ keyLength = 32      │        │ keyLength = 32  ◄─ explicit,
 │                     │        │                     │        │ no purpose byte     required
 └──────────┬──────────┘        └──────────┬──────────┘        └───────────┬───────────┘
            ▼                              ▼                               ▼
     AES-256 key K₁                 AES-256 key K₂                  HMAC key K₃
            │                              │                               │
            ▼                              ▼                               │
 AES-256-CBC(K₁, IV₁)           AES-256-CBC(K₂, IV₂)                       │
 ← private key                  ← certificate(s)                           │
            ▼                              ▼                               │
   Shrouded Keybag               PKCS7 Encrypted data                      │
            └──────────────┬───────────────┘                               │
                           ▼                                               │
                 ┌───────────────────┐                                     │
                 │ AuthenticatedSafe │ ◄── HMAC-SHA256(K₃, all of it) ─────┘
                 └─────────┬─────────┘                    │
                           │                              ▼
                           │                         32-byte MAC
                           ▼                              │
 ┌─────────────────────────────────────────────────────────────────────────┐
 │ demo.p12                                                                │
 │  • AuthenticatedSafe: encrypted key bag + encrypted cert bag            │
 │  • in the clear next to each bag: salt₁/IV₁, salt₂/IV₂, iterations      │
 │  • MacData:                                                             │
 │      digestAlgorithm = id-PBMAC1 (1.2.840.113549.1.5.14)                │
 │        └─ PBMAC1-params                                                 │
 │             ├─ keyDerivationFunc: PBKDF2 { salt₃, N, keyLength 32,      │
 │             │                              prf HMAC-SHA256 }            │
 │             └─ messageAuthScheme: HMAC-SHA256                           │
 │      digest   = the 32-byte MAC                                         │
 │      macSalt  = "NOT USED"   (ignored)                                  │
 │      iterations = 1          (ignored)                                  │
 └─────────────────────────────────────────────────────────────────────────┘
```

```java
    private static byte[] deriveKey(final Mac prf, final byte[] password,
            byte[] salt, int iterCount, int keyLengthInBit) {
        int keyLength = keyLengthInBit/8;
        byte[] key = new byte[keyLength];
        try {
            int hlen = prf.getMacLength();
            int intL = (keyLength + hlen - 1)/hlen; // ceiling
            int intR = keyLength - (intL - 1)*hlen; // residue
            byte[] ui = new byte[hlen];
            byte[] ti = new byte[hlen];
            String algName = prf.getAlgorithm();
            // SecretKeySpec cannot be used, since password can be empty here.
            SecretKey macKey = new SecretKey() {
                @java.io.Serial
                private static final long serialVersionUID = 7874493593505141603L;
                @Override
                public String getAlgorithm() {
                    return algName;
                }
                @Override
                public String getFormat() {
                    return "RAW";
                }
                @Override
                public byte[] getEncoded() {
                    return password.clone();
                }
                @Override
                public int hashCode() {
                    return Arrays.hashCode(password) * 41 +
                      algName.toLowerCase(Locale.ENGLISH).hashCode();
                }
                @Override
                public boolean equals(Object obj) {
                    if (this == obj) return true;
                    if (obj == null || this.getClass() != obj.getClass()) return false;
                    SecretKey sk = (SecretKey)obj;
                    return algName.equalsIgnoreCase(
                        sk.getAlgorithm()) &&
                        MessageDigest.isEqual(password, sk.getEncoded());
                }
                // This derived key can't be deserialized.
                @java.io.Serial
                private void readObject(ObjectInputStream stream)
                        throws IOException, ClassNotFoundException {
                    throw new InvalidObjectException(
                            "PBKDF2KeyImpl SecretKeys are not " +
                            "directly deserializable");
                }
            };

            prf.init(macKey);

            byte[] ibytes = new byte[4];
            for (int i = 1; i <= intL; i++) {
                prf.update(salt);
                ibytes[3] = (byte) i;
                ibytes[2] = (byte) ((i >> 8) & 0xff);
                ibytes[1] = (byte) ((i >> 16) & 0xff);
                ibytes[0] = (byte) ((i >> 24) & 0xff);
                prf.update(ibytes);
                prf.doFinal(ui, 0);
                System.arraycopy(ui, 0, ti, 0, ui.length);

                for (int j = 2; j <= iterCount; j++) {
                    prf.update(ui);
                    prf.doFinal(ui, 0);
                    // XOR the intermediate Ui's together.
                    for (int k = 0; k < ui.length; k++) {
                        ti[k] ^= ui[k];
                    }
                }
                if (i == intL) {
                    System.arraycopy(ti, 0, key, (i-1)*hlen, intR);
                } else {
                    System.arraycopy(ti, 0, key, (i-1)*hlen, hlen);
                }
            }
        } catch (GeneralSecurityException gse) {
            throw new RuntimeException("Error deriving PBKDF2 keys", gse);
        }
        return key;
    }
```

The fundamental difference between PBKDF2 and HKDF comes down to the entropy (randomness) of your starting material and the speed required for the operation.

PBKDF2 assumes you are starting with a weak, human-created password and intentionally slows down the process to protect it. HKDF assumes you are starting with a strong, highly random cryptographic secret (like a Diffie-Hellman key exchange) and just needs to mold it into the right shape as fast as possible.

```sh
U₁ = HMAC(password, salt || blockIndex)
U₂ = HMAC(password, U₁)
...
U_N = HMAC(password, U_{N-1})
block = U₁ ⊕ U₂ ⊕ ... ⊕ U_N
```
- The password is the HMAC key and stays the same key for all N rounds.
- The iteration count N is the cost. Each block of output needs N HMAC calls, so the cost scales with N.
- If you need more bytes than one HMAC output (more than 32 for SHA-256), it computes more blocks, each with N calls.
### HKDF

```sh
Extract: PRK = HMAC(salt, IKM)                      -- 1 call, salt is the key
Expand:  T(1) = HMAC(PRK, info || 0x01)
         T(2) = HMAC(PRK, T(1) || info || 0x02)
         ...
         OKM  = T(1) || T(2) || ...                 -- 1 call per output block

```         
- The secret is the input to Extract. Expand then uses the extracted PRK as the HMAC key.
- There is no iteration count. Total work is about 1 call plus one per output block, so it is cheap on purpose.


#### Web and tokens
- JOSE / JWE: ECDH-ES key agreement uses Concat KDF (NIST SP 800-56A), not HKDF. Some newer specs, such as HPKE-based JOSE, use HKDF.
- OAuth / DPoP and similar: mostly not HKDF.
- WebAuthn / FIDO2: the hmac-secret extension and CTAP2 PIN protocol use HKDF with SHA-256.

#### Cryptographic building blocks
- Key hierarchies and key wrapping: cloud KMS or envelope encryption designs often use HKDF to derive per-object keys from a master key.
- Post-quantum hybrid schemes: hybrid key exchanges such as X25519+ML-KEM feed both shared secrets into HKDF to produce one key.

WebAuthn / FIDO2 (hmac-secret Extension): Uses HKDF to process raw secrets returned from a hardware security key (YubiKey) to derive symmetric encryption keys used by operating systems for offline disk encryption

## HSM
he private key becomes bytes in your server's memory.

- A PEM file: you read it, and the key bytes are in memory.
- A .p12: getKey() runs PBKDF2, decrypts, and the key bytes are in memory (that's `PKCS8EncodedKeySpec` at line 390).
Even an encrypted key has to be decrypted before it can be used.
So if an attacker gets into that server (a vulnerability, a stolen backup, a memory dump, a malicious insider), they can copy the key. With a copy they can impersonate your bank or authorization server forever, from anywhere, and you'd never know, because nothing about a copied key looks different.

An HSM (Hardware Security Module) is a dedicated, tamper-resistant computer whose job is to hold keys and use them internally. You never receive the key. Instead you send it work, and it sends back the result.

```sh
        your server (application)                     HSM (tamper-resistant box)
 ┌──────────────────────────────────┐          ┌─────────────────────────────────────┐
 │                                  │  ① "create an EC P-256 key"                   │
 │                                  │ ───────────────────────────►  generates key    │
 │                                  │  ◄─────── handle #42 + PUBLIC key    🔑 #42    │
 │                                  │                                (stays here)    │
 │  needs a signature over          │  ② "sign these bytes with #42"                │
 │  the TLS transcript / a JWT      │ ───────────────────────────►  signs inside     │
 │                                  │  ◄─────────────── signature                    │
 │                                  │                                                │
 │  "give me key #42's bytes"       │ ─────────────────────────►   ✗ REFUSED         │
 └──────────────────────────────────┘          └─────────────────────────────────────┘
```

What your server holds is only a handle: an ID number pointing to the key inside the HSM

Java talks to HSMs through the SunPKCS11 provider. PKCS#11 is the standard API that almost all HSMs implement.


```java
your code            Signature.getInstance("SHA256withECDSA", p11Provider)
                     sig.initSign(privateKey);  sig.update(data);  sig.sign()
   │
   ▼  JCA: the same API as for normal keys
P11Signature.java    token.p11.C_SignInit(session, mechanism, keyID)       ← keyID = the handle, not the key
(SunPKCS11, Java)    token.p11.C_Sign(session, digest)
```