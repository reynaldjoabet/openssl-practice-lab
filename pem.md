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