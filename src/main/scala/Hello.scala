import jdk.security
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.CipherSpi
import javax.crypto.DecapsulateException
import javax.crypto.EncryptedPrivateKeyInfo
import javax.crypto.ExemptionMechanism
import javax.crypto.ExemptionMechanismException
import javax.crypto.ExemptionMechanismSpi
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KEM
import javax.crypto.KEMSpi
import javax.crypto.KeyAgreement
import javax.crypto.KeyAgreementSpi
import javax.crypto.KeyGenerator
import javax.crypto.KeyGeneratorSpi
import javax.crypto.Mac
import javax.crypto.MacSpi
import javax.crypto.NoSuchPaddingException
import javax.crypto.NullCipher
import javax.crypto.SealedObject
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.SecretKeyFactorySpi
import javax.crypto.ShortBufferException
import javax.crypto.interfaces
import javax.crypto.interfaces.DHKey
import javax.crypto.interfaces.DHPrivateKey
import javax.crypto.interfaces.DHPublicKey
import javax.crypto.interfaces.PBEKey
import javax.crypto.spec

import javax.crypto.spec.ChaCha20ParameterSpec
import javax.crypto.spec.DESKeySpec
import javax.crypto.spec.DESedeKeySpec
import javax.crypto.spec.DHGenParameterSpec
import javax.crypto.spec.DHParameterSpec
import javax.crypto.spec.DHPrivateKeySpec
import javax.crypto.spec.DHPublicKeySpec
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.HKDFParameterSpec
import javax.crypto.spec.HKDFParameterSpec
import javax.crypto.spec.HKDFParameterSpec
import javax.crypto.spec.HKDFParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.PBEParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.RC2ParameterSpec
import javax.crypto.spec.RC5ParameterSpec
import javax.crypto.spec.SecretKeySpec

import javax.security.cert.CertificateEncodingException
import javax.security.cert.CertificateException
import javax.security.cert.CertificateNotYetValidException
import javax.security.cert.X509Certificate
import javax.security.cert.Certificate
import javax.security.cert.CertificateParsingException

import sun.security.ec

import sun.security.jca

import sun.security.jgss

import sun.security.krb5

import sun.security.pkcs

import sun.security.pkcs10

import sun.security.pkcs11

import sun.security.provider

import sun.security.rsa

import sun.security.smartcardio

import sun.security.ssl

import sun.security.x509

import javax.crypto.KDF
import javax.crypto.KDF.getInstance
import java.security.spec.AlgorithmParameterSpec

import org.conscrypt.ConcatenationKdfSpec

object Hello extends Greeting with App {
  println(greeting)

  val x = javax.crypto.KDF.getInstance("HKDF-SHA256")
}

trait Greeting {
  lazy val greeting: String = "hello"
  val salt: Array[Byte] = Array.emptyByteArray
  val ikm = "input keying material"

  val info: Array[Byte] = Array.emptyByteArray
  val kdfHkdf = KDF.getInstance("HKDF-SHA256");
  val derivationSpec: AlgorithmParameterSpec =
    HKDFParameterSpec
      .ofExtract()
      .addIKM(ikm.getBytes())
      .addSalt(salt)
      .thenExpand(info, 32)
  val sKey = kdfHkdf.deriveKey("AES", derivationSpec)

  val label = Array.emptyByteArray
  val derivationSpec2 = HKDFParameterSpec
    .ofExtract()
    .addIKM(label)
    .addIKM(ikm.getBytes())
    .addSalt(salt)
    .extractOnly()

}
