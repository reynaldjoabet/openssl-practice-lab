import java.security.{MessageDigest, SecureRandom}
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec 


var number = 20

number << 1

(255<<1)

(255<<1).toByte

0x4000_0000 << 1   
// 2^30 → -2^31 (the bit moves into the sign bit, so it goes negative)
Integer.MAX_VALUE << 1   // → -2

Integer.parseInt("11111110", 2) 


// pad to a fixed width so the shift is easy to see
def bin(x: Int, width: Int = 32): String =
  String.format(s"%${width}s", x.toBinaryString).replace(' ', '0')
    .grouped(8).mkString(" ")


bin(255)

bin(255<<1)

bin(-2)

bin(0x40000000 << 1)




object PasswordHash {

  private val Algorithm  = "PBKDF2WithHmacSHA256"
  private val Iterations = 600_000 // OWASP recommendation for PBKDF2-HMAC-SHA256
  private val SaltBytes  = 16
  private val KeyBits    = 256
  private val random     = SecureRandom()
  private val b64        = Base64.getEncoder.withoutPadding
  private val b64d       = Base64.getDecoder

  private def pbkdf2(password: Array[Char], salt: Array[Byte], iterations: Int, keyBits: Int): Array[Byte] = {
    val spec = PBEKeySpec(password, salt, iterations, keyBits)
    try SecretKeyFactory.getInstance(Algorithm).generateSecret(spec).getEncoded
    finally spec.clearPassword() // wipe the spec's internal copy of the password
  }

  /** Returns a self-describing string: pbkdf2-sha256$<iterations>$<salt>$<hash>. */
  def hash(password: Array[Char]): String = {
    val salt = new Array[Byte](SaltBytes)
    random.nextBytes(salt) // unique per user: stops one table cracking every account
    val dk = pbkdf2(password, salt, Iterations, KeyBits)
    s"pbkdf2-sha256$$$Iterations$$${b64.encodeToString(salt)}$$${b64.encodeToString(dk)}"
  }

}

val hash= PasswordHash.hash("mypassword".toCharArray())