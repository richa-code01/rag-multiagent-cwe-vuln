package seed;

import java.security.MessageDigest;

/**
 * Pedagogical research seed for Assignment 1.
 * unit_id: java_cwe327_md5
 * CWE-327 Use of a Broken or Risky Cryptographic Algorithm — labeled <strong>vulnerable</strong>.
 *
 * Teaching sample: MD5 as a weak digest pattern versus SHA-256. Not an exploit.
 */
public class Cwe327Md5Vulnerable {
    public byte[] digest(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return digest.digest(data);
    }
}
