package research;

import java.security.MessageDigest;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe327_t03_md5_variable
 * CWE-327 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe327T03Md5Variable {
    public byte[] digest(byte[] data) throws Exception {
        String algorithm = "MD5";
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        return digest.digest(data);
    }
}
