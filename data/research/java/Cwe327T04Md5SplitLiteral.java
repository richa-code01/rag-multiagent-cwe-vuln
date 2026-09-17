package research;

import java.security.MessageDigest;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe327_t04_md5_split_literal
 * CWE-327 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe327T04Md5SplitLiteral {
    public byte[] digest(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD" + "5");
        return digest.digest(data);
    }
}
