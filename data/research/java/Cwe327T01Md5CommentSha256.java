package research;

import java.security.MessageDigest;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe327_t01_md5_comment_sha256
 * CWE-327 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe327T01Md5CommentSha256 {
    public byte[] digest(byte[] data) throws Exception {
        // Do not call MessageDigest.getInstance("MD5")
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }
}
