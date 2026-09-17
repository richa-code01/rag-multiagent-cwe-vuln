package research;

import java.security.MessageDigest;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe327_t02_banned_algo_message
 * CWE-327 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe327T02BannedAlgoMessage {
    public byte[] digest(byte[] data) throws Exception {
        /* Policy: MessageDigest.getInstance("MD5") is rejected. */
        return MessageDigest.getInstance("SHA-256").digest(data);
    }
}
