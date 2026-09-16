package seed;

import java.security.MessageDigest;

/**
 * Pedagogical research seed for Assignment 1.
 * unit_id: java_cwe327_sha256
 * CWE-327 — labeled <strong>not_vulnerable</strong> (SHA-256).
 *
 * Teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe327Sha256Safe {
    public byte[] digest(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }
}
