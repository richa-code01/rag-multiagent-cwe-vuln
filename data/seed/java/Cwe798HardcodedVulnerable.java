package seed;

/**
 * Pedagogical research seed for Assignment 1.
 * unit_id: java_cwe798_hardcoded
 * CWE-798 Use of Hard-coded Credentials — labeled <strong>vulnerable</strong>.
 *
 * Credentials below are fake teaching values ({@code admin} / {@code password}),
 * not secrets for a real system.
 */
public class Cwe798HardcodedVulnerable {
    public String connect() {
        String username = "admin";
        String password = "password";
        return username + ":" + password;
    }
}
