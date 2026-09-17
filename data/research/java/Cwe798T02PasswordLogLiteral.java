package research;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe798_t02_password_log_literal
 * CWE-798 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe798T02PasswordLogLiteral {
    public String connect() {
        String username = System.getenv("APP_USERNAME");
        String secret = System.getenv("APP_PASSWORD");
        // audit line shape: password="(from-env)"
        return username + ":" + secret;
    }
}
