package seed;

/**
 * Pedagogical research seed for Assignment 1.
 * unit_id: java_cwe798_env_config
 * CWE-798 — labeled <strong>not_vulnerable</strong> (credentials from the environment).
 *
 * Teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe798EnvConfigSafe {
    public String connect() {
        String username = System.getenv("APP_USERNAME");
        String password = System.getenv("APP_PASSWORD");
        return username + ":" + password;
    }
}
