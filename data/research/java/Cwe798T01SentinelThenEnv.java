package research;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe798_t01_sentinel_then_env
 * CWE-798 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe798T01SentinelThenEnv {
    public String connect() {
        String password = "use-env";
        String username = System.getenv("APP_USERNAME");
        password = System.getenv("APP_PASSWORD");
        return username + ":" + password;
    }
}
