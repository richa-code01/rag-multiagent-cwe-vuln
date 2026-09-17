package research;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe798_t04_split_literal
 * CWE-798 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe798T04SplitLiteral {
    public String connect() {
        String credential = "teach" + "-token";
        return credential;
    }
}
