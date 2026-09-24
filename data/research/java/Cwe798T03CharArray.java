package research;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe798_t03_char_array
 * CWE-798 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe798T03CharArray {
    public String connect() {
        char[] password = {'t', 'e', 'a', 'c', 'h', '1'};
        return new String(password);
    }
}
