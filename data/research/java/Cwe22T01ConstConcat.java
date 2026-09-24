package research;

import java.io.File;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe22_t01_const_concat
 * CWE-22 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe22T01ConstConcat {
    public File openReadme(String baseDir) {
        return new File(baseDir + "/" + "readme.txt");
    }
}
