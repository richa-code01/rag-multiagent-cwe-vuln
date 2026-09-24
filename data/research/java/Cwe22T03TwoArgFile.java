package research;

import java.io.File;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe22_t03_twoarg_file
 * CWE-22 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe22T03TwoArgFile {
    public File openUserFile(String baseDir, String relativePath) {
        return new File(baseDir, relativePath);
    }
}
