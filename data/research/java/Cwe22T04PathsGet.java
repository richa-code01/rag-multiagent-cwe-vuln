package research;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe22_t04_paths_get
 * CWE-22 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe22T04PathsGet {
    public Path openUserFile(String baseDir, String relativePath) {
        return Paths.get(baseDir, relativePath);
    }
}
