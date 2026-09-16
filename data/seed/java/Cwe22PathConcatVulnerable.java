package seed;

import java.io.File;

/**
 * Pedagogical research seed for Assignment 1.
 * unit_id: java_cwe22_path_concat
 * CWE-22 Path Traversal — labeled <strong>vulnerable</strong>.
 *
 * Teaching sample: path segments concatenated into java.io.File with no
 * sandbox check. Not an exploit or attack procedure.
 */
public class Cwe22PathConcatVulnerable {
    public File openUserFile(String baseDir, String relativePath) {
        return new File(baseDir + "/" + relativePath);
    }
}
