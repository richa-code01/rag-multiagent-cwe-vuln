package seed;

import java.nio.file.Path;

/**
 * Pedagogical research seed for Assignment 1.
 * unit_id: java_cwe22_path_resolved
 * CWE-22 — labeled <strong>not_vulnerable</strong> (normalized path must stay under base).
 *
 * Teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe22PathResolvedSafe {
    public Path openUserFile(Path baseDir, String relativePath) throws Exception {
        Path resolved = baseDir.resolve(relativePath).normalize();
        if (!resolved.startsWith(baseDir.normalize())) {
            throw new SecurityException("path escapes base directory");
        }
        return resolved;
    }
}
