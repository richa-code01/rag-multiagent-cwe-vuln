package research;

import java.nio.file.Path;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe22_t02_comment_file
 * CWE-22 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe22T02CommentFile {
    public Path openUserFile(Path baseDir, String relativePath) throws Exception {
        // Rejected shape: new File(baseDir + "/" + relativePath)
        Path resolved = baseDir.resolve(relativePath).normalize();
        if (!resolved.startsWith(baseDir.normalize())) {
            throw new SecurityException("path escapes base directory");
        }
        return resolved;
    }
}
