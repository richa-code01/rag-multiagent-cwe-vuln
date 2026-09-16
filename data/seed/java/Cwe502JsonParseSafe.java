package seed;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Pedagogical research seed for Assignment 1.
 * unit_id: java_cwe502_json_parse
 * CWE-502 — labeled <strong>not_vulnerable</strong> (plain-text line; no Java deserialization).
 *
 * Teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe502JsonParseSafe {
    public String loadName(InputStream input) throws Exception {
        BufferedReader reader =
                new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
        return reader.readLine();
    }
}
