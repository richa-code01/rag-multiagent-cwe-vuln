package research;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe502_t01_javadoc_objectstream
 * CWE-502 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe502T01JavadocObjectStream {
    /**
     * This loader does not construct ObjectInputStream or call readObject.
     */
    public String loadName(InputStream input) throws Exception {
        BufferedReader reader =
                new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
        return reader.readLine();
    }
}
