package research;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe502_t02_roundtrip
 * CWE-502 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe502T02Roundtrip {
    public String echoLabel() throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (ObjectOutputStream output = new ObjectOutputStream(buffer)) {
            output.writeObject("teaching-label");
        }
        try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(buffer.toByteArray()))) {
            return (String) input.readObject();
        }
    }
}
