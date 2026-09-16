package seed;

import java.io.InputStream;
import java.io.ObjectInputStream;

/**
 * Pedagogical research seed for Assignment 1.
 * unit_id: java_cwe502_readobject
 * CWE-502 Deserialization of Untrusted Data — labeled <strong>vulnerable</strong>.
 *
 * Teaching sample: Java object deserialization API on an input stream.
 * Tiny and non-weaponized; not a gadget chain or exploit.
 */
public class Cwe502ReadObjectVulnerable {
    public Object load(InputStream input) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(input);
        return stream.readObject();
    }
}
