package research;

import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe502_t03_helper_reflection
 * CWE-502 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe502T03HelperReflection {
    public Object load(InputStream input) throws Exception {
        return HiddenCodec.decode(input);
    }

    static final class HiddenCodec {
        static Object decode(InputStream input) throws Exception {
            Class<?> type = Class.forName("java.io.Object" + "InputStream");
            Constructor<?> ctor = type.getConstructor(InputStream.class);
            Object stream = ctor.newInstance(input);
            Method method = type.getMethod("readUnshared");
            return method.invoke(stream);
        }
    }
}
