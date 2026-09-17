package research;

import java.io.InputStream;
import java.lang.reflect.Method;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe502_t04_xmldecoder_reflect
 * CWE-502 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe502T04XmlDecoderReflect {
    public Object load(InputStream input) throws Exception {
        Class<?> type = Class.forName("java.beans.XMLDecoder");
        Object decoder = type.getConstructor(InputStream.class).newInstance(input);
        Method method = type.getMethod("read" + "Object");
        return method.invoke(decoder);
    }
}
