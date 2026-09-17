package research;

import java.io.PrintWriter;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe79_t01_encoded_then_concat
 * CWE-79 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe79T01EncodedThenConcat {
    public void writeComment(PrintWriter out, String comment) {
        String safe = htmlEncode(comment);
        out.println("<div class=\"comment\">" + safe + "</div>");
    }

    static String htmlEncode(String value) {
        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
