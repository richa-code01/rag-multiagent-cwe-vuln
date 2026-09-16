package seed;

import java.io.PrintWriter;

/**
 * Pedagogical research seed for Assignment 1.
 * unit_id: java_cwe79_xss_encoded
 * CWE-79 — labeled <strong>not_vulnerable</strong> (HTML-encoded output).
 *
 * Teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe79XssEncodedSafe {
    public void writeComment(PrintWriter out, String comment) {
        out.println("<div class=\"comment\">" + htmlEncode(comment) + "</div>");
    }

    static String htmlEncode(String value) {
        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
