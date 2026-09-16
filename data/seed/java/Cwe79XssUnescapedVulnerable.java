package seed;

import java.io.PrintWriter;

/**
 * Pedagogical research seed for Assignment 1.
 * unit_id: java_cwe79_xss_unescaped
 * CWE-79 Cross-site Scripting — labeled <strong>vulnerable</strong>.
 *
 * Teaching sample: HTML markup concatenated with unsanitized text.
 * Not an exploit payload or attack procedure.
 */
public class Cwe79XssUnescapedVulnerable {
    public void writeComment(PrintWriter out, String comment) {
        out.println("<div class=\"comment\">" + comment + "</div>");
    }
}
