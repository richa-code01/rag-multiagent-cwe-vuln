package research;

import java.io.PrintWriter;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe79_t02_constant_html
 * CWE-79 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe79T02ConstantHtml {
    private static final String LABEL = "ok";

    public void writeStatus(PrintWriter out) {
        out.println("<div class=\"status\">" + LABEL + "</div>");
    }
}
