package research;

import java.io.PrintWriter;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe79_t04_concat_method
 * CWE-79 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe79T04ConcatMethod {
    public void writeComment(PrintWriter out, String comment) {
        out.println("<div class=\"comment\">".concat(comment).concat("</div>"));
    }
}
