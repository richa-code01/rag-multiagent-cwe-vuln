package research;

import java.io.PrintWriter;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe79_t03_getparameter
 * CWE-79 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe79T03GetParameter {
    public void writeName(PrintWriter out, HttpRequest request) {
        out.print("text/html name=");
        out.print(request.getParameter("name"));
    }

    public interface HttpRequest {
        String getParameter(String name);
    }
}
