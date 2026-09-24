package securibench.micro.basic;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
/**
 *  @servlet description="very simple XSS"
 *  @servlet vuln_count = "1"
 */
public class BasicTinyXss {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        PrintWriter writer = resp.getWriter();
        writer.println(req.getParameter("name")); /* BAD */
    }
    public int getVulnerabilityCount() {
        return 1;
    }
}
