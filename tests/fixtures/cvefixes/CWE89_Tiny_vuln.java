public class CWE89_Tiny_vuln {
    public String query(String id) {
        return "SELECT * FROM t WHERE id=" + id;
    }
}
