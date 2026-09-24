/* TEMPLATE GENERATED TESTCASE FILE (fixture, not from NIST) */
package testcases.CWE89_SQL_Injection;
import java.sql.Statement;

public class CWE89_SQL_Injection__connect_tcp_68a
{
    public void bad() throws Throwable
    {
        String data = "id";
        CWE89_SQL_Injection__connect_tcp_68b.helper(data);
    }

    private void goodG2B() throws Throwable
    {
        String data = "hardcoded";
        CWE89_SQL_Injection__connect_tcp_68b.helper(data);
    }

    public void good() throws Throwable
    {
        goodG2B();
    }
}
