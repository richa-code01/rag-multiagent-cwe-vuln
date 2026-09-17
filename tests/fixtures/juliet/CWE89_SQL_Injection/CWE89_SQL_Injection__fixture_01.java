/* TEMPLATE GENERATED TESTCASE FILE (fixture, not from NIST) */
package testcases.CWE89_SQL_Injection;
import java.sql.Statement;

public class CWE89_SQL_Injection__fixture_01
{
    public void bad() throws Throwable
    {
        String data = "id";
        Statement statement = null;
        statement.execute("SELECT * FROM users WHERE id='" + data + "'");
    }

    private void goodG2B() throws Throwable
    {
        String data = "hardcoded";
        Statement statement = null;
        statement.execute("SELECT * FROM users WHERE id='" + data + "'");
    }

    private void goodB2G() throws Throwable
    {
        String data = "id";
        Statement statement = null;
        statement.executeQuery("SELECT * FROM users WHERE id=?");
    }

    public void good() throws Throwable
    {
        goodG2B();
        goodB2G();
    }
}
