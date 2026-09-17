/* filename-level bad sink fixture */
package testcases.CWE89_SQL_Injection;

public class CWE89_SQL_Injection__fixture_81_bad
{
    public void action(String data) throws Throwable
    {
        String sql = "SELECT * FROM users WHERE id='" + data + "'";
    }
}
