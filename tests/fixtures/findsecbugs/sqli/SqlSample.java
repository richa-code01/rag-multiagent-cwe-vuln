package testcode.sqli;
public class SqlSample {
    public void query(String username) {
        String sql = "select * from users where name = '" + username + "'";
    }
}
