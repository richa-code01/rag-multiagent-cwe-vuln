package research;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe89_t04_split_concat
 * CWE-89 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe89T04SplitConcat {
    public ResultSet findUser(Connection connection, String userName) throws Exception {
        Statement statement = connection.createStatement();
        String prefix = "SELECT id, name FROM users WHERE name = '";
        String query = prefix + userName + "'";
        return statement.executeQuery(query);
    }
}
