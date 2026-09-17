package research;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe89_t03_stringbuilder
 * CWE-89 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe89T03StringBuilder {
    public ResultSet findUser(Connection connection, String userName) throws Exception {
        Statement statement = connection.createStatement();
        StringBuilder query = new StringBuilder("SELECT id, name FROM users WHERE name = '");
        query.append(userName);
        query.append("'");
        return statement.executeQuery(query.toString());
    }
}
