package seed;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

/**
 * Pedagogical research seed for Assignment 1.
 * unit_id: java_cwe89_sqli_prepared
 * CWE-89 — labeled <strong>not_vulnerable</strong> (parameterized query).
 *
 * Teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe89SqlPreparedSafe {
    public ResultSet findUser(Connection connection, String userName) throws Exception {
        String query = "SELECT id, name FROM users WHERE name = ?";
        PreparedStatement statement = connection.prepareStatement(query);
        statement.setString(1, userName);
        return statement.executeQuery();
    }
}
