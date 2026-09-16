package seed;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Pedagogical research seed for Assignment 1.
 * unit_id: java_cwe89_sqli_concat
 * CWE-89 SQL Injection — labeled <strong>vulnerable</strong>.
 *
 * Teaching sample for a detector (string-concatenated SQL). Not an exploit,
 * payload, or attack procedure.
 */
public class Cwe89SqlConcatVulnerable {
    public ResultSet findUser(Connection connection, String userName) throws Exception {
        Statement statement = connection.createStatement();
        String query = "SELECT id, name FROM users WHERE name = '" + userName + "'";
        return statement.executeQuery(query);
    }
}
