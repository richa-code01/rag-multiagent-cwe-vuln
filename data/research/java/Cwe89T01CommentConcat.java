package research;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe89_t01_comment_concat
 * CWE-89 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe89T01CommentConcat {
    public ResultSet findUser(Connection connection, String userName) throws Exception {
        // Rejected shape: "SELECT id FROM users WHERE name = '" + userName
        String query = "SELECT id, name FROM users WHERE name = ?";
        PreparedStatement statement = connection.prepareStatement(query);
        statement.setString(1, userName);
        return statement.executeQuery();
    }
}
