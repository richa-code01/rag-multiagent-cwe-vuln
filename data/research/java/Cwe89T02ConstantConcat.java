package research;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Pedagogical research unit.
 * unit_id: java_cwe89_t02_constant_concat
 * CWE-89 teaching sample for a detector. Not an exploit or attack procedure.
 */
public class Cwe89T02ConstantConcat {
    private static final String CATEGORY = "books";

    public ResultSet listCatalog(Connection connection) throws Exception {
        Statement statement = connection.createStatement();
        String query = "SELECT id, title FROM catalog WHERE category = '" + CATEGORY + "'";
        return statement.executeQuery(query);
    }
}
