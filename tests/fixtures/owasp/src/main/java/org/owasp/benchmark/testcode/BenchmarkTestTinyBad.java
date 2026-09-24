package org.owasp.benchmark.testcode;
public class BenchmarkTestTinyBad {
    public void service(String id) {
        String sql = "SELECT * FROM users WHERE id = '" + id + "'";
    }
}
