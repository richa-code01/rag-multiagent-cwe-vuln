package org.owasp.benchmark.testcode;
public class BenchmarkTestTinyGood {
    public void service(String id) {
        String sql = "SELECT * FROM users WHERE id = ?";
    }
}
