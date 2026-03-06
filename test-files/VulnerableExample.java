/**
 * Test Case: Vulnerable Code Example
 * 
 * This file contains intentionally vulnerable code to demonstrate
 * SQL injection vulnerabilities that should be detected by the compiler.
 */

import java.sql.*;
import javax.servlet.http.*;
import java.util.Scanner;

public class VulnerableExample {
    
    /**
     * VULNERABILITY 1: Direct user input in SQL query
     * User input from HTTP request is directly concatenated into SQL query
     */
    public void loginUser(HttpServletRequest request) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement statement = conn.createStatement();
        
        // TAINTED: getParameter returns user-controlled input
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        // VULNERABLE: String concatenation with tainted data
        String query = "SELECT * FROM users WHERE username = '" + username + 
                      "' AND password = '" + password + "'";
        
        // SINK: Tainted query executed here - SQL INJECTION!
        ResultSet rs = statement.executeQuery(query);
        
        if (rs.next()) {
            System.out.println("Login successful");
        }
    }
    
    /**
     * VULNERABILITY 2: Taint propagation through multiple variables
     */
    public void searchProducts(HttpServletRequest request) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        
        // TAINTED source
        String searchTerm = request.getParameter("search");
        
        // TAINT propagates to queryPart
        String queryPart = " WHERE name LIKE '%" + searchTerm + "%'";
        
        // TAINT propagates to fullQuery
        String fullQuery = "SELECT * FROM products" + queryPart;
        
        // SINK: SQL Injection via taint propagation
        stmt.executeQuery(fullQuery);
    }
    
    /**
     * VULNERABILITY 3: Scanner input (console-based)
     */
    public void deleteRecord() throws SQLException {
        Scanner scanner = new Scanner(System.in);
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        
        System.out.print("Enter user ID to delete: ");
        
        // TAINTED: nextLine returns user input
        String userId = scanner.nextLine();
        
        // VULNERABLE: Direct concatenation
        String deleteQuery = "DELETE FROM users WHERE id = " + userId;
        
        Statement stmt = conn.createStatement();
        
        // SINK: SQL Injection
        stmt.executeUpdate(deleteQuery);
    }
    
    /**
     * VULNERABILITY 4: Multiple concatenations
     */
    public void complexQuery(HttpServletRequest request) throws SQLException {
        String userRole = request.getParameter("role");
        String department = request.getParameter("dept");
        
        String sql = "SELECT * FROM employees WHERE role = '" + userRole + "'";
        sql = sql + " AND department = '" + department + "'";
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        
        stmt.executeQuery(sql);
    }
    
    /**
     * SAFE EXAMPLE: Using PreparedStatement (should NOT be flagged)
     * 
     * This is the correct way to handle user input in SQL queries.
     * The compiler should NOT report this as a vulnerability.
     */
    public void safeLogin(HttpServletRequest request) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        // SAFE: Query structure is fixed, parameters are bound separately
        PreparedStatement ps = conn.prepareStatement(
            "SELECT * FROM users WHERE username = ? AND password = ?"
        );
        
        // Parameter binding prevents SQL injection
        ps.setString(1, username);
        ps.setString(2, password);
        
        // This should NOT be flagged as vulnerable
        ResultSet rs = ps.executeQuery();
        
        if (rs.next()) {
            System.out.println("Safe login successful");
        }
    }
}