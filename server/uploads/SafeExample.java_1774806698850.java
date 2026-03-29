/**
 * Test Case: Safe Code Examples
 * 
 * This file contains properly secured code that should NOT trigger
 * SQL injection warnings. All SQL queries use PreparedStatement
 * with proper parameter binding.
 */

import java.sql.*;
import javax.servlet.http.*;

public class SafeExample {
    
    /**
     * SAFE: PreparedStatement with parameter binding
     */
    public void safeLogin(HttpServletRequest request) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        // Query structure is fixed - parameters are bound separately
        PreparedStatement ps = conn.prepareStatement(
            "SELECT * FROM users WHERE username = ? AND password = ?"
        );
        
        ps.setString(1, username);
        ps.setString(2, password);
        
        ResultSet rs = ps.executeQuery();
        
        if (rs.next()) {
            System.out.println("Login successful");
        }
    }
    
    /**
     * SAFE: Multiple parameters with PreparedStatement
     */
    public void safeSearch(HttpServletRequest request) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        
        String searchTerm = request.getParameter("search");
        String category = request.getParameter("category");
        
        PreparedStatement ps = conn.prepareStatement(
            "SELECT * FROM products WHERE name LIKE ? AND category = ?"
        );
        
        ps.setString(1, "%" + searchTerm + "%");
        ps.setString(2, category);
        
        ResultSet rs = ps.executeQuery();
    }
    
    /**
     * SAFE: Update with PreparedStatement
     */
    public void safeUpdate(HttpServletRequest request) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        
        String newEmail = request.getParameter("email");
        String userId = request.getParameter("id");
        
        PreparedStatement ps = conn.prepareStatement(
            "UPDATE users SET email = ? WHERE id = ?"
        );
        
        ps.setString(1, newEmail);
        ps.setString(2, userId);
        
        ps.executeUpdate();
    }
    
    /**
     * SAFE: No user input involved
     */
    public void safeListing() throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        
        // No user input - completely static query
        String query = "SELECT * FROM products ORDER BY created_date DESC";
        
        ResultSet rs = stmt.executeQuery(query);
    }
    
    /**
     * SAFE: User input not used in SQL
     */
    public void safeLogging(HttpServletRequest request) {
        String userName = request.getParameter("user");
        
        // User input used only for logging, not in SQL
        System.out.println("User logged in: " + userName);
        
        // Separate, safe SQL query
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
            PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO audit_log (action, timestamp) VALUES (?, NOW())"
            );
            ps.setString(1, "login");
            ps.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}