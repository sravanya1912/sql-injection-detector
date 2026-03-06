# Quick Start Guide

## 🚀 Get Running in 5 Minutes

### Prerequisites Check

```bash
# Check Java version (need 8+)
java -version

# Check Maven version (need 3.6+)
mvn -version
```

### Setup Steps

#### 1. Create Project Directory

```bash
mkdir sql-injection-detector
cd sql-injection-detector
```

#### 2. Create Directory Structure

```bash
mkdir -p src/main/java
mkdir -p test-files
```

#### 3. Add Files

Place these files in the project:

```
sql-injection-detector/
├── pom.xml                                 (provided)
├── src/main/java/SQLInjectionDetectorMain.java  (provided)
└── test-files/
    ├── VulnerableExample.java             (provided)
    └── SafeExample.java                   (provided)
```

#### 4. Build

```bash
mvn clean package
```

#### 5. Run

```bash
# Test with vulnerable code
java -jar target/sql-injection-detector-1.0.0-jar-with-dependencies.jar \
    test-files/VulnerableExample.java

# Test with safe code
java -jar target/sql-injection-detector-1.0.0-jar-with-dependencies.jar \
    test-files/SafeExample.java
```

## 📊 Expected Results

### VulnerableExample.java

- ❌ Should detect **4 vulnerabilities**
- Methods: `loginUser()`, `searchProducts()`, `deleteRecord()`, `complexQuery()`
- ✅ `safeLogin()` should NOT be flagged

### SafeExample.java

- ✅ Should detect **0 vulnerabilities**
- All methods use PreparedStatement correctly

## 🎯 Understanding the Output

### Vulnerable Code Detection

```
╔══════════════════════════════════════════════════════════════╗
║              ⚠️  VULNERABILITIES DETECTED  ⚠️                 ║
╚══════════════════════════════════════════════════════════════╝

Total vulnerabilities found: 4

┌─────────────────────────────────────────────────────────────┐
│ Vulnerability #1                                            │
└─────────────────────────────────────────────────────────────┘

[SEVERITY]  HIGH - SQL Injection
[FILE]      test-files/VulnerableExample.java
[LINE]      26
[VARIABLE]  query

TAINT FLOW:
  SOURCE:  getParameter() (line 21)
           └─> Variable 'query' marked as TAINTED
  SINK:    executeQuery() (line 26)
           └─> Tainted variable used in SQL execution
```

### Safe Code Detection

```
╔══════════════════════════════════════════════════════════════╗
║                    ANALYSIS RESULT                           ║
╠══════════════════════════════════════════════════════════════╣
║  ✓ No SQL Injection vulnerabilities detected                ║
╚══════════════════════════════════════════════════════════════╝
```

## 🧪 Create Your Own Test File

Create `MyTest.java` in `test-files/`:

```java
import java.sql.*;
import javax.servlet.http.*;

public class MyTest {
    public void testMethod(HttpServletRequest request) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();

        // This WILL be flagged as vulnerable
        String userInput = request.getParameter("id");
        String query = "SELECT * FROM data WHERE id = " + userInput;
        stmt.executeQuery(query);
    }
}
```

Run analysis:

```bash
java -jar target/sql-injection-detector-1.0.0-jar-with-dependencies.jar \
    test-files/MyTest.java
```

## 🔧 Troubleshooting

### "Command not found: mvn"

Install Maven:

```bash
# Ubuntu/Debian
sudo apt install maven

# macOS
brew install maven

# Windows
# Download from https://maven.apache.org/download.cgi
```

### "Command not found: java"

Install Java JDK:

```bash
# Ubuntu/Debian
sudo apt install openjdk-11-jdk

# macOS
brew install openjdk@11

# Windows
# Download from https://adoptium.net/
```

### Build Fails

```bash
# Clean and rebuild
mvn clean install -U

# Skip tests if any
mvn clean package -DskipTests
```

### Cannot Find Test Files

Use absolute paths:

```bash
java -jar target/sql-injection-detector-1.0.0-jar-with-dependencies.jar \
    /absolute/path/to/VulnerableExample.java
```

## 📖 Next Steps

1. ✅ Run the provided test cases
2. 📝 Create your own vulnerable code
3. 🔍 Analyze the compiler output
4. 🛠️ Modify detection rules (see README.md)
5. 📚 Study the source code implementation

## 💡 Key Takeaways

**What Makes Code Vulnerable:**

- User input → String concatenation → SQL execution
- Example: `"SELECT * FROM users WHERE id = " + userInput`

**What Makes Code Safe:**

- PreparedStatement with parameter binding
- Example: `ps.prepareStatement("SELECT * FROM users WHERE id = ?"); ps.setString(1, userInput);`

**What the Compiler Detects:**

- ✓ Taint sources (user input methods)
- ✓ Taint propagation (assignments, concatenations)
- ✓ Taint sinks (SQL execution methods)
- ✓ Complete data flow from source → sink

---

**You're ready to detect SQL injection vulnerabilities! 🎉**
