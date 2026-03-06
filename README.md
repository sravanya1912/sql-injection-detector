# Static SQL Injection Detection Compiler

A compile-time static analysis tool that detects SQL injection vulnerabilities in Java source code using taint analysis and data-flow tracking.

## 🎯 Project Overview

This compiler performs **static analysis** (no code execution) to identify potential SQL injection vulnerabilities by:

- Tracking untrusted user input (taint sources)
- Propagating taint through variable assignments and string concatenations
- Detecting when tainted data reaches SQL execution points (sinks)
- Generating detailed vulnerability reports

## 🏗️ Architecture

The compiler follows a traditional multi-pass architecture:

```
Java Source Code
       ↓
[PHASE 1] Lexical & Syntax Analysis (JavaParser)
       ↓
[PHASE 2] Symbol Table Construction
       ↓
[PHASE 3] Taint Analysis (Data-Flow Analysis)
       ↓
[PHASE 4] SQL Injection Detection
       ↓
[PHASE 5] Warning Report Generation
```

## 📋 Prerequisites

- **Java JDK 8 or higher**
- **Maven 3.6+** (for dependency management)
- Internet connection (for downloading JavaParser dependency)

## 🚀 Installation & Setup

### Step 1: Create Project Structure

```bash
mkdir sql-injection-detector
cd sql-injection-detector
```

### Step 2: Create Maven Project Files

Create the following directory structure:

```
sql-injection-detector/
├── pom.xml
├── src/
│   └── main/
│       └── java/
│           └── SQLInjectionDetectorMain.java
└── test-files/
    └── VulnerableExample.java
```

### Step 3: Add the Code Files

1. Copy `pom.xml` to the root directory
2. Copy `SQLInjectionDetectorMain.java` to `src/main/java/`
3. Copy `VulnerableExample.java` to `test-files/`

### Step 4: Build the Project

```bash
mvn clean compile
```

### Step 5: Package as Executable JAR (Optional)

```bash
mvn clean package
```

This creates `target/sql-injection-detector-1.0.0-jar-with-dependencies.jar`

## 📖 Usage

### Method 1: Using Maven

```bash
mvn exec:java -Dexec.mainClass="SQLInjectionDetectorMain" \
    -Dexec.args="test-files/VulnerableExample.java"
```

### Method 2: Using Compiled JAR

```bash
java -jar target/sql-injection-detector-1.0.0-jar-with-dependencies.jar \
    test-files/VulnerableExample.java
```

### Method 3: Direct Java Execution (after compilation)

```bash
cd target/classes
java SQLInjectionDetectorMain ../../test-files/VulnerableExample.java
```

### Analyzing Multiple Files

```bash
java -jar target/sql-injection-detector-1.0.0-jar-with-dependencies.jar \
    file1.java file2.java file3.java
```

## 🧪 Testing with the Provided Example

Run the detector on the vulnerable example:

```bash
mvn exec:java -Dexec.mainClass="SQLInjectionDetectorMain" \
    -Dexec.args="test-files/VulnerableExample.java"
```

**Expected Output:** The tool should detect 4 SQL injection vulnerabilities in methods:

1. `loginUser()` - Lines with username/password concatenation
2. `searchProducts()` - Line with search term concatenation
3. `deleteRecord()` - Line with userId concatenation
4. `complexQuery()` - Lines with role/department concatenation

The `safeLogin()` method should **NOT** be flagged (uses PreparedStatement correctly).

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║   Static SQL Injection Detection Compiler                   ║
║   Compile-Time Security Analysis using Taint Analysis       ║
╚══════════════════════════════════════════════════════════════╝

Analyzing: test-files/VulnerableExample.java
─────────────────────────────────────────────────────────────

[PHASE 1] Parsing source code and generating AST...
✓ AST generation complete

[PHASE 2] Building symbol table...
✓ Symbol table constructed
  Variables tracked: 15

[PHASE 3] Performing taint analysis...
✓ Taint analysis complete
  Tainted variables: 8

[PHASE 4] Detecting SQL injection vulnerabilities...
✓ Vulnerability detection complete

[PHASE 5] Generating warning report...

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

DESCRIPTION:
  Potential SQL Injection vulnerability detected.
  Tainted data flows into SQL execution method.

TAINT FLOW:
  SOURCE:  getParameter() (line 21)
           └─> Variable 'query' marked as TAINTED

  SINK:    executeQuery() (line 26)
           └─> Tainted variable used in SQL execution

EXPLANATION:
  User-controlled input from getParameter()
  flows into variable 'query' and is used to
  construct an SQL query that is executed via executeQuery().
  This allows attackers to manipulate the SQL query structure.

RECOMMENDATION:
  Use PreparedStatement with parameter binding instead of
  string concatenation to construct SQL queries.

  Example fix:
    PreparedStatement ps = conn.prepareStatement(
        "SELECT * FROM users WHERE name = ?");
    ps.setString(1, userInput);
    ps.executeQuery();

═════════════════════════════════════════════════════════════
```

## 🔍 How It Works

### 1. Taint Sources (Untrusted Input)

The compiler identifies these methods as returning untrusted data:

- `request.getParameter()`
- `Scanner.nextLine()`, `next()`, `nextInt()`
- `BufferedReader.readLine()`

### 2. Taint Propagation Rules

**Rule 1: Direct Assignment**

```java
String x = request.getParameter("input"); // x is TAINTED
String y = x;                              // y is TAINTED (propagates)
```

**Rule 2: String Concatenation**

```java
String safe = "SELECT * FROM users";
String tainted = request.getParameter("name");
String query = safe + tainted;  // query is TAINTED
```

### 3. SQL Sinks (Vulnerability Points)

The compiler flags vulnerabilities when tainted data reaches:

- `statement.executeQuery(taintedVar)`
- `statement.executeUpdate(taintedVar)`
- `statement.execute(taintedVar)`

### 4. Safe Patterns (Not Flagged)

PreparedStatement with parameter binding:

```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setString(1, userInput);  // Safe - parameter binding
ps.executeQuery();           // NOT flagged as vulnerable
```

## 🎓 Compiler Concepts Demonstrated

1. **Abstract Syntax Tree (AST)**: Parse Java code into a tree representation
2. **Symbol Table**: Track variables and their properties (taint status)
3. **Semantic Analysis**: Understand program meaning beyond syntax
4. **Data-Flow Analysis**: Track how data moves through the program
5. **Visitor Pattern**: Traverse AST nodes systematically
6. **Static Analysis**: Analyze code without executing it

## 📂 Project Structure

```
sql-injection-detector/
├── pom.xml                              # Maven configuration
├── src/
│   └── main/
│       └── java/
│           └── SQLInjectionDetectorMain.java  # Main source code
├── test-files/
│   └── VulnerableExample.java          # Test cases
├── target/
│   ├── classes/                        # Compiled .class files
│   └── sql-injection-detector-1.0.0-jar-with-dependencies.jar
└── README.md                           # This file
```

## 🛠️ Customization

### Adding New Taint Sources

Edit `TaintAnalyzer.java` and add to `TAINT_SOURCES`:

```java
private static final Set<String> TAINT_SOURCES = new HashSet<>(Arrays.asList(
    "getParameter",
    "nextLine",
    "readLine",
    "yourCustomMethod"  // Add here
));
```

### Adding New SQL Sinks

Edit `SQLInjectionDetector.java` and add to `SQL_SINKS`:

```java
private static final Set<String> SQL_SINKS = new HashSet<>(Arrays.asList(
    "executeQuery",
    "executeUpdate",
    "execute",
    "yourCustomSQLMethod"  // Add here
));
```

## 🐛 Troubleshooting

### Issue: "Could not find or load main class"

**Solution:** Ensure you're in the correct directory and the class is compiled:

```bash
mvn clean compile
cd target/classes
java SQLInjectionDetectorMain <file.java>
```

### Issue: "FileNotFoundException"

**Solution:** Provide absolute path or correct relative path:

```bash
java SQLInjectionDetectorMain /full/path/to/VulnerableExample.java
```

### Issue: JavaParser dependency not found

**Solution:** Run Maven to download dependencies:

```bash
mvn clean install
```

## 📝 Limitations

This is an **academic/educational** tool with intentional limitations:

1. **Language Subset**: Supports basic Java constructs only
2. **Simplified Analysis**: Does not handle all edge cases
3. **No Inter-procedural Analysis**: Analyzes methods independently
4. **Conservative Approach**: May report false positives
5. **No Object-Oriented Analysis**: Limited class hierarchy support

## 🎯 Future Enhancements

- Inter-procedural taint analysis
- Path-sensitive analysis
- Support for more complex Java features
- Integration with IDE plugins
- Configuration file for custom rules
- HTML report generation

## 📚 References

- **JavaParser Documentation**: https://javaparser.org/
- **OWASP SQL Injection**: https://owasp.org/www-community/attacks/SQL_Injection
- **Taint Analysis**: Basic concept of tracking untrusted data flow
- **Static Analysis**: Compile-time program analysis techniques

## 👨‍💻 Author

Created as an educational compiler design project demonstrating:

- Compiler construction principles
- Static program analysis
- Security vulnerability detection
- Software engineering best practices

## 📄 License

This project is for educational purposes.

---

**Ready to detect SQL injection vulnerabilities at compile time! 🛡️**

to run safe code
java -jar target/sql-injection-detector-1.0.0-jar-with-dependencies.jar test-files/SafeExample.java

to run vulmerable code
java -jar target/sql-injection-detector-1.0.0-jar-with-dependencies.jar test-files/VulnerableExample.java
