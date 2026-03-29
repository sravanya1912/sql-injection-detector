# 🛡 SQL Injection Detector

A static analysis tool that detects **SQL Injection vulnerabilities in Java code** by tracking how user input flows through a program.

Instead of relying on simple pattern matching, this tool performs **taint analysis (source → propagation → sink)** to identify real vulnerabilities at compile-time — even when they involve multiple variables and indirect data flow.

---

## 💡 Why I built this

SQL Injection is one of the most common and dangerous security vulnerabilities, yet many basic tools fail to detect real-world cases where:

* user input flows through multiple variables
* queries are constructed indirectly
* vulnerabilities are not obvious in a single line

I built this project to understand how **real static analysis tools work internally** and to implement a simplified version of **data-flow based vulnerability detection from scratch**.

---

## 🚀 Key Features

* 🔍 Detects SQL injection vulnerabilities in `.java` files
* 🔗 Tracks **multi-step data flow** across variables
* ⚠️ Classifies vulnerabilities into HIGH / MEDIUM / LOW
* 📊 Displays full **taint flow (source → propagation → sink)**
* 💡 Provides secure fix suggestions using `PreparedStatement`
* ⚡ Works at **compile-time** (no code execution needed)
* 🧠 Handles indirect and non-trivial vulnerability patterns

---

## 📊 Example Output

```text id="pt3g5f"
Vulnerability #1
[SEVERITY] HIGH
[LINE] 26
[VARIABLE] query

TAINT FLOW:
SOURCE → getParameter()
PROPAGATION → query variable
SINK → executeQuery()

Explanation:
User-controlled input flows into SQL query without sanitization,
allowing attackers to manipulate the query.

Recommendation:
Use PreparedStatement with parameter binding.
```

---

## 🔍 What it detects

This tool identifies vulnerabilities such as:

* SQL queries built using string concatenation
* User input directly used in SQL execution methods
* Multi-step propagation across variables and assignments
* Missing or ineffective sanitization

Severity levels:

* 🔴 HIGH → direct unsafe usage
* 🟡 MEDIUM → potential vulnerability
* 🔵 LOW → weak or risky patterns

---

## ⚙️ How it works

The tool follows a pipeline similar to a compiler:

```text id="0j3q2y"
Java Code
   ↓
Parse → Abstract Syntax Tree (AST)
   ↓
Build Symbol Table (track variables)
   ↓
Taint Analysis (track user input flow)
   ↓
Detect SQL execution points (sinks)
   ↓
Generate vulnerability report
```

### 🔁 Core Concept: Taint Flow

```text id="jq8q1h"
SOURCE → PROPAGATION → SINK
```

* **SOURCE** → where untrusted input enters
  (e.g., `getParameter()`, `Scanner.nextLine()`)

* **PROPAGATION** → how data moves through variables

* **SINK** → where SQL is executed
  (e.g., `executeQuery()`)

If tainted data reaches a sink → ⚠️ vulnerability detected

---

## 🧪 Example

### ❌ Vulnerable

```java id="e8wdyu"
String query = "SELECT * FROM users WHERE id = '" + userInput + "'";
stmt.execute(query);
```

### ✅ Safe

```java id="0z7b4u"
PreparedStatement ps = conn.prepareStatement(
    "SELECT * FROM users WHERE id = ?");
ps.setString(1, userInput);
ps.executeQuery();
```

---

## 🖥 How to run

### 1. Build project

```bash id="7s4i9k"
mvn clean compile
```

### 2. Run analysis

```bash id="a4d7xj"
mvn exec:java -Dexec.mainClass="SQLInjectionDetectorMain" \
-Dexec.args="test-files/VulnerableExample.java"
```

### OR using JAR

```bash id="w2n9rc"
java -jar target/sql-injection-detector-1.0.0-jar-with-dependencies.jar \
test-files/VulnerableExample.java
```

---

## 📁 Project Structure

```text id="u8d9kt"
sql-injection-detector/
├── src/        # Java analysis engine
├── test-files/ # sample vulnerable/safe files
├── server/     # Node.js backend
├── frontend/   # UI for visualization
└── README.md
```

---

## 🧠 Concepts Used

* Abstract Syntax Tree (AST)
* Symbol Table Construction
* Data Flow Analysis
* Taint Analysis
* Static Code Analysis

---

## 🚧 Limitations

* Works on a simplified subset of Java
* May produce false positives in edge cases
* Limited support for complex object-oriented flows

---

## 🔧 Future Improvements

* Inter-procedural analysis (across methods/files)
* More advanced sanitization detection
* Support for additional programming languages
* IDE plugins (VS Code / IntelliJ)
* CI/CD integration for automated scanning

---

## 👩‍💻 Author

**Sravanya Kanukollu**
B.Tech CSE — NIT Warangal

---

⭐ If you found this useful, consider starring the repo!
