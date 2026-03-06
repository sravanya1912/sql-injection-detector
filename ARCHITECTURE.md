# System Architecture Documentation

## Overview

The Static SQL Injection Detection Compiler is a multi-pass compiler that performs compile-time security analysis using taint analysis and data-flow tracking.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     INPUT LAYER                             │
│                  Java Source Files                          │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                 PHASE 1: PARSING                            │
│              JavaParser Library                             │
│         • Lexical Analysis (Tokenization)                   │
│         • Syntax Analysis (Grammar Validation)              │
│         • AST Generation                                    │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│           PHASE 2: SEMANTIC ANALYSIS                        │
│              Symbol Table Construction                      │
│         • Variable Discovery                                │
│         • Scope Tracking                                    │
│         • Type Information                                  │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│         PHASE 3: DATA-FLOW ANALYSIS                         │
│               Taint Analysis Engine                         │
│         • Identify Taint Sources                            │
│         • Track Taint Propagation                           │
│         • Maintain Taint Map                                │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│        PHASE 4: SECURITY ANALYSIS                           │
│          SQL Injection Detection                            │
│         • Identify SQL Sinks                                │
│         • Check Taint at Sink Points                        │
│         • Detect Vulnerabilities                            │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              PHASE 5: REPORTING                             │
│            Report Generator                                 │
│         • Format Vulnerability Details                      │
│         • Show Taint Flow Paths                             │
│         • Generate Recommendations                          │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                  OUTPUT LAYER                               │
│            Vulnerability Report                             │
└─────────────────────────────────────────────────────────────┘
```

## Component Architecture

### 1. Main Driver (`SQLInjectionDetectorMain`)

**Responsibilities:**

- Accept command-line arguments (source files)
- Coordinate execution of all phases
- Handle errors and exceptions
- Display progress information

**Key Methods:**

- `main(String[] args)` - Entry point
- `analyzeFile(String filePath)` - Orchestrates analysis for single file

### 2. AST Parser (`JavaParser` Library)

**Responsibilities:**

- Tokenize source code
- Parse according to Java grammar
- Build Abstract Syntax Tree
- Provide AST traversal mechanisms

**External Dependency:**

- `com.github.javaparser:javaparser-core:3.24.4`

### 3. Symbol Table (`SymbolTable` + `VariableInfo`)

**Data Structure:**

```java
Map<String, VariableInfo>
  │
  ├─ Variable Name (String) → Key
  │
  └─ VariableInfo → Value
       ├─ name: String
       ├─ tainted: boolean
       ├─ declarationLine: int
       ├─ taintSource: String
       └─ taintLine: int
```

**Operations:**

- `addVariable(name, line)` - Register new variable
- `markTainted(name, source, line)` - Mark variable as tainted
- `isTainted(name)` - Query taint status
- `getVariableInfo(name)` - Retrieve full information

### 4. Symbol Table Builder (`SymbolTableBuilder`)

**Pattern:** Visitor Pattern

**Responsibilities:**

- Traverse AST nodes
- Identify variable declarations
- Populate symbol table

**Visited Nodes:**

- `VariableDeclarator` - Variable declarations

### 5. Taint Analyzer (`TaintAnalyzer`)

**Pattern:** Visitor Pattern

**Responsibilities:**

- Identify taint sources
- Track taint propagation
- Maintain taint status in symbol table

**Taint Sources:**

```java
{
  "getParameter",    // HttpServletRequest.getParameter()
  "nextLine",        // Scanner.nextLine()
  "next",            // Scanner.next()
  "nextInt",         // Scanner.nextInt()
  "readLine"         // BufferedReader.readLine()
}
```

**Propagation Rules:**

| Rule              | Code Pattern                  | Result            |
| ----------------- | ----------------------------- | ----------------- |
| Direct Assignment | `String b = taintedA;`        | b becomes TAINTED |
| Concatenation     | `String c = safe + tainted;`  | c becomes TAINTED |
| Method Call       | `String d = taintedMethod();` | d becomes TAINTED |

**Visited Nodes:**

- `VariableDeclarator` - Variable initialization
- `AssignExpr` - Assignment expressions

### 6. SQL Injection Detector (`SQLInjectionDetector`)

**Pattern:** Visitor Pattern

**Responsibilities:**

- Identify SQL execution points (sinks)
- Check if sink arguments are tainted
- Record vulnerabilities

**SQL Sinks:**

```java
{
  "executeQuery",     // Statement.executeQuery()
  "executeUpdate",    // Statement.executeUpdate()
  "execute"           // Statement.execute()
}
```

**Detection Logic:**

```
IF (method_name IN SQL_SINKS)
  AND (argument_variable IS TAINTED)
THEN
  REPORT VULNERABILITY
```

**Visited Nodes:**

- `MethodCallExpr` - Method invocations

### 7. Vulnerability Record (`Vulnerability`)

**Data Model:**

```java
class Vulnerability {
  - fileName: String          // Source file name
  - line: int                 // Line number of vulnerability
  - variable: String          // Tainted variable name
  - sinkMethod: String        // SQL execution method
  - taintSource: String       // Original taint source
  - taintSourceLine: int      // Line where taint originated
}
```

### 8. Report Generator (`ReportGenerator`)

**Responsibilities:**

- Format vulnerability information
- Display taint flow paths
- Provide remediation recommendations
- Generate summary statistics

**Output Sections:**

1. Header with tool information
2. Analysis summary (counts)
3. Individual vulnerability details
4. Taint flow visualization
5. Recommendations

## Data Flow Through System

### Example Analysis Flow

**Input Code:**

```java
String userInput = request.getParameter("id");
String query = "SELECT * FROM users WHERE id = " + userInput;
statement.executeQuery(query);
```

**Step-by-Step Processing:**

```
1. PARSING (AST Generation)
   ├─ VariableDeclarator: userInput
   ├─ VariableDeclarator: query
   └─ MethodCallExpr: executeQuery

2. SYMBOL TABLE
   ├─ Add "userInput" → {line: 1, tainted: false}
   └─ Add "query" → {line: 2, tainted: false}

3. TAINT ANALYSIS
   ├─ Analyze: userInput = request.getParameter("id")
   │  └─ Source: getParameter() → Mark "userInput" as TAINTED
   │
   └─ Analyze: query = "..." + userInput
      └─ Propagation: userInput is TAINTED → Mark "query" as TAINTED

4. VULNERABILITY DETECTION
   └─ Analyze: executeQuery(query)
      ├─ Sink: executeQuery() detected
      ├─ Argument: query
      ├─ Check: query is TAINTED
      └─ VULNERABILITY DETECTED!

5. REPORT GENERATION
   └─ Format and display vulnerability details
```

## Visitor Pattern Implementation

### Why Visitor Pattern?

The Visitor pattern allows us to:

- Separate algorithm from AST structure
- Add new operations without modifying AST
- Process different node types polymorphically

### Visitor Flow

```
CompilationUnit (AST Root)
        │
        ├─ accept(SymbolTableBuilder)
        │    └─ Builds symbol table
        │
        ├─ accept(TaintAnalyzer)
        │    └─ Performs taint analysis
        │
        └─ accept(SQLInjectionDetector)
             └─ Detects vulnerabilities
```

### Each Visitor Implements

```java
class MyVisitor extends VoidVisitorAdapter<Void> {
    @Override
    public void visit(NodeType n, Void arg) {
        // Process this node
        processNode(n);

        // Continue traversal to children
        super.visit(n, arg);
    }
}
```

## Algorithm Details

### Taint Propagation Algorithm

```
Algorithm: PropagateTaint(expression)
Input: Expression from AST
Output: Boolean (is tainted)

1. IF expression is MethodCallExpr THEN
     IF method_name IN TAINT_SOURCES THEN
       RETURN TRUE
     END IF
   END IF

2. IF expression is BinaryExpr THEN
     left_tainted ← PropagateTaint(expression.left)
     right_tainted ← PropagateTaint(expression.right)
     RETURN left_tainted OR right_tainted
   END IF

3. IF expression is NameExpr THEN
     RETURN SymbolTable.isTainted(expression.name)
   END IF

4. RETURN FALSE
```

### Vulnerability Detection Algorithm

```
Algorithm: DetectSQLInjection(methodCall)
Input: MethodCallExpr from AST
Output: Vulnerability or NULL

1. method_name ← methodCall.getName()

2. IF method_name NOT IN SQL_SINKS THEN
     RETURN NULL
   END IF

3. FOR EACH argument IN methodCall.arguments DO
     IF IsTainted(argument) THEN
       vulnerability ← CreateVulnerability(methodCall, argument)
       RETURN vulnerability
     END IF
   END FOR

4. RETURN NULL
```

## Performance Characteristics

### Time Complexity

- **Parsing**: O(n) where n = source code size
- **Symbol Table Construction**: O(v) where v = number of variables
- **Taint Analysis**: O(s) where s = number of statements
- **Detection**: O(m) where m = number of method calls
- **Overall**: O(n + v + s + m) ≈ O(n) linear

### Space Complexity

- **AST Storage**: O(n)
- **Symbol Table**: O(v)
- **Taint Map**: O(v)
- **Vulnerability List**: O(k) where k = vulnerabilities found
- **Overall**: O(n + v + k) ≈ O(n) linear

### Scalability

The tool is designed for **small to medium** Java programs:

- Suitable for: Individual classes, small modules
- Limitations: Does not scale to large enterprise applications
- Reason: No inter-procedural analysis, limited optimization

## Design Decisions

### Why Static Analysis?

**Advantages:**

- ✅ Detects vulnerabilities before deployment
- ✅ No runtime overhead
- ✅ No need for test inputs
- ✅ Analyzes all code paths

**Trade-offs:**

- ⚠️ May produce false positives
- ⚠️ Cannot verify actual exploitability
- ⚠️ Conservative assumptions required

### Why JavaParser?

**Alternatives Considered:**

- Custom lexer/parser (too complex)
- Eclipse JDT (heavyweight)
- ANTLR-based (requires grammar knowledge)

**Selected: JavaParser**

- Mature and well-maintained
- Easy to use API
- Good documentation
- Lightweight dependency

### Why HashMap for Symbol Table?

**Requirements:**

- Fast lookup: O(1) average
- Dynamic sizing
- Simple implementation

**HashMap Provides:**

- Constant-time get/put operations
- Built-in collision handling
- Standard Java collection

## Extension Points

### Adding New Taint Sources

```java
// In TaintAnalyzer class
private static final Set<String> TAINT_SOURCES = new HashSet<>(Arrays.asList(
    "getParameter",
    "nextLine",
    "yourNewSource"  // Add here
));
```

### Adding New SQL Sinks

```java
// In SQLInjectionDetector class
private static final Set<String> SQL_SINKS = new HashSet<>(Arrays.asList(
    "executeQuery",
    "executeUpdate",
    "yourNewSink"  // Add here
));
```

### Adding New Analysis Passes

```java
// Create new visitor
class MyAnalyzer extends VoidVisitorAdapter<Void> {
    @Override
    public void visit(SomeNode n, Void arg) {
        // Your analysis logic
        super.visit(n, arg);
    }
}

// Add to main analysis flow
MyAnalyzer analyzer = new MyAnalyzer();
analyzer.visit(cu, null);
```

## Testing Strategy

### Unit Testing Approach

1. **Symbol Table Tests**
   - Add/retrieve variables
   - Taint marking
   - Query operations

2. **Taint Analysis Tests**
   - Source identification
   - Propagation rules
   - Edge cases

3. **Detection Tests**
   - Sink identification
   - Vulnerability reporting
   - False positive cases

### Integration Testing

1. **End-to-End Tests**
   - Vulnerable code samples
   - Safe code samples
   - Mixed scenarios

2. **Regression Tests**
   - Previous bug fixes
   - Edge cases
   - Performance benchmarks

---

**This architecture provides a solid foundation for understanding and extending the SQL Injection Detection Compiler.**
