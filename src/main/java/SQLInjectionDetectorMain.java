import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.io.File;
import java.io.FileInputStream;
import java.util.*;

/**
 * Static SQL Injection Detection Compiler
 */
public class SQLInjectionDetectorMain {

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java SQLInjectionDetectorMain <source-file.java>");
            return;
        }

        System.out.println("\n=== Static SQL Injection Detection Compiler ===\n");

        for (String filePath : args) {
            analyzeFile(filePath);
        }
    }

    private static void analyzeFile(String filePath) {
        try {
            File sourceFile = new File(filePath);
            System.out.println("Analyzing file: " + filePath);

            // Ensure the file has a .java extension for JavaParser
            File parseTarget = sourceFile;
            if (!filePath.endsWith(".java")) {
                parseTarget = File.createTempFile("upload_", ".java");
                parseTarget.deleteOnExit();
                java.nio.file.Files.copy(
                    sourceFile.toPath(),
                    parseTarget.toPath(),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING
                );
            }

            CompilationUnit cu;
            try (FileInputStream in = new FileInputStream(parseTarget)) {
                cu = StaticJavaParser.parse(in);
            }

            SymbolTable symbolTable = new SymbolTable();
            new SymbolTableBuilder(symbolTable).visit(cu, null);
            new TaintAnalyzer(symbolTable).visit(cu, null);

            SQLInjectionDetector detector =
                    new SQLInjectionDetector(symbolTable, sourceFile.getName());
            detector.visit(cu, null);

            ReportGenerator.generate(detector.getVulnerabilities());

        } catch (Exception e) {
            System.err.println("Error analyzing file: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

/* ================= SYMBOL TABLE ================= */

class SymbolTable {

    private final Map<String, VariableInfo> table = new HashMap<>();

    public void add(String name, int line) {
        table.put(name, new VariableInfo(name, line));
    }

    public void markTainted(String name, String source, int line) {
        VariableInfo info = table.get(name);
        if (info != null) {
            info.tainted = true;
            info.source = source;
            info.sourceLine = line;
        } else {
            // Variable assigned without prior declaration (e.g. re-assignment)
            VariableInfo newInfo = new VariableInfo(name, line);
            newInfo.tainted = true;
            newInfo.source = source;
            newInfo.sourceLine = line;
            table.put(name, newInfo);
        }
    }

    public boolean isTainted(String name) {
        VariableInfo info = table.get(name);
        return info != null && info.tainted;
    }

    public VariableInfo get(String name) {
        return table.get(name);
    }

    public int size() {
        return table.size();
    }

    public long taintedCount() {
        return table.values().stream().filter(v -> v.tainted).count();
    }

    static class VariableInfo {
        String name;
        boolean tainted;
        int declLine;
        String source;
        int sourceLine;

        VariableInfo(String name, int declLine) {
            this.name = name;
            this.declLine = declLine;
        }
    }
}

/* ================= SYMBOL TABLE BUILDER ================= */

class SymbolTableBuilder extends VoidVisitorAdapter<Void> {

    private final SymbolTable table;

    SymbolTableBuilder(SymbolTable table) {
        this.table = table;
    }

    @Override
    public void visit(VariableDeclarator n, Void arg) {
        super.visit(n, arg);
        int line = n.getBegin().isPresent() ? n.getBegin().get().line : -1;
        table.add(n.getNameAsString(), line);
    }
}

/* ================= TAINT ANALYSIS ================= */

class TaintAnalyzer extends VoidVisitorAdapter<Void> {

    private final SymbolTable table;

    private static final Set<String> SOURCES = new HashSet<>(
            Arrays.asList("getParameter", "next", "nextLine", "readLine",
                          "getHeader", "getCookies", "getQueryString")
    );

    TaintAnalyzer(SymbolTable table) {
        this.table = table;
    }

    @Override
    public void visit(VariableDeclarator n, Void arg) {
        super.visit(n, arg);
        if (n.getInitializer().isPresent()) {
            Expression expr = n.getInitializer().get();
            if (isTainted(expr)) {
                int line = n.getBegin().isPresent() ? n.getBegin().get().line : -1;
                table.markTainted(n.getNameAsString(), extractSource(expr), line);
            }
        }
    }

    @Override
    public void visit(AssignExpr n, Void arg) {
        super.visit(n, arg);
        if (n.getTarget().isNameExpr() && isTainted(n.getValue())) {
            String var = n.getTarget().asNameExpr().getNameAsString();
            int line = n.getBegin().isPresent() ? n.getBegin().get().line : -1;
            table.markTainted(var, extractSource(n.getValue()), line);
        }
    }

    boolean isTainted(Expression expr) {
        if (expr == null) return false;
        if (expr.isMethodCallExpr()) {
            return SOURCES.contains(expr.asMethodCallExpr().getNameAsString());
        }
        if (expr.isBinaryExpr()) {
            return isTainted(expr.asBinaryExpr().getLeft())
                    || isTainted(expr.asBinaryExpr().getRight());
        }
        if (expr.isNameExpr()) {
            return table.isTainted(expr.asNameExpr().getNameAsString());
        }
        if (expr.isEnclosedExpr()) {
            return isTainted(expr.asEnclosedExpr().getInner());
        }
        return false;
    }

    String extractSource(Expression expr) {
        if (expr == null) return "unknown";
        if (expr.isMethodCallExpr()) {
            return expr.asMethodCallExpr().getNameAsString() + "()";
        }
        if (expr.isNameExpr()) {
            SymbolTable.VariableInfo info = table.get(expr.asNameExpr().getNameAsString());
            return (info != null && info.source != null) ? info.source : "unknown";
        }
        if (expr.isBinaryExpr()) {
            // Walk both sides and return first tainted source found
            String left = extractSource(expr.asBinaryExpr().getLeft());
            if (!left.equals("unknown")) return left;
            return extractSource(expr.asBinaryExpr().getRight());
        }
        return "unknown";
    }
}

/* ================= SQL INJECTION DETECTOR ================= */

class SQLInjectionDetector extends VoidVisitorAdapter<Void> {

    private final SymbolTable table;
    private final String file;
    private final List<Vulnerability> vulnerabilities = new ArrayList<>();

    private static final Set<String> SQL_SINKS = new HashSet<>(
            Arrays.asList("executeQuery", "executeUpdate", "execute")
    );

    SQLInjectionDetector(SymbolTable table, String file) {
        this.table = table;
        this.file = file;
    }

    @Override
    public void visit(MethodCallExpr n, Void arg) {
        super.visit(n, arg);

        if (SQL_SINKS.contains(n.getNameAsString())) {
            for (Expression e : n.getArguments()) {
                boolean tainted = false;
                String varName = null;

                if (e.isNameExpr()) {
                    varName = e.asNameExpr().getNameAsString();
                    tainted = table.isTainted(varName);
                } else if (e.isBinaryExpr()) {
                    // Direct tainted concatenation passed straight to sink
                    TaintAnalyzer helper = new TaintAnalyzer(table);
                    tainted = helper.isTainted(e);
                    varName = e.toString();
                }

                if (tainted && varName != null) {
                    int line = n.getBegin().isPresent() ? n.getBegin().get().line : -1;
                    SymbolTable.VariableInfo info = table.get(varName);
                    String src = (info != null && info.source != null) ? info.source : "user input";
                    int srcLine = (info != null) ? info.sourceLine : -1;
                    vulnerabilities.add(new Vulnerability(
                            file, line, varName, src, srcLine, n.getNameAsString()
                    ));
                    break; // one vuln per sink call
                }
            }
        }
    }

    public List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }
}

/* ================= VULNERABILITY ================= */

class Vulnerability {

    String file;
    int line;
    String variable;
    String source;
    int sourceLine;
    String sink;

    Vulnerability(String file, int line, String variable,
                  String source, int sourceLine, String sink) {
        this.file = file;
        this.line = line;
        this.variable = variable;
        this.source = source;
        this.sourceLine = sourceLine;
        this.sink = sink;
    }
}

/* ================= REPORT GENERATOR ================= */

class ReportGenerator {

    public static void generate(List<Vulnerability> vulns) {
        if (vulns.isEmpty()) {
            System.out.println("╔══════════════════════════════════════════════╗");
            System.out.println("║           ANALYSIS RESULT                    ║");
            System.out.println("╠══════════════════════════════════════════════╣");
            System.out.println("║  ✔ No SQL Injection vulnerabilities detected ║");
            System.out.println("╚══════════════════════════════════════════════╝");
            return;
        }

        System.out.println("╔══════════════════════════════════════════════╗");
        System.out.println("║        ⚠  VULNERABILITIES DETECTED  ⚠       ║");
        System.out.println("╚══════════════════════════════════════════════╝");
        System.out.println("Total vulnerabilities found: " + vulns.size());
        System.out.println();

        int idx = 1;
        for (Vulnerability v : vulns) {
            System.out.println("┌──────────────────────────────────────────────┐");
            System.out.println("│ Vulnerability #" + idx++);
            System.out.println("└──────────────────────────────────────────────┘");
            System.out.println("[SEVERITY]  HIGH - SQL Injection");
            System.out.println("[FILE]      " + v.file);
            System.out.println("[LINE]      " + v.line);
            System.out.println("[VARIABLE]  " + v.variable);
            System.out.println();
            System.out.println("TAINT FLOW:");
            System.out.println("  SOURCE:  " + v.source
                    + (v.sourceLine > 0 ? " (line " + v.sourceLine + ")" : ""));
            System.out.println("           └─> Variable '" + v.variable + "' marked as TAINTED");
            System.out.println("  SINK:    " + v.sink + "() (line " + v.line + ")");
            System.out.println("           └─> Tainted variable used in SQL execution");
            System.out.println();
            System.out.println("RECOMMENDATION:");
            System.out.println("  Use PreparedStatement with parameter binding:");
            System.out.println("    PreparedStatement ps = conn.prepareStatement(");
            System.out.println("        \"SELECT * FROM table WHERE col = ?\");");
            System.out.println("    ps.setString(1, userInput);");
            System.out.println("    ps.executeQuery();");
            System.out.println("──────────────────────────────────────────────");
            System.out.println();
        }
    }
}