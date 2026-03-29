import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.io.File;
import java.io.FileInputStream;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Enhanced Static SQL Injection Detection Compiler
 * ─────────────────────────────────────────────────
 * Features:
 *  • Sanitization-aware taint analysis (reduced false positives)
 *  • Deep taint propagation: concatenation, ternary, cast, enclosed exprs
 *  • Parent-based taint flow tracking (full source → sink chain)
 *  • Extended source / sink coverage
 *  • Confidence scoring: HIGH / MEDIUM / LOW
 *  • Structured, human-readable report with propagation paths
 *  • Basic inter-procedural analysis (method-level taint transfer)
 *  • Heuristic-based severity ranking
 */
public class SQLInjectionDetectorMain {

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java SQLInjectionDetectorMain <source-file.java>");
            return;
        }
        System.out.println("\n╔══════════════════════════════════════════════════════════╗");
        System.out.println("║    Enhanced Static SQL Injection Detection Compiler      ║");
        System.out.println("║    Version 2.0  |  Taint + Sanitization + Confidence     ║");
        System.out.println("╚══════════════════════════════════════════════════════════╝\n");

        for (String filePath : args) {
            analyzeFile(filePath);
        }
    }

    private static void analyzeFile(String filePath) {
        try {
            File sourceFile = new File(filePath);
            System.out.println("▶  Analyzing: " + filePath);
            System.out.println("─".repeat(62));

            File parseTarget = sourceFile;
            if (!filePath.endsWith(".java")) {
                parseTarget = File.createTempFile("upload_", ".java");
                parseTarget.deleteOnExit();
                java.nio.file.Files.copy(
                    sourceFile.toPath(), parseTarget.toPath(),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }

            CompilationUnit cu;
            try (FileInputStream in = new FileInputStream(parseTarget)) {
                cu = StaticJavaParser.parse(in);
            }

            // Phase 1 – build symbol table
            EnhancedSymbolTable symbolTable = new EnhancedSymbolTable();
            new SymbolTableBuilder(symbolTable).visit(cu, null);

            // Phase 2 – collect method return taint (inter-procedural)
            MethodTaintRegistry methodRegistry = new MethodTaintRegistry();
            new MethodReturnTaintVisitor(symbolTable, methodRegistry).visit(cu, null);

            // Phase 3 – taint propagation
            new EnhancedTaintAnalyzer(symbolTable, methodRegistry).visit(cu, null);

            // Phase 4 – detect vulnerabilities
            EnhancedSQLInjectionDetector detector =
                new EnhancedSQLInjectionDetector(symbolTable, methodRegistry, sourceFile.getName());
            detector.visit(cu, null);

            // Phase 5 – generate report
            EnhancedReportGenerator.generate(
                detector.getVulnerabilities(), symbolTable, sourceFile.getName());

        } catch (Exception e) {
            System.err.println("Error analyzing file: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

/* ═══════════════════════════ TAINT NODE ═══════════════════════════ */

class TaintNode {
    enum NodeType { SOURCE, PROPAGATION, SANITIZED, SINK }

    NodeType type;
    String   label;       // human-readable description
    int      line;
    String   variable;    // variable name at this hop (may be null for sink/expr)

    TaintNode(NodeType type, String label, int line, String variable) {
        this.type     = type;
        this.label    = label;
        this.line     = line;
        this.variable = variable;
    }

    @Override
    public String toString() {
        String prefix = switch (type) {
            case SOURCE      -> "  [SOURCE]      ";
            case PROPAGATION -> "  [PROPAGATION] ";
            case SANITIZED   -> "  [SANITIZED]   ";
            case SINK        -> "  [SINK]        ";
        };
        return prefix + label + (line > 0 ? "  (line " + line + ")" : "");
    }
}

/* ═══════════════════════════ SYMBOL TABLE ══════════════════════════ */

class EnhancedSymbolTable {

    final Map<String, VariableInfo> table = new LinkedHashMap<>();

    void add(String name, int line) {
        table.putIfAbsent(name, new VariableInfo(name, line));
    }

    void markTainted(String name, String sourceLabel, int line, List<TaintNode> chain) {
        VariableInfo info = table.computeIfAbsent(name, k -> new VariableInfo(k, line));
        info.tainted   = true;
        info.sanitized = false;
        info.sourceLabel = sourceLabel;
        info.sourceLine  = line;
        if (chain != null) info.taintChain = new ArrayList<>(chain);
    }

    void markSanitized(String name, int line) {
        VariableInfo info = table.get(name);
        if (info != null) {
            info.sanitized = true;
            info.taintChain.add(new TaintNode(
                TaintNode.NodeType.SANITIZED,
                "'" + name + "' passed through sanitizer", line, name));
        }
    }

    boolean isTainted(String name) {
        VariableInfo info = table.get(name);
        return info != null && info.tainted && !info.sanitized;
    }

    VariableInfo get(String name) { return table.get(name); }

    static class VariableInfo {
        String name;
        boolean tainted;
        boolean sanitized;
        int declLine;
        String sourceLabel;
        int sourceLine;
        int propagationDepth;
        List<TaintNode> taintChain = new ArrayList<>();

        VariableInfo(String name, int declLine) {
            this.name     = name;
            this.declLine = declLine;
        }
    }
}

/* ═══════════════════════════ SYMBOL TABLE BUILDER ══════════════════ */

class SymbolTableBuilder extends VoidVisitorAdapter<Void> {
    private final EnhancedSymbolTable table;
    SymbolTableBuilder(EnhancedSymbolTable t) { this.table = t; }

    @Override public void visit(VariableDeclarator n, Void arg) {
        super.visit(n, arg);
        int line = n.getBegin().map(p -> p.line).orElse(-1);
        table.add(n.getNameAsString(), line);
    }
}

/* ═══════════════════════════ METHOD TAINT REGISTRY ════════════════ */

/** Tracks which methods return tainted values (basic inter-procedural). */
class MethodTaintRegistry {
    private final Map<String, Boolean> taintedMethods = new HashMap<>();
    private final Map<String, String>  methodSources  = new HashMap<>();

    void register(String methodName, boolean tainted, String source) {
        taintedMethods.put(methodName, tainted);
        methodSources.put(methodName, source);
    }

    boolean isTainted(String methodName) {
        return taintedMethods.getOrDefault(methodName, false);
    }

    String getSource(String methodName) {
        return methodSources.getOrDefault(methodName, "unknown");
    }
}

/* ═══════════════════════════ METHOD RETURN TAINT VISITOR ═══════════ */

class MethodReturnTaintVisitor extends VoidVisitorAdapter<Void> {

    private final EnhancedSymbolTable  table;
    private final MethodTaintRegistry  registry;
    private       String               currentMethod;

    private static final Set<String> TAINT_SOURCES = Set.of(
        "getParameter", "getParameterValues", "getParameterMap",
        "next", "nextLine", "readLine", "readAllBytes",
        "getHeader", "getHeaders", "getCookies", "getQueryString",
        "getRequestURI", "getPathInfo", "getRemoteAddr",
        "getText", "getSelectedItem", "getSelectedItems",
        "getAttribute", "getInitParameter", "getenv", "getProperty",
        "read", "readUTF", "receiveText", "nextToken"
    );

    MethodReturnTaintVisitor(EnhancedSymbolTable t, MethodTaintRegistry r) {
        this.table = t; this.registry = r;
    }

    @Override public void visit(MethodDeclaration n, Void arg) {
        currentMethod = n.getNameAsString();
        super.visit(n, arg);
    }

    @Override public void visit(com.github.javaparser.ast.stmt.ReturnStmt n, Void arg) {
        super.visit(n, arg);
        if (currentMethod == null) return;
        n.getExpression().ifPresent(expr -> {
            EnhancedTaintAnalyzer helper = new EnhancedTaintAnalyzer(table, new MethodTaintRegistry());
            if (helper.isTainted(expr)) {
                registry.register(currentMethod, true, helper.extractSourceLabel(expr));
            }
        });
    }
}

/* ═══════════════════════════ ENHANCED TAINT ANALYZER ══════════════ */

class EnhancedTaintAnalyzer extends VoidVisitorAdapter<Void> {

    private final EnhancedSymbolTable table;
    private final MethodTaintRegistry methodRegistry;

    // ── Taint sources ──────────────────────────────────────────────
    static final Set<String> SOURCES = Set.of(
        "getParameter", "getParameterValues", "getParameterMap",
        "next", "nextLine", "readLine", "readAllBytes",
        "getHeader", "getHeaders", "getCookies", "getQueryString",
        "getRequestURI", "getPathInfo", "getRemoteAddr",
        "getText", "getSelectedItem", "getSelectedItems",
        "getAttribute", "getInitParameter", "getenv", "getProperty",
        "read", "readUTF", "receiveText", "nextToken"
    );

    // ── Sanitizers ────────────────────────────────────────────────
    static final Set<String> SANITIZERS = Set.of(
        "sanitize", "escape", "escapeSql", "escapeHtml", "htmlEncode",
        "encodeForSQL", "encodeForHTML", "stripSql", "cleanInput",
        "replace", "replaceAll", "replaceFirst", "trim",
        "validateInput", "encode", "encodeURIComponent",
        "prepareStatement", "setString", "setInt", "setLong",
        "setDouble", "setObject", "setDate", "setTimestamp"
    );

    EnhancedTaintAnalyzer(EnhancedSymbolTable table, MethodTaintRegistry methodRegistry) {
        this.table          = table;
        this.methodRegistry = methodRegistry;
    }

    // ── Variable declaration ─────────────────────────────────────
    @Override public void visit(VariableDeclarator n, Void arg) {
        super.visit(n, arg);
        n.getInitializer().ifPresent(expr -> {
            if (isTainted(expr)) {
                int line = n.getBegin().map(p -> p.line).orElse(-1);
                String src  = extractSourceLabel(expr);
                List<TaintNode> chain = buildChain(expr, n.getNameAsString(), line, src);
                table.markTainted(n.getNameAsString(), src, line, chain);
                // update propagation depth
                EnhancedSymbolTable.VariableInfo info = table.get(n.getNameAsString());
                if (info != null) info.propagationDepth = computeDepth(expr);
            } else if (isSanitized(expr)) {
                // If initializer wraps a tainted var in a sanitizer, mark safe
                extractTaintedName(expr).ifPresent(name -> {
                    int line = n.getBegin().map(p -> p.line).orElse(-1);
                    table.markSanitized(n.getNameAsString(), line);
                });
            }
        });
    }

    // ── Assignment expressions ────────────────────────────────────
    @Override public void visit(AssignExpr n, Void arg) {
        super.visit(n, arg);
        if (!n.getTarget().isNameExpr()) return;
        String var  = n.getTarget().asNameExpr().getNameAsString();
        int    line = n.getBegin().map(p -> p.line).orElse(-1);

        if (isSanitized(n.getValue())) {
            table.markSanitized(var, line);
        } else if (isTainted(n.getValue())) {
            String src = extractSourceLabel(n.getValue());
            List<TaintNode> chain = buildChain(n.getValue(), var, line, src);
            table.markTainted(var, src, line, chain);
            EnhancedSymbolTable.VariableInfo info = table.get(var);
            if (info != null) info.propagationDepth = computeDepth(n.getValue());
        }
    }

    // ── Core taint check ─────────────────────────────────────────
    boolean isTainted(Expression expr) {
        if (expr == null) return false;

        // Method call — check if it's a known source
        if (expr.isMethodCallExpr()) {
            MethodCallExpr mc = expr.asMethodCallExpr();
            if (SOURCES.contains(mc.getNameAsString())) return true;
            // Inter-procedural: check registry
            if (methodRegistry.isTainted(mc.getNameAsString())) return true;
            // Sanitizer wrapping a tainted argument
            if (SANITIZERS.contains(mc.getNameAsString())) return false;
            // Propagation through method arguments (conservative)
            return mc.getArguments().stream().anyMatch(this::isTainted);
        }

        if (expr.isNameExpr())
            return table.isTainted(expr.asNameExpr().getNameAsString());

        if (expr.isBinaryExpr()) {
            BinaryExpr b = expr.asBinaryExpr();
            return isTainted(b.getLeft()) || isTainted(b.getRight());
        }

        if (expr.isEnclosedExpr())
            return isTainted(expr.asEnclosedExpr().getInner());

        if (expr.isCastExpr())
            return isTainted(expr.asCastExpr().getExpression());

        if (expr.isConditionalExpr()) {
            ConditionalExpr c = expr.asConditionalExpr();
            return isTainted(c.getThenExpr()) || isTainted(c.getElseExpr());
        }

        if (expr.isArrayAccessExpr())
            return isTainted(expr.asArrayAccessExpr().getName());

        return false;
    }

    // ── Sanitization check ──────────────────────────────────────
    boolean isSanitized(Expression expr) {
        if (expr == null) return false;
        if (expr.isMethodCallExpr()) {
            MethodCallExpr mc = expr.asMethodCallExpr();
            if (SANITIZERS.contains(mc.getNameAsString())) {
                // Only counts if one of the args is tainted
                return mc.getArguments().stream().anyMatch(this::isTainted);
            }
        }
        if (expr.isEnclosedExpr()) return isSanitized(expr.asEnclosedExpr().getInner());
        return false;
    }

    // ── Source label extraction ──────────────────────────────────
    String extractSourceLabel(Expression expr) {
        if (expr == null) return "unknown";
        if (expr.isMethodCallExpr()) {
            MethodCallExpr mc = expr.asMethodCallExpr();
            if (SOURCES.contains(mc.getNameAsString()))
                return mc.getNameAsString() + "()";
            if (methodRegistry.isTainted(mc.getNameAsString()))
                return mc.getNameAsString() + "() [inter-procedural]";
            // Recurse into args
            for (Expression a : mc.getArguments()) {
                String s = extractSourceLabel(a);
                if (!s.equals("unknown")) return s;
            }
        }
        if (expr.isNameExpr()) {
            EnhancedSymbolTable.VariableInfo v =
                table.get(expr.asNameExpr().getNameAsString());
            return (v != null && v.sourceLabel != null) ? v.sourceLabel : "unknown";
        }
        if (expr.isBinaryExpr()) {
            String l = extractSourceLabel(expr.asBinaryExpr().getLeft());
            if (!l.equals("unknown")) return l;
            return extractSourceLabel(expr.asBinaryExpr().getRight());
        }
        if (expr.isEnclosedExpr()) return extractSourceLabel(expr.asEnclosedExpr().getInner());
        if (expr.isCastExpr())     return extractSourceLabel(expr.asCastExpr().getExpression());
        if (expr.isConditionalExpr()) {
            ConditionalExpr c = expr.asConditionalExpr();
            String t = extractSourceLabel(c.getThenExpr());
            return t.equals("unknown") ? extractSourceLabel(c.getElseExpr()) : t;
        }
        return "unknown";
    }

    // ── Build taint chain (for reporting) ────────────────────────
    List<TaintNode> buildChain(Expression expr, String varName, int line, String srcLabel) {
        List<TaintNode> chain = new ArrayList<>();
        // Carry over existing chain from a referenced variable
        if (expr.isNameExpr()) {
            EnhancedSymbolTable.VariableInfo v = table.get(expr.asNameExpr().getNameAsString());
            if (v != null && !v.taintChain.isEmpty()) chain.addAll(v.taintChain);
        } else if (expr.isBinaryExpr()) {
            // Collect chains from both sides
            appendChainFromExpr(expr.asBinaryExpr().getLeft(),  chain);
            appendChainFromExpr(expr.asBinaryExpr().getRight(), chain);
        }
        // If chain is empty this must be a direct source
        if (chain.isEmpty()) {
            chain.add(new TaintNode(TaintNode.NodeType.SOURCE,
                "Tainted input from " + srcLabel, line, varName));
        }
        // Add propagation node for the current variable
        chain.add(new TaintNode(TaintNode.NodeType.PROPAGATION,
            "Assigned to '" + varName + "'", line, varName));
        return chain;
    }

    private void appendChainFromExpr(Expression expr, List<TaintNode> chain) {
        if (expr.isNameExpr()) {
            EnhancedSymbolTable.VariableInfo v = table.get(expr.asNameExpr().getNameAsString());
            if (v != null && !v.taintChain.isEmpty()) chain.addAll(v.taintChain);
        }
    }

    /** Heuristic depth: count variable hops. */
    int computeDepth(Expression expr) {
        if (expr.isNameExpr()) {
            EnhancedSymbolTable.VariableInfo v = table.get(expr.asNameExpr().getNameAsString());
            return (v != null) ? v.propagationDepth + 1 : 1;
        }
        if (expr.isBinaryExpr()) {
            return Math.max(
                computeDepthOf(expr.asBinaryExpr().getLeft()),
                computeDepthOf(expr.asBinaryExpr().getRight()));
        }
        return 1;
    }

    private int computeDepthOf(Expression e) {
        return new EnhancedTaintAnalyzer(table, methodRegistry).computeDepth(e);
    }

    private Optional<String> extractTaintedName(Expression expr) {
        if (expr.isMethodCallExpr()) {
            for (Expression a : expr.asMethodCallExpr().getArguments()) {
                if (a.isNameExpr() && table.isTainted(a.asNameExpr().getNameAsString()))
                    return Optional.of(a.asNameExpr().getNameAsString());
            }
        }
        return Optional.empty();
    }
}

/* ═══════════════════════════ VULNERABILITY ════════════════════════ */

class Vulnerability {

    enum Severity { HIGH, MEDIUM, LOW }
    enum ConfidenceFlag {
        DIRECT_CONCAT,
        INDIRECT_PROPAGATION,
        SANITIZER_PRESENT,
        DEEP_PROPAGATION,
        INTER_PROCEDURAL
    }

    String file;
    int    sinkLine;
    String variable;
    String sourceLabel;
    int    sourceLine;
    String sinkMethod;
    List<TaintNode>       taintChain;
    List<ConfidenceFlag>  flags     = new ArrayList<>();
    int                   propagationDepth;
    Severity              severity;
    int                   confidenceScore;  // 0-100
    String                explanation;

    Vulnerability(String file, int sinkLine, String variable,
                  String sourceLabel, int sourceLine, String sinkMethod,
                  List<TaintNode> chain, int depth) {
        this.file             = file;
        this.sinkLine         = sinkLine;
        this.variable         = variable;
        this.sourceLabel      = sourceLabel;
        this.sourceLine       = sourceLine;
        this.sinkMethod       = sinkMethod;
        this.taintChain       = chain != null ? new ArrayList<>(chain) : new ArrayList<>();
        this.propagationDepth = depth;
        computeSeverity();
    }

    void computeSeverityPublic() { computeSeverity(); }

    private void computeSeverity() {
        int score = 50; // baseline

        if (flags.contains(ConfidenceFlag.DIRECT_CONCAT))     score += 30;
        if (flags.contains(ConfidenceFlag.DEEP_PROPAGATION))  score -= 10;
        if (flags.contains(ConfidenceFlag.INTER_PROCEDURAL))  score += 10;
        if (flags.contains(ConfidenceFlag.SANITIZER_PRESENT)) score -= 40;
        if (propagationDepth <= 1)                            score += 15;
        if (propagationDepth > 4)                             score -= 5;

        confidenceScore = Math.min(100, Math.max(0, score));

        if (confidenceScore >= 70)      severity = Severity.HIGH;
        else if (confidenceScore >= 40) severity = Severity.MEDIUM;
        else                            severity = Severity.LOW;

        explanation = buildExplanation();
    }

    private String buildExplanation() {
        StringBuilder sb = new StringBuilder();
        sb.append("Tainted data from '").append(sourceLabel).append("' ");
        if (propagationDepth <= 1) {
            sb.append("flows directly into '").append(sinkMethod).append("()'. ");
        } else {
            sb.append("propagates through ").append(propagationDepth)
              .append(" variable(s) before reaching '").append(sinkMethod).append("()'. ");
        }
        if (flags.contains(ConfidenceFlag.DIRECT_CONCAT)) {
            sb.append("String concatenation detected — attacker can inject arbitrary SQL. ");
        }
        if (flags.contains(ConfidenceFlag.SANITIZER_PRESENT)) {
            sb.append("Note: a sanitizer was detected but may not fully neutralize the input. ");
        }
        sb.append("Use PreparedStatement with parameterized queries to eliminate this risk.");
        return sb.toString();
    }
}

/* ═══════════════════════════ ENHANCED DETECTOR ════════════════════ */

class EnhancedSQLInjectionDetector extends VoidVisitorAdapter<Void> {

    private final EnhancedSymbolTable table;
    private final MethodTaintRegistry methodRegistry;
    private final String              file;
    private final List<Vulnerability> vulnerabilities = new ArrayList<>();

    // Extended SQL sinks
    private static final Set<String> SQL_SINKS = Set.of(
        "executeQuery", "executeUpdate", "execute", "executeBatch",
        "executeLargeUpdate", "executeLargeBatch",
        "addBatch", "prepareStatement", "prepareCall",
        "nativeSQL", "query", "update", "queryForObject",
        "queryForList", "queryForMap", "getResultSet"
    );

    EnhancedSQLInjectionDetector(EnhancedSymbolTable t, MethodTaintRegistry m, String f) {
        this.table = t; this.methodRegistry = m; this.file = f;
    }

    @Override
    public void visit(MethodCallExpr n, Void arg) {
        super.visit(n, arg);
        if (!SQL_SINKS.contains(n.getNameAsString())) return;

        for (Expression e : n.getArguments()) {
            int line = n.getBegin().map(p -> p.line).orElse(-1);
            EnhancedTaintAnalyzer helper = new EnhancedTaintAnalyzer(table, methodRegistry);

            boolean tainted      = false;
            boolean directConcat = false;
            String  varName      = null;
            List<TaintNode> chain;
            int depth = 0;

            if (e.isNameExpr()) {
                varName = e.asNameExpr().getNameAsString();
                tainted = table.isTainted(varName);
                EnhancedSymbolTable.VariableInfo info = table.get(varName);
                chain = (info != null) ? info.taintChain : new ArrayList<>();
                depth = (info != null) ? info.propagationDepth : 0;

            } else if (e.isBinaryExpr()) {
                tainted      = helper.isTainted(e);
                directConcat = true;
                varName      = e.toString();
                chain        = buildInlineChain(e, line, helper);
                depth        = 1;

            } else if (e.isMethodCallExpr()) {
                tainted = helper.isTainted(e);
                varName = e.toString();
                chain   = new ArrayList<>();
                if (tainted) chain.add(new TaintNode(TaintNode.NodeType.SOURCE,
                    "Inline tainted method call: " + varName, line, varName));
                depth = 1;

            } else {
                chain = new ArrayList<>();
            }

            if (tainted && varName != null) {
                EnhancedSymbolTable.VariableInfo info = table.get(
                    e.isNameExpr() ? e.asNameExpr().getNameAsString() : null);
                String src     = (info != null && info.sourceLabel != null)
                                 ? info.sourceLabel
                                 : helper.extractSourceLabel(e);
                int    srcLine = (info != null) ? info.sourceLine : -1;

                // Finalize chain: append sink node
                List<TaintNode> finalChain = new ArrayList<>(chain);
                finalChain.add(new TaintNode(TaintNode.NodeType.SINK,
                    "Tainted value passed to " + n.getNameAsString() + "()", line, varName));

                Vulnerability v = new Vulnerability(
                    file, line, varName, src, srcLine,
                    n.getNameAsString(), finalChain, depth);

                if (directConcat)  v.flags.add(Vulnerability.ConfidenceFlag.DIRECT_CONCAT);
                if (depth > 3)     v.flags.add(Vulnerability.ConfidenceFlag.DEEP_PROPAGATION);
                if (methodRegistry.isTainted(src.replace("()", "").replace(" [inter-procedural]", "")))
                    v.flags.add(Vulnerability.ConfidenceFlag.INTER_PROCEDURAL);

                // Re-compute severity with flags
                v.computeSeverityPublic();
                vulnerabilities.add(v);
                break;
            }
        }
    }

    private List<TaintNode> buildInlineChain(BinaryExpr expr, int line, EnhancedTaintAnalyzer h) {
        List<TaintNode> chain = new ArrayList<>();
        String src = h.extractSourceLabel(expr);
        chain.add(new TaintNode(TaintNode.NodeType.SOURCE,
            "Tainted input from " + src, line, expr.toString()));
        chain.add(new TaintNode(TaintNode.NodeType.PROPAGATION,
            "Direct string concatenation into SQL: " + shortenExpr(expr.toString()), line, null));
        return chain;
    }

    private String shortenExpr(String s) {
        return s.length() > 60 ? s.substring(0, 57) + "..." : s;
    }

    List<Vulnerability> getVulnerabilities() { return vulnerabilities; }
}

// Make computeSeverity accessible from detector
class VulnerabilityHelper {
    static void recompute(Vulnerability v) { v.computeSeverityPublic(); }
}

/* ═══════════════════════════ VULNERABILITY (continued) ════════════ */
// Patch: add public method so detector can re-trigger after flags are set
// We extend Vulnerability via a helper — but since it's in same file, just add method:
// (Already done in the class above — the call v.computeSeverityPublic() needs the method)

/* ═══════════════════════════ ENHANCED REPORT GENERATOR ════════════ */

class EnhancedReportGenerator {

    static void generate(List<Vulnerability> vulns,
                         EnhancedSymbolTable table,
                         String fileName) {

        printSummaryHeader(vulns, fileName, table);

        if (vulns.isEmpty()) return;

        // Sort by confidence descending
        vulns.sort((a, b) -> Integer.compare(b.confidenceScore, a.confidenceScore));

        int idx = 1;
        for (Vulnerability v : vulns) {
            printVulnerability(v, idx++);
        }

        printFooter(vulns);
    }

    private static void printSummaryHeader(List<Vulnerability> vulns,
                                            String fileName,
                                            EnhancedSymbolTable table) {
        System.out.println();
        System.out.println("┌──────────────────────────────────────────────────────────┐");
        System.out.printf ("│  File     : %-46s  │%n", fileName);
        System.out.printf ("│  Variables tracked : %-39d  │%n", table.table.size());
        System.out.printf ("│  Tainted variables : %-39d  │%n",
            table.table.values().stream().filter(v -> v.tainted && !v.sanitized).count());
        System.out.printf ("│  Vulnerabilities   : %-39d  │%n", vulns.size());
        System.out.println("└──────────────────────────────────────────────────────────┘");

        if (vulns.isEmpty()) {
            System.out.println();
            System.out.println("  ╔══════════════════════════════════════════════════════╗");
            System.out.println("  ║  ✔  No SQL Injection vulnerabilities detected.       ║");
            System.out.println("  ║     All tainted paths are sanitized or none found.   ║");
            System.out.println("  ╚══════════════════════════════════════════════════════╝");
            System.out.println();
            return;
        }

        long high   = vulns.stream().filter(v -> v.severity == Vulnerability.Severity.HIGH).count();
        long medium = vulns.stream().filter(v -> v.severity == Vulnerability.Severity.MEDIUM).count();
        long low    = vulns.stream().filter(v -> v.severity == Vulnerability.Severity.LOW).count();

        System.out.println();
        System.out.println("  ⚠  SEVERITY BREAKDOWN:");
        if (high   > 0) System.out.printf("     ● HIGH   : %d vulnerability(ies)%n", high);
        if (medium > 0) System.out.printf("     ● MEDIUM : %d vulnerability(ies)%n", medium);
        if (low    > 0) System.out.printf("     ● LOW    : %d vulnerability(ies)%n", low);
        System.out.println();
    }

    private static void printVulnerability(Vulnerability v, int idx) {
        String sevBar = switch (v.severity) {
            case HIGH   -> "████████████████████ HIGH   ";
            case MEDIUM -> "█████████████░░░░░░░ MEDIUM ";
            case LOW    -> "███████░░░░░░░░░░░░░ LOW    ";
        };

        System.out.println("╔══════════════════════════════════════════════════════════╗");
        System.out.printf ("║  Vulnerability #%-3d                                      ║%n", idx);
        System.out.println("╚══════════════════════════════════════════════════════════╝");
        System.out.println();

        System.out.println("  SEVERITY     : " + sevBar);
        System.out.printf ("  CONFIDENCE   : %d / 100%n", v.confidenceScore);
        System.out.println("  FILE         : " + v.file);
        System.out.println("  SINK LINE    : " + v.sinkLine);
        System.out.println("  VARIABLE     : " + v.variable);
        System.out.println("  SINK METHOD  : " + v.sinkMethod + "()");
        System.out.println();

        // Flags
        if (!v.flags.isEmpty()) {
            System.out.println("  DETECTED FLAGS:");
            for (Vulnerability.ConfidenceFlag f : v.flags) {
                System.out.println("    • " + flagDescription(f));
            }
            System.out.println();
        }

        // Taint flow chain
        System.out.println("  TAINT FLOW:");
        if (v.taintChain.isEmpty()) {
            System.out.println("    (no chain recorded)");
        } else {
            for (int i = 0; i < v.taintChain.size(); i++) {
                TaintNode node = v.taintChain.get(i);
                System.out.println("    " + (i + 1) + ". " + node);
                if (i < v.taintChain.size() - 1)
                    System.out.println("        │");
            }
        }
        System.out.println();

        // Explanation
        System.out.println("  EXPLANATION:");
        wrapPrint("  │  ", v.explanation, 60);
        System.out.println();

        // Recommendation
        System.out.println("  RECOMMENDATION:");
        System.out.println("  │  Replace dynamic query construction with a");
        System.out.println("  │  PreparedStatement:");
        System.out.println("  │");
        System.out.println("  │    PreparedStatement ps = conn.prepareStatement(");
        System.out.println("  │        \"SELECT * FROM table WHERE col = ?\");");
        System.out.println("  │    ps.setString(1, " + shortVar(v.variable) + ");");
        System.out.println("  │    ResultSet rs = ps.executeQuery();");
        System.out.println();
        System.out.println("═".repeat(62));
        System.out.println();
    }

    private static void printFooter(List<Vulnerability> vulns) {
        System.out.println("┌──────────────────────────────────────────────────────────┐");
        System.out.println("│  ANALYSIS COMPLETE                                       │");
        System.out.printf ("│  Total vulnerabilities : %-33d │%n", vulns.size());
        System.out.printf ("│  Highest confidence    : %-3d / 100%-26s │%n",
            vulns.stream().mapToInt(v -> v.confidenceScore).max().orElse(0), "");
        System.out.println("│  Action required       : Review and fix all HIGH items   │");
        System.out.println("└──────────────────────────────────────────────────────────┘");
        System.out.println();
    }

    private static String flagDescription(Vulnerability.ConfidenceFlag f) {
        return switch (f) {
            case DIRECT_CONCAT      -> "Direct string concatenation into SQL query (very dangerous)";
            case INDIRECT_PROPAGATION -> "Taint propagated through multiple variables";
            case SANITIZER_PRESENT  -> "Partial sanitizer detected (may reduce risk, verify)";
            case DEEP_PROPAGATION   -> "Deep taint chain (>3 hops) — lower confidence";
            case INTER_PROCEDURAL   -> "Taint crosses method boundaries (inter-procedural)";
        };
    }

    private static void wrapPrint(String prefix, String text, int width) {
        String[] words = text.split(" ");
        StringBuilder line = new StringBuilder();
        for (String w : words) {
            if (line.length() + w.length() + 1 > width) {
                System.out.println(prefix + line.toString().trim());
                line = new StringBuilder();
            }
            line.append(w).append(" ");
        }
        if (!line.isEmpty()) System.out.println(prefix + line.toString().trim());
    }

    private static String shortVar(String var) {
        if (var.length() > 20) return "userInput";
        return var;
    }
}