const express = require("express");
const multer  = require("multer");
const { exec } = require("child_process");
const path    = require("path");
const fs      = require("fs");
const cors    = require("cors");

const app = express();
app.use(cors());

// ── Multer: accept .java uploads ────────────────────────────
const upload = multer({
  dest: "uploads/",
  fileFilter: (req, file, cb) => {
    // Accept any file — we rename to .java ourselves
    cb(null, true);
  },
  limits: { fileSize: 5 * 1024 * 1024 } // 5 MB max
});

// ── Ensure uploads directory exists ─────────────────────────
if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");

// ── POST /analyze ────────────────────────────────────────────
app.post("/analyze", upload.single("file"), (req, res) => {

  if (!req.file) {
    return res.status(400).send("No file uploaded.");
  }

  const uploadedPath = req.file.path;

  // Ensure .java extension — JavaParser requires it
  const safeName = req.file.originalname.replace(/[^a-zA-Z0-9_.\-]/g, "_");
  const javaName = safeName.endsWith(".java") ? safeName : safeName + ".java";
  const javaPath = path.join("uploads", javaName + "_" + Date.now() + ".java");

  try {
    fs.renameSync(uploadedPath, javaPath);
  } catch (e) {
    return res.status(500).send("Failed to prepare uploaded file:\n" + e.message);
  }

  // ── Locate the analysis JAR ──────────────────────────────
  const jarPath = path.join(
    __dirname, "..", "target",
    "sql-injection-detector-1.0.0-jar-with-dependencies.jar"
  );

  if (!fs.existsSync(jarPath)) {
    safeClean(javaPath);
    return res.status(500).send(
      "JAR not found at:\n  " + jarPath +
      "\n\nBuild with:\n  mvn package -q\n" +
      "or\n  mvn assembly:single"
    );
  }

  // ── Validate Java is installed ───────────────────────────
  exec("java -version 2>&1", (jErr) => {
    if (jErr) {
      safeClean(javaPath);
      return res.status(500).send(
        "Java runtime not found.\n\nInstall JDK 11+ and ensure 'java' is on your PATH."
      );
    }

    // ── Run the detector ───────────────────────────────────
    const command = `java -jar "${jarPath}" "${javaPath}"`;
    const opts = {
      timeout: 30_000,   // 30-second safety timeout
      maxBuffer: 2 * 1024 * 1024
    };

    exec(command, opts, (error, stdout, stderr) => {
      safeClean(javaPath);

      // A non-zero exit code is acceptable when vulnerabilities are found;
      // only fail if there is no stdout to return.
      if (error && !stdout && !stdout?.trim()) {
        const msg = [
          "Analysis failed.",
          "",
          "Exit code: " + error.code,
          "",
          "STDERR:",
          stderr || "(none)"
        ].join("\n");
        return res.status(500).send(msg);
      }

      const output = stdout || stderr || "(no output)";
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.send(output);
    });
  });
});

// ── Static frontend ──────────────────────────────────────────
const frontendDir = path.join(__dirname, "..", "frontend");
if (fs.existsSync(frontendDir)) {
  app.use(express.static(frontendDir));
} else {
  // Fallback: serve the frontend from parent directory
  app.use(express.static(path.join(__dirname, "..")));
}

// ── Cleanup helper ───────────────────────────────────────────
function safeClean(filePath) {
  try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch (_) {}
}

// ── Health check ─────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok", version: "2.0.0" });
});

// ── Start ─────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log("╔══════════════════════════════════════════════╗");
  console.log("║  SQL Injection Detector Backend  v2.0        ║");
  console.log("╠══════════════════════════════════════════════╣");
  console.log("║  http://localhost:" + PORT + "                       ║");
  console.log("╚══════════════════════════════════════════════╝");
});