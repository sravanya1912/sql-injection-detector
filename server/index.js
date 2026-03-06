const express = require("express");//create web server
const multer = require("multer");//handle file uploads
const { exec } = require("child_process");//run external commands linke jar
const path = require("path");//builds paths
const fs = require("fs");//file operations
const cors = require("cors");//cross origin requests frontend backend communi

const app = express();
app.use(cors());
//without cors browser blocks requests
const upload = multer({ dest: "uploads/" });//uploaded file temporarily saved in here

app.post("/analyze", upload.single("file"), (req, res) => {
  if (!req.file) {
    return res.status(400).send("No file uploaded.");
  }

  const uploadedPath = req.file.path;
  const javaPath = uploadedPath + ".java";
  fs.renameSync(uploadedPath, javaPath);

  const jarPath = path.join(
    __dirname,
    "..",
    "target",
    "sql-injection-detector-1.0.0-jar-with-dependencies.jar"
  );

  const command = `java -jar "${jarPath}" "${javaPath}"`;//buildingjava command

  exec(command, (error, stdout, stderr) => {
    try { fs.unlinkSync(javaPath); } catch (_) {}

    if (error && !stdout) {
      return res.status(500).send("Error running analysis:\n" + stderr);
    }

    res.setHeader("Content-Type", "text/plain");
    res.send(stdout || stderr);
  });
});

app.use(express.static(path.join(__dirname, '..', 'frontend')));

app.listen(5000, () => {
  console.log("Backend running at http://localhost:5000");
});