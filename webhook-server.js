const express = require("express");
const crypto = require("node:crypto");
const { exec } = require("node:child_process");
const path = require("path");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

// Validate webhook secret is set
if (!WEBHOOK_SECRET) {
  console.error("Error: WEBHOOK_SECRET environment variable not set");
  process.exit(1);
}

// Use raw body for signature verification
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);

// Helper function to verify signature
function verifySignature(req) {
  const signature = req.headers["x-hub-signature-256"];
  if (!signature) return false;

  const hmac = crypto.createHmac("sha256", WEBHOOK_SECRET);
  hmac.update(req.rawBody);
  const digest = "sha256=" + hmac.digest("hex");

  try {
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest));
  } catch (error) {
    console.error("Signature verification error:", error);
    return false;
  }
}

app.post("/webhook", (req, res) => {
  // Verify the payload came from GitHub
  if (!verifySignature(req)) {
    console.error("Invalid signature or missing webhook secret");
    return res.status(403).send("Forbidden");
  }

  // Check the event type
  const event = req.headers["x-github-event"];
  if (event !== "push") {
    console.log(`Received ${event} event, ignoring`);
    return res.status(200).send(`Ignoring ${event} event`);
  }

  // Optional: Filter by branch (e.g., only deploy on main/master)
  const payload = req.body;
  const branch = payload.ref.replace("refs/heads/", "");
  const repository = payload.repository?.full_name || "unknown";

  console.log(`Push event received for ${repository} on branch ${branch}`);

  // Acknowledge receipt before starting deployment
  res.status(202).send("Deployment queued");

  console.log("Starting deployment process...");

  // Execute the deployment script with relative path
  const scriptPath = path.join(__dirname, "deploy.sh");
  console.log(`Running deployment script: ${scriptPath}`);

  exec(scriptPath, (error, stdout, stderr) => {
    if (error) {
      console.error(`Deployment error: ${error.message}`);
      return;
    }
    if (stderr) {
      console.error(`Deployment stderr: ${stderr}`);
    }
    console.log(`Deployment completed successfully:`);
    console.log(stdout);
  });
});

// Add a health check endpoint
app.get("/health", (req, res) => {
  res.status(200).send("OK");
});

app.listen(PORT, () => {
  console.log(`Webhook listener running on port ${PORT}`);
});
