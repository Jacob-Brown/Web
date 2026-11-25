const { spawn } = require("child_process");
const path = require("path");
const express = require("express");
const cookieParser = require("cookie-parser");
require("dotenv").config();

const ROOT_DIR = path.resolve(__dirname, "..");
const PYTHON_BIN = process.env.PYTHON_BIN || "python3";
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "change-me-in-production";
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || "";
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || "";
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || "";
const SITE_URL = (process.env.SITE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const MAX_SOURCE_BYTES = Number(process.env.MAX_SOURCE_BYTES || 200000);

const app = express();
app.use(express.json({ limit: "10mb" }));
app.use(cookieParser(SESSION_SECRET));
app.use(express.static(path.join(__dirname, "static")));

const presets = [
  "minimum", "medium", "compact", "balanced", "strong", "maximum",
  "all", "ultra", "auto", "debug", "hazma",
];

function sessionUser(req) {
  const token = req.signedCookies?.voltagesec_session;
  if (!token) return null;
  try {
    return JSON.parse(Buffer.from(token, "base64").toString("utf8"));
  } catch {
    return null;
  }
}

function setSession(res, user) {
  const value = Buffer.from(JSON.stringify(user)).toString("base64");
  res.cookie("voltagesec_session", value, {
    maxAge: 1000 * 60 * 60 * 24 * 14,
    httpOnly: true,
    sameSite: "lax",
    secure: SITE_URL.startsWith("https://"),
    signed: true,
  });
}

function runPythonObfuscator(payload) {
  return new Promise((resolve, reject) => {
    const child = spawn(PYTHON_BIN, [path.join(__dirname, "obfuscate.py")], {
      cwd: ROOT_DIR,
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });

    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(stderr.trim() || `Python obfuscator exited with code ${code}`));
        return;
      }
      try {
        resolve(JSON.parse(stdout));
      } catch (error) {
        reject(new Error(`Invalid obfuscator response: ${error.message}\n${stdout}\n${stderr}`));
      }
    });

    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
  });
}

app.get("/health", (_req, res) => {
  res.json({ status: "ok", version: "1.0.0" });
});

app.get("/api/me", (req, res) => {
  const user = sessionUser(req);
  if (!user) return res.status(401).json({ detail: "Not signed in." });
  res.json(user);
});

app.get("/api/presets", (_req, res) => {
  res.json({ presets });
});

app.post("/api/obfuscate", async (req, res) => {
  const user = sessionUser(req);
  if (!user) return res.status(401).json({ detail: "Sign in with Discord first." });

  try {
    const result = await runPythonObfuscator({
      source: req.body?.source || "",
      preset: req.body?.preset || "maximum",
      seed: req.body?.seed || null,
      compression: req.body?.compression || null,
      anti_tamper: req.body?.anti_tamper ?? null,
      discord_invite: req.body?.discord_invite || null,
      inject_discord_invite: Boolean(req.body?.inject_discord_invite),
      max_source_bytes: MAX_SOURCE_BYTES,
    });
    result.user = user.global_name || user.username;
    res.json(result);
  } catch (error) {
    res.status(422).json({ detail: error.message });
  }
});

app.get("/auth/discord", (req, res) => {
  if (!DISCORD_CLIENT_ID || !DISCORD_REDIRECT_URI) {
    return res.status(500).send("Discord OAuth is not configured.");
  }
  const state = Math.random().toString(36).slice(2) + Date.now().toString(36);
  res.cookie("vs_oauth_state", state, { maxAge: 600000, httpOnly: true, sameSite: "lax" });
  const url = new URL("https://discord.com/oauth2/authorize");
  url.searchParams.set("client_id", DISCORD_CLIENT_ID);
  url.searchParams.set("redirect_uri", DISCORD_REDIRECT_URI);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "identify");
  url.searchParams.set("state", state);
  res.redirect(url.toString());
});

app.get("/auth/discord/callback", async (req, res) => {
  const { code, state } = req.query;
  const expectedState = req.cookies?.vs_oauth_state;
  if (!code || !state || !expectedState || expectedState !== state) {
    return res.status(400).send("Invalid OAuth state.");
  }

  try {
    const tokenResponse = await fetch("https://discord.com/api/v10/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code: String(code),
        redirect_uri: DISCORD_REDIRECT_URI,
      }),
    });
    if (!tokenResponse.ok) throw new Error(await tokenResponse.text());
    const tokenData = await tokenResponse.json();

    const userResponse = await fetch("https://discord.com/api/v10/users/@me", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    if (!userResponse.ok) throw new Error(await userResponse.text());
    const user = await userResponse.json();

    setSession(res, {
      discord_id: String(user.id),
      username: user.username,
      global_name: user.global_name || user.username,
      avatar: user.avatar,
      signed_in_at: Date.now(),
    });
    res.clearCookie("vs_oauth_state");
    res.redirect("/");
  } catch (error) {
    res.status(400).send(`Discord authentication failed: ${error.message}`);
  }
});

app.get("/auth/logout", (_req, res) => {
  res.clearCookie("voltagesec_session");
  res.redirect("/");
});

app.get("*", (_req, res) => {
  res.sendFile(path.join(__dirname, "static", "index.html"));
});

app.listen(PORT, () => {
  console.log(`VoltageSec website listening on port ${PORT}`);
});
