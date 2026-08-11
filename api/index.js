import express from "express";
import { v4 as uuidv4 } from "uuid";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.urlencoded({ extended: true })); // penting! ChatGPT kirim form-urlencoded
app.use(express.json());

// ====================== KONFIGURASI ======================
const CLIENT_ID = process.env.CLIENT_ID || "gpt-client-123";
const CLIENT_SECRET = process.env.CLIENT_SECRET || "rahasia-super-aman-12345";
const ACCESS_TOKEN_EXPIRES = 3600; // 1 jam
const REFRESH_TOKEN_EXPIRES = 30 * 24 * 3600; // 30 hari

// Storage sederhana (ganti dengan database di production!)
const codes = new Map(); // authorization code → data
const tokens = new Map(); // refresh_token → data
const accessTokens = new Map(); // access_token → data

// ====================== 1. AUTHORIZE ======================
app.get("/oauth/authorize", (req, res) => {
  const { client_id, redirect_uri, state, scope, response_type } = req.query;

  if (client_id !== CLIENT_ID) {
    return res.status(400).send("Invalid client_id");
  }

  if (response_type !== "code") {
    return res.status(400).send("Only response_type=code is supported");
  }

  // Di production: tampilkan halaman login yang beneran
  // Untuk demo, kita auto-approve
  const code = uuidv4();
  codes.set(code, {
    client_id,
    redirect_uri,
    scope: scope || "",
    expires: Date.now() + 5 * 60 * 1000, // code berlaku 5 menit
  });

  // Redirect kembali ke ChatGPT
  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set("code", code);
  if (state) redirectUrl.searchParams.set("state", state);

  res.redirect(redirectUrl.toString());
});

// ====================== 2. TOKEN (code + refresh) ======================
app.post("/oauth/token", (req, res) => {
  const {
    grant_type,
    client_id,
    client_secret,
    code,
    redirect_uri,
    refresh_token,
  } = req.body;

  // Validasi client
  if (client_id !== CLIENT_ID || client_secret !== CLIENT_SECRET) {
    return res.status(401).json({ error: "invalid_client" });
  }

  // ---- Authorization Code Flow ----
  if (grant_type === "authorization_code") {
    const stored = codes.get(code);
    if (!stored || stored.expires < Date.now()) {
      return res.status(400).json({ error: "invalid_grant" });
    }

    // Hapus code setelah dipakai (one-time)
    codes.delete(code);

    const access_token = "at_" + uuidv4();
    const refresh_token = "rt_" + uuidv4();

    accessTokens.set(access_token, {
      client_id,
      scope: stored.scope,
      expires: Date.now() + ACCESS_TOKEN_EXPIRES * 1000,
    });

    tokens.set(refresh_token, {
      client_id,
      scope: stored.scope,
      expires: Date.now() + REFRESH_TOKEN_EXPIRES * 1000,
    });

    return res.json({
      access_token,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_EXPIRES,
      refresh_token,
    });
  }

  // ---- Refresh Token Flow ----
  if (grant_type === "refresh_token") {
    const stored = tokens.get(refresh_token);
    if (!stored || stored.expires < Date.now()) {
      return res.status(401).json({ error: "invalid_grant" });
    }

    // Optional: rotating refresh token (lebih aman)
    tokens.delete(refresh_token);

    const new_access_token = "at_" + uuidv4();
    const new_refresh_token = "rt_" + uuidv4();

    accessTokens.set(new_access_token, {
      client_id,
      scope: stored.scope,
      expires: Date.now() + ACCESS_TOKEN_EXPIRES * 1000,
    });

    tokens.set(new_refresh_token, {
      client_id,
      scope: stored.scope,
      expires: Date.now() + REFRESH_TOKEN_EXPIRES * 1000,
    });

    return res.json({
      access_token: new_access_token,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_EXPIRES,
      refresh_token: new_refresh_token,
    });
  }

  return res.status(400).json({ error: "unsupported_grant_type" });
});

// ====================== Endpoint untuk test token ======================
app.get("/me", (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.replace("Bearer ", "");

  const data = accessTokens.get(token);
  if (!data || data.expires < Date.now()) {
    return res.status(401).json({ error: "invalid_token" });
  }

  res.json({
    message: "Token valid!",
    client_id: data.client_id,
    scope: data.scope,
  });
});

app.get("/privacy", (req, res) => {
  res.send(`
    <html>
      <head><title>Privacy Policy</title></head>
      <body style="font-family: sans-serif; max-width: 700px; margin: 40px auto; padding: 20px;">
        <h1>Privacy Policy</h1>
        <p>This OAuth server is used only for authentication purposes with ChatGPT Actions.</p>
        <p>We do not collect, store, or share any personal data beyond what is necessary for the OAuth flow.</p>
        <p>Access tokens and refresh tokens are stored temporarily and used solely to authenticate API requests.</p>
        <p>Last updated: August 2026</p>
      </body>
    </html>
  `);
});

// Health check
app.get("/", (req, res) => {
  res.json({
    status: "OAuth Server for GPT Actions is running",
    endpoints: {
      authorize: "/oauth/authorize",
      token: "/oauth/token",
    },
  });
});

// Untuk local development
if (process.env.NODE_ENV !== "production") {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`OAuth server running on http://localhost:${PORT}`);
  });
}

export default app;
