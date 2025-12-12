// src/server.js
import express from "express";
import fs from "fs";
import path from "path";
import { decryptSeedBase64, signCommitHashHex, encryptSignatureForInstructor } from "./crypto-utils.js";
import { hex64ToBase32, generateTOTP, verifyTOTP } from "./totp.js";
const app = express();
app.use(express.json());
const DATA_DIR = process.env.DATA_DIR || "/data";
const SEED_PATH = path.join(DATA_DIR, "seed.txt");
const MY_PRIVATE_KEY = process.env.MY_PRIVATE_KEY || "./keys/private.pem";
const INSTRUCTOR_PUBLIC_KEY = process.env.INSTRUCTOR_PUBLIC_KEY || "./keys/instructor_public.pem";
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
app.post("/decrypt-seed", (req, res) => {
  try {
    const encrypted = req.body && req.body.encrypted;
    if (!encrypted) return res.status(400).json({ error: "Missing encrypted field" });
    const decrypted = decryptSeedBase64(encrypted, MY_PRIVATE_KEY);
    if (!/^[0-9a-fA-F]{64}$/.test(decrypted)) {
      return res.status(500).json({ error: "Decryption failed (invalid seed format)" });
    }
    fs.writeFileSync(SEED_PATH, decrypted, { mode: 0o600 });
    return res.json({ status: "ok" });
  } catch (err) {
    console.error("decrypt-seed error:", err);
    return res.status(500).json({ error: "Decryption failed" });
  }
});
app.get("/generate-2fa", (req, res) => {
  try {
    if (!fs.existsSync(SEED_PATH)) return res.status(500).json({ error: "Seed unavailable" });
    const hexSeed = fs.readFileSync(SEED_PATH, "utf8").trim();
    const base32 = hex64ToBase32(hexSeed);
    const { code, valid_for } = generateTOTP(base32, Date.now());
    return res.json({ code, valid_for });
  } catch (err) {
    console.error("generate-2fa error:", err);
    return res.status(500).json({ error: "Failed to generate 2FA" });
  }
});
app.post("/verify-2fa", (req, res) => {
  try {
    const code = (req.body && req.body.code) || "";
    if (!code) return res.status(400).json({ error: "Missing code" });
    if (!fs.existsSync(SEED_PATH)) return res.status(500).json({ error: "Seed unavailable" });
    const hexSeed = fs.readFileSync(SEED_PATH, "utf8").trim();
    const base32 = hex64ToBase32(hexSeed);
    const valid = verifyTOTP(base32, code, Date.now());
    return res.json({ valid });
  } catch (err) {
    console.error("verify-2fa error:", err);
    return res.status(500).json({ error: "Verification failed" });
  }
});
app.post("/sign-commit", (req, res) => {
  try {
    const commitHash = req.body && req.body.commit_hash;
    if (!commitHash || !/^[0-9a-fA-F]+$/.test(commitHash)) {
      return res.status(400).json({ error: "Missing/invalid commit_hash" });
    }
    const signature = signCommitHashHex(commitHash, MY_PRIVATE_KEY);
    const encrypted = encryptSignatureForInstructor(signature, INSTRUCTOR_PUBLIC_KEY);
    return res.json({ encrypted_signature: encrypted });
  } catch (err) {
    console.error("sign-commit error:", err);
    return res.status(500).json({ error: "Signing failed" });
  }
});
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server listening on :${PORT}`);
});

