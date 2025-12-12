# === fill-files.ps1 ===
# Writes all project files into C:\Gpp_task structure (overwrites existing)

param()

# Helper to write files and create directories
function Write-File {
    param($Path, $Content)
    $dir = Split-Path $Path -Parent
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $Content | Out-File -FilePath $Path -Encoding UTF8 -Force
    Write-Host "Wrote $Path"
}

# Root files
Write-File -Path ".\package.json" -Content '{
  "name": "pki-2fa-microservice",
  "version": "1.0.0",
  "type": "module",
  "description": "PKI + TOTP 2FA microservice for Partnr GPP task",
  "main": "src/server.js",
  "scripts": {
    "start": "node src/server.js",
    "dev": "NODE_ENV=development node src/server.js",
    "keygen": "node src/keygen.js"
  },
  "author": "You",
  "license": "MIT",
  "dependencies": {
    "express": "^4.18.2"
  }
}'

Write-File -Path ".\.dockerignore" -Content 'node_modules
npm-debug.log
keys/private.pem
.DS_Store
.git
'

Write-File -Path ".\Dockerfile" -Content '# Stage 1: builder
FROM node:18-alpine AS builder
WORKDIR /build
RUN apk add --no-cache python3 make g++
COPY package*.json ./
RUN npm ci
COPY . .
RUN node src/keygen.js || true
FROM node:18-alpine
ENV NODE_ENV=production TZ=UTC
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY --from=builder /build/src ./src
COPY --from=builder /build/keys ./keys
COPY --from=builder /build/cron ./cron
COPY --from=builder /build/entrypoint.sh ./entrypoint.sh
RUN mkdir -p /data /cron && chown -R node:node /data /cron /app
RUN apk add --no-cache tzdata
RUN chmod +x /app/entrypoint.sh
EXPOSE 8080
USER node
ENTRYPOINT ["/app/entrypoint.sh"]
'

Write-File -Path ".\entrypoint.sh" -Content '#!/bin/sh
set -e
CRON_DIR=${CRON_DIR:-/cron}
if [ -f "$CRON_DIR/mycron" ]; then
  crontab "$CRON_DIR/mycron"
  echo "Installed crontab from $CRON_DIR/mycron"
else
  echo "No cron file at $CRON_DIR/mycron"
fi
mkdir -p /data
crond -b -l 8
exec node src/server.js
'

Write-File -Path ".\README.md" -Content '# PKI 2FA Microservice (Partnr GPP)
Quick setup (local)
1. Ensure Node 18+ is installed.
2. In project root:
   npm ci
   npm run keygen
   npm start
Endpoints:
- POST /decrypt-seed { "encrypted": "<base64>" }
- GET /generate-2fa -> { code, valid_for }
- POST /verify-2fa { "code": "123456" }
Docker:
docker build -t gpp-microservice:latest .
docker run -d --name gpp2fa -p 8080:8080 -v "C:\Gpp_task\data:/data" -v "C:\Gpp_task\cron:/cron" -v "C:\Gpp_task\keys:/app/keys" gpp-microservice:latest
Cron:
cron/mycron runs every minute and executes src/scripts/cronTask.js
'

# cron file
Write-File -Path ".\cron\mycron" -Content '* * * * * /usr/bin/node /app/src/scripts/cronTask.js >> /var/log/cron.log 2>&1'

# src files
Write-File -Path ".\src\keygen.js" -Content '// src/keygen.js
import { generateKeyPairSync } from "crypto";
import fs from "fs";
import path from "path";
const outDir = path.resolve("./keys");
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
const { publicKey, privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 4096,
  publicExponent: 0x10001,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" }
});
fs.writeFileSync(path.join(outDir, "private.pem"), privateKey, { mode: 0o600 });
fs.writeFileSync(path.join(outDir, "public.pem"), publicKey, { mode: 0o644 });
console.log("Generated keys in ./keys:");
console.log(" - keys/private.pem");
console.log(" - keys/public.pem");'

Write-File -Path ".\src\crypto-utils.js" -Content '// src/crypto-utils.js
import fs from "fs";
import { constants, privateDecrypt, publicEncrypt, sign } from "crypto";
export function decryptSeedBase64(encryptedBase64, privateKeyPath) {
  try {
    const privateKeyPem = fs.readFileSync(privateKeyPath, "utf8");
    const encrypted = Buffer.from(encryptedBase64, "base64");
    const decrypted = privateDecrypt(
      {
        key: privateKeyPem,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
      },
      encrypted
    );
    return decrypted.toString("utf8");
  } catch (err) {
    throw new Error("Decryption failed: " + err.message);
  }
}
export function signCommitHashHex(commitHashHex, privateKeyPath) {
  const priv = fs.readFileSync(privateKeyPath, "utf8");
  const commitBuffer = Buffer.from(commitHashHex, "hex");
  const signature = sign(
    "sha256",
    commitBuffer,
    {
      key: priv,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: constants.RSA_PSS_SALTLEN_MAX_SIGN
    }
  );
  return signature;
}
export function encryptSignatureForInstructor(signatureBuffer, instructorPublicKeyPathOrPem) {
  let pub;
  try {
    if (instructorPublicKeyPathOrPem.trim().startsWith("-----BEGIN")) {
      pub = instructorPublicKeyPathOrPem;
    } else {
      pub = fs.readFileSync(instructorPublicKeyPathOrPem, "utf8");
    }
  } catch (err) {
    throw new Error("Instructor public key not found: " + err.message);
  }
  const encrypted = publicEncrypt(
    {
      key: pub,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256"
    },
    signatureBuffer
  );
  return encrypted.toString("base64");
}'

Write-File -Path ".\src\totp.js" -Content '// src/totp.js
import crypto from "crypto";
export function base32EncodeNoPad(buf) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let output = "";
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }
  return output;
}
export function hex64ToBase32(hex64) {
  if (typeof hex64 !== "string" || hex64.length !== 64) {
    throw new Error("Seed must be a 64-character hex string");
  }
  const buf = Buffer.from(hex64, "hex");
  return base32EncodeNoPad(buf);
}
function hotp(key, counter, digits = 6) {
  const buf = Buffer.alloc(8);
  for (let i = 0; i < 8; i++) buf[7 - i] = counter & 0xff, counter = counter >>> 8;
  const hmac = crypto.createHmac("sha1", key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % (10 ** digits);
  return code.toString().padStart(digits, "0");
}
export function generateTOTP(secretBase32, timeMs = Date.now()) {
  const key = base32Decode(secretBase32);
  const period = 30;
  const counter = Math.floor(Math.floor(timeMs / 1000) / period);
  const code = hotp(key, counter, 6);
  const secondsUsed = Math.floor((timeMs / 1000) % period);
  const valid_for = period - secondsUsed;
  return { code, valid_for };
}
export function verifyTOTP(secretBase32, code, timeMs = Date.now()) {
  const key = base32Decode(secretBase32);
  const period = 30;
  const counter = Math.floor(Math.floor(timeMs / 1000) / period);
  for (let d = -1; d <= 1; d++) {
    if (hotp(key, counter + d, 6) === code) return true;
  }
  return false;
}
export function base32Decode(str) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = str.replace(/=+$/g, "").toUpperCase();
  const bytes = [];
  let bits = 0;
  let value = 0;
  for (let i = 0; i < clean.length; i++) {
    const idx = alphabet.indexOf(clean[i]);
    if (idx === -1) throw new Error("Invalid base32 character");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}'

Write-File -Path ".\src\server.js" -Content '// src/server.js
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
'

Write-File -Path ".\src\scripts\cronTask.js" -Content '// src/scripts/cronTask.js
import fs from "fs";
import path from "path";
import { hex64ToBase32, generateTOTP } from "../totp.js";
const DATA_DIR = process.env.DATA_DIR || "/data";
const SEED_PATH = path.join(DATA_DIR, "seed.txt");
const LOG_PATH = path.join(DATA_DIR, "totp.log");
function run() {
  try {
    if (!fs.existsSync(SEED_PATH)) {
      fs.appendFileSync(LOG_PATH, `${new Date().toISOString()} - seed missing\n`);
      return;
    }
    const hexSeed = fs.readFileSync(SEED_PATH, "utf8").trim();
    const base32 = hex64ToBase32(hexSeed);
    const { code, valid_for } = generateTOTP(base32, Date.now());
    const line = `${new Date().toISOString()} - code=${code} valid_for=${valid_for}\n`;
    fs.appendFileSync(LOG_PATH, line);
  } catch (err) {
    fs.appendFileSync(LOG_PATH, `${new Date().toISOString()} - error: ${err.message}\n`);
  }
}
run();
'

Write-File -Path ".\src\scripts\installcron.sh" -Content '#!/bin/sh
if [ -f /cron/mycron ]; then
  crontab /cron/mycron
  echo "installed"
else
  echo "no cron file"
fi
'

Write-Host "All files written. You can now git add, commit, and push."
