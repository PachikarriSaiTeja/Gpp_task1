// src/keygen.js
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
console.log(" - keys/public.pem");
