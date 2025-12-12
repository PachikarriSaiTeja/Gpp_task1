// src/totp.js
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
}
