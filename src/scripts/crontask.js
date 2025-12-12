// src/scripts/cronTask.js
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

