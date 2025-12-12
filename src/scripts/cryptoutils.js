// src/crypto-utils.js
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
  return signature; // Buffer
}

export function encryptSignatureForInstructor(signatureBuffer, instructorPublicKeyPathOrPem) {
  let pub;
  try {
    if (typeof instructorPublicKeyPathOrPem === "string" && instructorPublicKeyPathOrPem.trim().startsWith("-----BEGIN")) {
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
}
