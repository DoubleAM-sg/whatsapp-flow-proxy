import crypto from "crypto";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }

  try {
    const PRIVATE_KEY = process.env.PRIVATE_KEY;

    const {
      encrypted_flow_data,
      encrypted_aes_key,
      initial_vector,
    } = req.body || {};

    if (!encrypted_flow_data || !encrypted_aes_key || !initial_vector) {
      return res.status(400).send("Missing encrypted payloads");
    }

    // 1) RSA decrypt the AES key
    const aesKey = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(encrypted_aes_key, "base64")
    );

    // 2) AES-GCM decrypt the flow payload
    const iv = Buffer.from(initial_vector, "base64");
    const encryptedBytes = Buffer.from(encrypted_flow_data, "base64");

    const authTag = encryptedBytes.subarray(encryptedBytes.length - 16);
    const ciphertext = encryptedBytes.subarray(0, encryptedBytes.length - 16);

    const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);

    const payload = JSON.parse(decrypted.toString("utf8"));

    // helper to encrypt all responses back to Meta
    const encryptResponse = (obj) => {
      const json = JSON.stringify(obj);

      const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, iv);
      const encrypted = Buffer.concat([
        cipher.update(json, "utf8"),
        cipher.final(),
      ]);

      const tag = cipher.getAuthTag();
      return Buffer.concat([encrypted, tag]).toString("base64");
    };

    // 3) Health check
    if (payload.action === "ping") {
      const response = {
        version: "3.0",
        data: {
          status: "active",
        },
      };

      return res.status(200).send(encryptResponse(response));
    }

    // 4) Real request handling
    console.log("Decrypted payload:", payload);

    // send to Make / GHL here if needed

    const response = {
      version: "3.0",
      data: {
        status: "ok",
      },
    };

    return res.status(200).send(encryptResponse(response));
  } catch (err) {
    console.error("Decryption Error:", err);
    return res.status(500).send(`Decryption failed: ${err.message}`);
  }
}
