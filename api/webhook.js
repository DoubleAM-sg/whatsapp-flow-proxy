import crypto from "crypto";

const PRIVATE_KEY = process.env.PRIVATE_KEY?.replace(/\\n/g, "\n");

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body) : (req.body || {});

    console.log("body keys:", Object.keys(body));

    const {
      encrypted_flow_data,
      encrypted_aes_key,
      initial_vector,
    } = body;

    if (!encrypted_flow_data || !encrypted_aes_key || !initial_vector) {
      return res.status(400).send("Missing encrypted payloads");
    }

    const aesKeyCiphertext = Buffer.from(encrypted_aes_key, "base64");
    const flowCiphertext = Buffer.from(encrypted_flow_data, "base64");
    const iv = Buffer.from(initial_vector, "base64");

    console.log("decoded lengths:", {
      encrypted_aes_key: aesKeyCiphertext.length,
      encrypted_flow_data: flowCiphertext.length,
      initial_vector: iv.length,
    });

    const aesKey = crypto.privateDecrypt(
      {
        key: PRIVATE_KEY,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      aesKeyCiphertext
    );

    const authTag = flowCiphertext.subarray(flowCiphertext.length - 16);
    const ciphertext = flowCiphertext.subarray(0, flowCiphertext.length - 16);

    const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);

    const payload = JSON.parse(decrypted.toString("utf8"));
    console.log("payload:", payload);

    const encryptResponse = (obj) => {
      const responseJson = Buffer.from(JSON.stringify(obj), "utf8");

      // For data_api_version 3.0, Meta says to invert all bits of the request IV for response encryption.
      const responseIv = Buffer.from(iv.map((b) => (~b) & 0xff));

      const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
      const encrypted = Buffer.concat([
        cipher.update(responseJson),
        cipher.final(),
      ]);
      const tag = cipher.getAuthTag();

      return Buffer.concat([encrypted, tag]).toString("base64");
    };

    if (payload.action === "ping") {
      return res.status(200).send(
        encryptResponse({
          version: "3.0",
          data: { status: "active" },
        })
      );
    }

    return res.status(200).send(
      encryptResponse({
        version: "3.0",
        data: { status: "ok" },
      })
    );
  } catch (err) {
    console.error("Decryption Error:", err);
    return res.status(500).send(`Decryption failed: ${err.message}`);
  }
}
