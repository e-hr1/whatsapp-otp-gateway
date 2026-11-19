

const {
  default: makeWASocket,
  useMultiFileAuthState,
  DisconnectReason
} = require("@whiskeysockets/baileys");

const sodium = require("libsodium-wrappers");
const archiver = require("archiver");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const axios = require("axios");

const AUTH_DIR = path.join(process.cwd(), "auth_info");

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function createArchive() {
  return new Promise((resolve, reject) => {
    const archive = archiver("zip", { zlib: { level: 9 } });
    const chunks = [];

    archive.on("data", chunk => chunks.push(chunk));
    archive.on("error", reject);
    archive.on("end", () => resolve(Buffer.concat(chunks)));

    archive.directory(AUTH_DIR, false);
    archive.finalize();
  });
}

function encryptSession(data) {
  const key = Buffer.from(required("SESSION_ENCRYPTION_KEY"), "base64");

  if (key.length !== 32) {
    throw new Error("SESSION_ENCRYPTION_KEY must be 32 bytes");
  }

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  const encrypted = Buffer.concat([
    cipher.update(data),
    cipher.final()
  ]);

  const tag = cipher.getAuthTag();

  return Buffer.concat([iv, tag, encrypted]).toString("base64");
}

async function saveGitHubSecret(secretValue) {
  await sodium.ready;

  const token = required("GH_SECRETS_TOKEN");
  const repository = required("GITHUB_REPOSITORY");

  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
  };

  const base = `https://api.github.com/repos/${repository}/actions/secrets`;

  const keyResponse = await axios.get(`${base}/public-key`, { headers });

  const publicKey = sodium.from_base64(
    keyResponse.data.key,
    sodium.base64_variants.ORIGINAL
  );

  const encryptedBytes = sodium.crypto_box_seal(
    Buffer.from(secretValue, "utf8"),
    publicKey
  );

  const encryptedValue = sodium.to_base64(
    encryptedBytes,
    sodium.base64_variants.ORIGINAL
  );

  await axios.put(
    `${base}/WHATSAPP_SESSION`,
    {
      encrypted_value: encryptedValue,
      key_id: keyResponse.data.key_id
    },
    { headers }
  );

  console.log("Encrypted WhatsApp session saved to GitHub Secrets.");
}

async function main() {
  const phone = required("PAIRING_PHONE").replace(/\D/g, "");

  if (!/^\d{8,15}$/.test(phone)) {
    throw new Error("Enter the phone number with country code, digits only.");
  }

  const { state, saveCreds } = await useMultiFileAuthState(AUTH_DIR);

  const sock = makeWASocket({
    auth: state,
    printQRInTerminal: false,
    logger: require("pino")({ level: "silent" }),
    browser: ["OTP Gateway", "Chrome", "1.0.0"]
  });

  sock.ev.on("creds.update", saveCreds);

  let pairingRequested = false;
  let finished = false;

  const timeout = setTimeout(() => {
    if (!finished) {
      console.error("Pairing timed out.");
      process.exit(1);
    }
  }, 4 * 60 * 1000);

  sock.ev.on("connection.update", async update => {
    if (
      update.connection === "connecting" &&
      !state.creds.registered &&
      !pairingRequested
    ) {
      pairingRequested = true;

      try {
        await delay(2500);
        const code = await sock.requestPairingCode(phone);
        console.log("Your WhatsApp Pairing Code:", code);
        console.log("Enter this code in WhatsApp Linked Devices.");
      } catch (error) {
        console.error("Could not request pairing code:", error.message);
        process.exit(1);
      }
    }

    if (update.connection === "open" && !finished) {
      finished = true;
      clearTimeout(timeout);

      try {
        await delay(3000);
        await saveCreds();

        const archive = await createArchive();
        const encrypted = encryptSession(archive);

        await saveGitHubSecret(encrypted);

        console.log("WhatsApp pairing completed successfully.");
        await sock.end(undefined);
        process.exit(0);
      } catch (error) {
        console.error("Session saving failed:", error.message);
        process.exit(1);
      }
    }

    if (
      update.connection === "close" &&
      !finished
    ) {
      const code = update.lastDisconnect?.error?.output?.statusCode;

      if (code === DisconnectReason.loggedOut) {
        console.error("WhatsApp session was logged out.");
      } else {
        console.error("WhatsApp connection closed.");
      }

      process.exit(1);
    }
  });
}

main().catch(error => {
  console.error(error.message);
  process.exit(1);
});
