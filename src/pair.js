
const {
  default: makeWASocket,
  useMultiFileAuthState,
  DisconnectReason
} = require("@whiskeysockets/baileys");

const sodium = require("libsodium-wrappers");
const archiver = require("archiver");
const crypto = require("crypto");
const path = require("path");
const axios = require("axios");
const pino = require("pino");

const AUTH_DIR = path.join(process.cwd(), "auth_info");

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ضغط الجلسة
async function createArchive() {
  return new Promise((resolve, reject) => {
    const archive = archiver("zip", {
      zlib: { level: 9 }
    });

    const chunks = [];

    archive.on("data", chunk => chunks.push(chunk));
    archive.on("error", reject);
    archive.on("end", () =>
      resolve(Buffer.concat(chunks))
    );

    archive.directory(AUTH_DIR, false);
    archive.finalize();
  });
}

// تشفير الجلسة
function encryptSession(data) {
  const key = Buffer.from(
    required("SESSION_ENCRYPTION_KEY"),
    "base64"
  );

  if (key.length !== 32) {
    throw new Error("Encryption key must be 32 bytes");
  }

  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    key,
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(data),
    cipher.final()
  ]);

  return Buffer.concat([
    iv,
    cipher.getAuthTag(),
    encrypted
  ]).toString("base64");
}

// حفظ الجلسة في GitHub Secrets
async function saveGitHubSecret(value) {
  await sodium.ready;

  const token = required("GH_SECRETS_TOKEN");
  const repository = required("GITHUB_REPOSITORY");

  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
  };

  const base =
    `https://api.github.com/repos/${repository}/actions/secrets`;

  const response = await axios.get(
    `${base}/public-key`,
    { headers }
  );

  const publicKey = sodium.from_base64(
    response.data.key,
    sodium.base64_variants.ORIGINAL
  );

  const encryptedBytes = sodium.crypto_box_seal(
    Buffer.from(value, "utf8"),
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
      key_id: response.data.key_id
    },
    { headers }
  );

  console.log("WhatsApp session saved to GitHub Secrets.");
}

async function main() {
  const phone = required("PAIRING_PHONE").replace(/\D/g, "");

  if (!/^\d{8,15}$/.test(phone)) {
    throw new Error("Invalid phone number");
  }

  const { state, saveCreds } =
    await useMultiFileAuthState(AUTH_DIR);

  let finished = false;
  let pairingRequested = false;
  let reconnecting = false;
  let saveQueue = Promise.resolve();

  const timeout = setTimeout(() => {
    if (!finished) {
      console.error("Pairing timed out.");
      process.exit(1);
    }
  }, 4 * 60 * 1000);

  async function finishConnection(sock) {
    if (finished) return;

    finished = true;
    clearTimeout(timeout);

    try {
      await saveQueue;
      await saveCreds();

      const archive = await createArchive();
      const encrypted = encryptSession(archive);

      await saveGitHubSecret(encrypted);

      console.log("--------------------------------");
      console.log("WHATSAPP CONNECTED SUCCESSFULLY");
      console.log("SESSION SAVED SUCCESSFULLY");
      console.log("--------------------------------");

      await sock.end(undefined);
      process.exit(0);

    } catch (error) {
      console.error(
        "Session saving failed:",
        error.message
      );
      process.exit(1);
    }
  }

  async function startSocket() {
    const sock = makeWASocket({
      auth: state,
      printQRInTerminal: false,
      logger: pino({ level: "silent" })
    });

    sock.ev.on("creds.update", () => {
      saveQueue = saveQueue.then(() => saveCreds());
    });

    sock.ev.on("connection.update", async update => {
      if (
        update.qr &&
        !state.creds.registered &&
        !pairingRequested
      ) {
        pairingRequested = true;

        try {
          await delay(1000);

          const code = await sock.requestPairingCode(phone);

          console.log("--------------------------------");
          console.log("WhatsApp Pairing Code:", code);
          console.log("--------------------------------");
          console.log("Enter the code in WhatsApp.");

        } catch (error) {
          console.error(
            "Pairing code error:",
            error.message
          );
          process.exit(1);
        }
      }

      if (update.connection === "open") {
        console.log("WhatsApp connection is OPEN.");

        await finishConnection(sock);
      }

      if (update.connection === "close") {
        const code =
          update.lastDisconnect?.error?.output?.statusCode;

        console.log("Connection closed:", code);

        // 515 يعني أن واتساب يطلب إعادة الاتصال
        if (
          code === DisconnectReason.restartRequired &&
          !finished &&
          !reconnecting
        ) {
          reconnecting = true;

          try {
            await saveQueue;
            await saveCreds();

            if (!state.creds.registered) {
              throw new Error(
                "New WhatsApp credentials were not saved."
              );
            }

            console.log(
              "Pairing accepted. Restarting socket..."
            );

            await startSocket();

          } catch (error) {
            console.error(
              "Reconnect failed:",
              error.message
            );
            process.exit(1);
          }

          return;
        }

        if (!finished) {
          clearTimeout(timeout);

          if (code === DisconnectReason.loggedOut) {
            console.error("WhatsApp logged out.");
          } else {
            console.error(
              "WhatsApp connection failed:",
              code
            );
          }

          process.exit(1);
        }
      }
    });

    return sock;
  }

  await startSocket();
}

main().catch(error => {
  console.error("Fatal error:", error.message);
  process.exit(1);
});
