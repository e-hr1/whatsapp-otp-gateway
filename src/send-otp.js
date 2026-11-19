const {
  default: makeWASocket,
  useMultiFileAuthState
} = require("@whiskeysockets/baileys");

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");
const pino = require("pino");

const AUTH_DIR = path.join(process.cwd(), "auth_info");

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}

function restoreSession() {
  const key = Buffer.from(
    required("SESSION_ENCRYPTION_KEY"),
    "base64"
  );

  if (key.length !== 32) {
    throw new Error("Invalid encryption key");
  }

  const encrypted = Buffer.from(
    required("WHATSAPP_SESSION"),
    "base64"
  );

  const iv = encrypted.subarray(0, 12);
  const tag = encrypted.subarray(12, 28);
  const data = encrypted.subarray(28);

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    iv
  );

  decipher.setAuthTag(tag);

  return Buffer.concat([
    decipher.update(data),
    decipher.final()
  ]);
}

async function main() {
  const phone = required("PHONE").replace(/\D/g, "");

  if (!/^\d{8,15}$/.test(phone)) {
    throw new Error("Invalid phone number");
  }

  // استعادة الجلسة
  const zipData = restoreSession();
  const tempZip = path.join(os.tmpdir(), "whatsapp-session.zip");

  fs.writeFileSync(tempZip, zipData);
  fs.mkdirSync(AUTH_DIR, { recursive: true });

  execFileSync("unzip", [
    "-q",
    "-o",
    tempZip,
    "-d",
    AUTH_DIR
  ]);

  fs.unlinkSync(tempZip);

  const { state, saveCreds } =
    await useMultiFileAuthState(AUTH_DIR);

  if (!state.creds.registered) {
    throw new Error("WhatsApp session is not registered");
  }

  const otp = crypto.randomInt(100000, 1000000).toString();

  const sock = makeWASocket({
    auth: state,
    logger: pino({ level: "silent" }),
    printQRInTerminal: false
  });

  sock.ev.on("creds.update", saveCreds);

  const timeout = setTimeout(() => {
    console.error("WhatsApp connection timed out");
    sock.end(undefined);
    process.exit(1);
  }, 90000);

  sock.ev.on("connection.update", async update => {
    if (update.connection === "open") {
      try {
        await sock.sendMessage(`${phone}@s.whatsapp.net`, {
          text:
            `رمز التحقق الخاص بك هو: ${otp}\n\n` +
            `لا تشارك هذا الرمز مع أي شخص.`
        });

        console.log("OTP message sent successfully.");

        clearTimeout(timeout);
        sock.end(undefined);
        process.exit(0);

      } catch (error) {
        console.error("Message sending failed:", error.message);
        clearTimeout(timeout);
        sock.end(undefined);
        process.exit(1);
      }
    }

    if (update.connection === "close") {
      console.error("WhatsApp connection closed.");
      clearTimeout(timeout);
      process.exit(1);
    }
  });
}

main().catch(error => {
  console.error("Error:", error.message);
  process.exit(1);
});
