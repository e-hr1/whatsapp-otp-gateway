
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
  if (!value) {
    throw new Error(`Missing ${name}`);
  }
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

  if (encrypted.length < 29) {
    throw new Error("Invalid encrypted session");
  }

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

  console.log("Restoring WhatsApp session...");

  const zipData = restoreSession();

  const tempZip = path.join(
    os.tmpdir(),
    "whatsapp-session.zip"
  );

  fs.writeFileSync(tempZip, zipData);

  fs.mkdirSync(AUTH_DIR, {
    recursive: true
  });

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

  const otp = crypto
    .randomInt(100000, 1000000)
    .toString();

  console.log("Connecting to WhatsApp...");

  const sock = makeWASocket({
    auth: state,
    logger: pino({ level: "silent" }),
    printQRInTerminal: false
  });

  sock.ev.on("creds.update", saveCreds);

  let messageSent = false;
  let finished = false;

  const timeout = setTimeout(() => {
    if (finished) return;

    finished = true;

    console.error("WhatsApp connection timed out.");

    sock.end(undefined);
    process.exit(1);
  }, 90000);

  sock.ev.on("connection.update", async update => {

    if (
      update.connection === "open" &&
      !messageSent &&
      !finished
    ) {
      try {
        console.log("WhatsApp connected.");

        await sock.sendMessage(
          `${phone}@s.whatsapp.net`,
          {
            text:
              `رمز التحقق الخاص بك هو: ${otp}\n\n` +
              "لا تشارك هذا الرمز مع أي شخص."
          }
        );

        messageSent = true;
        finished = true;

        clearTimeout(timeout);

        console.log("--------------------------------");
        console.log("OTP message sent successfully.");
        console.log("--------------------------------");

        sock.end(undefined);

        setTimeout(() => {
          process.exit(0);
        }, 1000);

      } catch (error) {
        if (finished) return;

        finished = true;
        clearTimeout(timeout);

        console.error(
          "Message sending failed:",
          error.message
        );

        sock.end(undefined);
        process.exit(1);
      }
    }

    if (update.connection === "close") {
      if (finished) return;

      finished = true;
      clearTimeout(timeout);

      console.error(
        "WhatsApp connection closed before sending."
      );

      process.exit(1);
    }
  });
}

main().catch(error => {
  console.error("Error:", error.message);
  process.exit(1);
});
