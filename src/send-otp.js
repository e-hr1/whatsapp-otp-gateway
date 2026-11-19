
const {
  default: makeWASocket,
  useMultiFileAuthState
} = require("@whiskeysockets/baileys");

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const axios = require("axios");
const sodium = require("libsodium-wrappers");
const { execFileSync } = require("child_process");
const pino = require("pino");

const AUTH_DIR = path.join(process.cwd(), "auth_info");

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}

// استعادة جلسة واتساب
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

// حفظ سجل OTP مشفرًا في GitHub Secrets
async function saveOtpRecord(phone, otp) {
  await sodium.ready;

  const token = required("GH_SECRETS_TOKEN");
  const repository = required("GITHUB_REPOSITORY");

  const [owner, repo] = repository.split("/");

  const api = axios.create({
    baseURL: "https://api.github.com",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28"
    },
    timeout: 20000
  });

  const publicKeyResponse = await api.get(
    `/repos/${owner}/${repo}/actions/secrets/public-key`
  );

  const publicKey = publicKeyResponse.data;

  const salt = crypto.randomBytes(32).toString("hex");

  const hash = crypto
    .createHash("sha256")
    .update(`${salt}:${phone}:${otp}`)
    .digest("hex");

  const record = JSON.stringify({
    phone,
    salt,
    hash,
    expiresAt: Date.now() + 5 * 60 * 1000
  });

  const encrypted = sodium.crypto_box_seal(
    sodium.from_string(record),
    sodium.from_base64(
      publicKey.key,
      sodium.base64_variants.ORIGINAL
    )
  );

  await api.put(
    `/repos/${owner}/${repo}/actions/secrets/OTP_RECORD`,
    {
      encrypted_value: sodium.to_base64(
        encrypted,
        sodium.base64_variants.ORIGINAL
      ),
      key_id: publicKey.key_id
    }
  );

  console.log("OTP verification record saved.");
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

  let finished = false;
  let messageSent = false;

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
      messageSent = true;

      try {
        console.log("WhatsApp connected.");

        // حفظ سجل التحقق قبل إرسال الرمز
        await saveOtpRecord(phone, otp);

        await sock.sendMessage(
          `${phone}@s.whatsapp.net`,
          {
            text:
              `رمز التحقق الخاص بك هو: ${otp}\n\n` +
              "الرمز صالح لمدة 5 دقائق. لا تشاركه مع أي شخص."
          }
        );

        finished = true;
        clearTimeout(timeout);

        console.log("OTP message sent successfully.");

        sock.end(undefined);

        setTimeout(() => process.exit(0), 1000);

      } catch (error) {
        finished = true;
        clearTimeout(timeout);

        console.error("OTP operation failed:", error.message);

        sock.end(undefined);
        process.exit(1);
      }
    }

    if (update.connection === "close" && !finished) {
      finished = true;
      clearTimeout(timeout);

      console.error("WhatsApp connection closed before sending.");
      process.exit(1);
    }
  });
}

main().catch(error => {
  console.error("Error:", error.message);
  process.exit(1);
});
