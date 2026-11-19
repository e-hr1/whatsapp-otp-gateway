
const express = require('express');
const {
  default: makeWASocket,
  useMultiFileAuthState,
  DisconnectReason
} = require('@whiskeysockets/baileys');

const qrcode = require('qrcode-terminal');
const pino = require('pino');
const crypto = require('crypto');

const app = express();
app.use(express.json());

let whatsapp;
const otpStore = new Map();

async function connectWhatsApp() {
  const { state, saveCreds } =
    await useMultiFileAuthState('./auth_info');

  whatsapp = makeWASocket({
    auth: state,
    logger: pino({ level: 'silent' })
  });

  whatsapp.ev.on('creds.update', saveCreds);

  whatsapp.ev.on('connection.update', (update) => {
    const { connection, lastDisconnect, qr } = update;

    if (qr) {
      console.log('Scan this QR with WhatsApp:');
      qrcode.generate(qr, { small: true });
    }

    if (connection === 'open') {
      console.log('WhatsApp connected successfully!');
    }

    if (connection === 'close') {
      const status =
        lastDisconnect?.error?.output?.statusCode;

      if (status !== DisconnectReason.loggedOut) {
        setTimeout(connectWhatsApp, 5000);
      } else {
        console.log('WhatsApp logged out. Reconnect manually.');
      }
    }
  });
}

app.post('/send-otp', async (req, res) => {
  try {
    if (req.headers.authorization !==
        `Bearer ${process.env.API_SECRET}`) {
      return res.status(401).json({
        success: false,
        message: 'Unauthorized'
      });
    }

    const { phone } = req.body;

    if (!/^\d{10,15}$/.test(phone || '')) {
      return res.status(400).json({
        success: false,
        message: 'Invalid phone number'
      });
    }

    if (!whatsapp?.user) {
      return res.status(503).json({
        success: false,
        message: 'WhatsApp is not connected'
      });
    }

    const now = Date.now();
    const previous = otpStore.get(phone);

    if (previous && now - previous.createdAt < 60000) {
      return res.status(429).json({
        success: false,
        message: 'Please wait before requesting another code'
      });
    }

    const otp = crypto.randomInt(100000, 1000000).toString();

    otpStore.set(phone, {
      code: otp,
      createdAt: now,
      expiresAt: now + 5 * 60 * 1000
    });

    await whatsapp.sendMessage(`${phone}@s.whatsapp.net`, {
      text: `Your verification code is: ${otp}\nThis code expires in 5 minutes.`
    });

    res.json({
      success: true,
      message: 'OTP sent successfully'
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: 'Failed to send OTP'
    });
  }
});

app.post('/verify-otp', (req, res) => {
  if (req.headers.authorization !==
      `Bearer ${process.env.API_SECRET}`) {
    return res.status(401).json({
      success: false
    });
  }

  const { phone, code } = req.body;
  const saved = otpStore.get(phone);

  if (!saved || Date.now() > saved.expiresAt ||
      saved.code !== String(code)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid or expired OTP'
    });
  }

  otpStore.delete(phone);

  res.json({
    success: true,
    message: 'Phone verified successfully'
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`OTP Gateway running on port ${PORT}`);
});

connectWhatsApp();
