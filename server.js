
require("dotenv").config();

const express = require("express");
const axios = require("axios");
const path = require("path");

const app = express();

app.use(express.json());

const {
  GH_SECRETS_TOKEN,
  GITHUB_OWNER,
  GITHUB_REPO,
  GITHUB_WORKFLOW,
  GITHUB_BRANCH,
  PORT
} = process.env;

const required = [
  GH_SECRETS_TOKEN,
  GITHUB_OWNER,
  GITHUB_REPO,
  GITHUB_WORKFLOW,
  GITHUB_BRANCH
];

if (required.some(value => !value)) {
  console.error("Missing configuration in .env");
  process.exit(1);
}

// تشغيل الصفحة من مجلد public فقط
app.use(express.static(path.join(__dirname, "public")));

const github = axios.create({
  baseURL: "https://api.github.com",
  headers: {
    Authorization: `Bearer ${GH_SECRETS_TOKEN}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
  },
  timeout: 15000
});

let activeRequest = false;
const recentRequests = new Map();

// طلب إرسال OTP
app.post("/api/send-otp", async (req, res) => {
  const phone = String(req.body.phone || "").replace(/\D/g, "");

  if (!/^\d{8,15}$/.test(phone)) {
    return res.status(400).json({
      message: "رقم الهاتف غير صحيح"
    });
  }

  if (activeRequest) {
    return res.status(429).json({
      message: "هناك طلب آخر قيد التنفيذ، انتظر قليلًا"
    });
  }

  const lastRequest = recentRequests.get(phone);

  if (lastRequest && Date.now() - lastRequest < 60000) {
    return res.status(429).json({
      message: "انتظر دقيقة قبل إعادة الإرسال لهذا الرقم"
    });
  }

  activeRequest = true;

  try {
    const workflow = GITHUB_WORKFLOW;
    const branch = GITHUB_BRANCH;

    // معرفة آخر تشغيل قبل إرسال الطلب
    const previous = await github.get(
      `/repos/${GITHUB_OWNER}/${GITHUB_REPO}/actions/workflows/${workflow}/runs`,
      {
        params: {
          branch,
          event: "workflow_dispatch",
          per_page: 1
        }
      }
    );

    const previousRunNumber =
      previous.data.workflow_runs[0]?.run_number || 0;

    // تشغيل GitHub Actions
    await github.post(
      `/repos/${GITHUB_OWNER}/${GITHUB_REPO}/actions/workflows/${workflow}/dispatches`,
      {
        ref: branch,
        inputs: {
          phone
        }
      }
    );

    recentRequests.set(phone, Date.now());

    // البحث عن التشغيل الجديد
    let run = null;

    for (let i = 0; i < 15; i++) {
      await new Promise(resolve => setTimeout(resolve, 2000));

      const result = await github.get(
        `/repos/${GITHUB_OWNER}/${GITHUB_REPO}/actions/workflows/${workflow}/runs`,
        {
          params: {
            branch,
            event: "workflow_dispatch",
            per_page: 10
          }
        }
      );

      run = result.data.workflow_runs.find(
        item => item.run_number > previousRunNumber
      );

      if (run) break;
    }

    if (!run) {
      throw new Error("لم يتم العثور على تشغيل Workflow الجديد");
    }

    res.json({
      success: true,
      message: "تم إرسال طلب الإرسال إلى GitHub",
      run_id: run.id,
      status: run.status
    });

  } catch (error) {
    console.error(
      "GitHub error:",
      error.response?.data || error.message
    );

    res.status(500).json({
      message: "تعذر تشغيل GitHub Actions. تحقق من صلاحيات التوكن."
    });

  } finally {
    activeRequest = false;
  }
});

// متابعة حالة الإرسال
app.get("/api/status/:runId", async (req, res) => {
  const runId = req.params.runId;

  if (!/^\d+$/.test(runId)) {
    return res.status(400).json({
      message: "رقم التشغيل غير صحيح"
    });
  }

  try {
    const result = await github.get(
      `/repos/${GITHUB_OWNER}/${GITHUB_REPO}/actions/runs/${runId}`
    );

    res.json({
      status: result.data.status,
      conclusion: result.data.conclusion,
      url: result.data.html_url
    });

  } catch (error) {
    console.error("Status error:", error.message);

    res.status(500).json({
      message: "تعذر جلب حالة التشغيل"
    });
  }
});

// تشغيل الخادم محليًا فقط
const serverPort = Number(PORT) || 3000;

app.listen(serverPort, "127.0.0.1", () => {
  console.log("--------------------------------");
  console.log("WhatsApp OTP Local Server");
  console.log(`http://127.0.0.1:${serverPort}`);
  console.log("--------------------------------");
});
