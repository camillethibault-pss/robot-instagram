require("dotenv").config();
const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const basicAuth = require("express-basic-auth");

const app = express();
app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } }));
app.use(express.urlencoded({ extended: true }));

const {
  PORT = 3000, VERIFY_TOKEN, PAGE_ACCESS_TOKEN, IG_USER_ID, APP_SECRET,
  ADMIN_USER, ADMIN_PASS
} = process.env;

const GRAPH = "https://graph.facebook.com/v20.0";
const RULES_FILE = path.join(__dirname, "rules.json");

function loadRules() {
  try { return JSON.parse(fs.readFileSync(RULES_FILE, "utf8")); }
  catch { return []; }
}
function saveRules(rules) {
  fs.writeFileSync(RULES_FILE, JSON.stringify(rules, null, 2));
}

app.get("/webhook", (req, res) => {
  if (req.query["hub.mode"] === "subscribe" &&
      req.query["hub.verify_token"] === VERIFY_TOKEN) {
    return res.status(200).send(req.query["hub.challenge"]);
  }
  res.sendStatus(403);
});

function verifySignature(req) {
  const sig = req.headers["x-hub-signature-256"];
  if (!sig) return false;
  const expected = "sha256=" + crypto.createHmac("sha256", APP_SECRET)
    .update(req.rawBody).digest("hex");
  try { return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected)); }
  catch { return false; }
}

app.post("/webhook", async (req, res) => {
  if (!verifySignature(req)) return res.sendStatus(403);
  res.sendStatus(200);
  for (const entry of req.body.entry || []) {
    for (const change of entry.changes || []) {
      if (change.field === "comments") await handleComment(change.value);
    }
  }
});

async function handleComment(c) {
  try {
    if (!c.text || !c.from || c.from.id === IG_USER_ID) return;
    const lower = c.text.toLowerCase();
    const rules = loadRules();
    const rule = rules.find(r =>
      r.keywords.some(k => lower.includes(k.toLowerCase()))
    );
    if (!rule) return console.log(`ℹ️ Pas de mot-clé dans "${c.text}"`);

    console.log(`🎯 Match (${rule.keywords[0]}) sur ${c.id}`);
    await axios.post(`${GRAPH}/${IG_USER_ID}/messages`, {
      recipient: { comment_id: c.id },
      message: { text: rule.dm }
    }, { params: { access_token: PAGE_ACCESS_TOKEN } });
    console.log(`📩 DM envoyé`);

    if (rule.publicReply) {
      await axios.post(`${GRAPH}/${c.id}/replies`,
        { message: rule.publicReply },
        { params: { access_token: PAGE_ACCESS_TOKEN } });
      console.log(`💬 Réponse publique postée`);
    }
  } catch (e) { console.error("Erreur:", e.response?.data || e.message); }
}

const auth = basicAuth({
  users: { [ADMIN_USER]: ADMIN_PASS },
  challenge: true
});

// 🔧 Route /admin : sert directement la page admin.html
app.get("/admin", auth, (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});
app.use("/admin", auth, express.static(path.join(__dirname, "public")));

app.get("/api/rules", auth, (_req, res) => res.json(loadRules()));

app.post("/api/rules", auth, (req, res) => {
  const { keyword, dm, publicReply } = req.body;
  if (!keyword || !dm) return res.status(400).json({ error: "Champs requis" });
  const rules = loadRules();
  rules.push({
    id: Date.now().toString(),
    keywords: keyword.split(",").map(s => s.trim()).filter(Boolean),
    dm,
    publicReply: publicReply || null
  });
  saveRules(rules);
  res.json({ ok: true });
});

app.delete("/api/rules/:id", auth, (req, res) => {
  const rules = loadRules().filter(r => r.id !== req.params.id);
  saveRules(rules);
  res.json({ ok: true });
});

app.get("/", (_req, res) => res.send("🤖 Robot Instagram actif. Va sur /admin"));

app.listen(PORT, () => console.log(`🚀 En ligne sur :${PORT}`));
