require("dotenv").config();
const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const basicAuth = require("express-basic-auth");

const app = express();

app.use(express.json({
  verify: (req, _res, buf) => { req.rawBody = buf; }
}));
app.use(express.urlencoded({ extended: true }));

app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  if (req.method === "POST" && req.body && Object.keys(req.body).length) {
    console.log("   Body:", JSON.stringify(req.body).substring(0, 500));
  }
  next();
});

const {
  PORT = 3000,
  VERIFY_TOKEN,
  PAGE_ACCESS_TOKEN,
  IG_USER_ID,
  APP_SECRET,
  ADMIN_USER,
  ADMIN_PASS
} = process.env;

const GRAPH = "https://graph.instagram.com/v21.0";
const RULES_FILE = path.join(__dirname, "rules.json");

function loadRules() {
  try { return JSON.parse(fs.readFileSync(RULES_FILE, "utf8")); }
  catch { return []; }
}
function saveRules(rules) {
  fs.writeFileSync(RULES_FILE, JSON.stringify(rules, null, 2));
}

// CHOISIT UNE REPONSE PUBLIQUE ALEATOIRE PARMI LES VARIANTES
function pickRandomReply(rawReply) {
  if (!rawReply) return null;
  const variants = rawReply
    .split(/[|\n]/)
    .map(s => s.trim())
    .filter(Boolean);
  if (variants.length === 0) return null;
  return variants[Math.floor(Math.random() * variants.length)];
}

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    time: new Date().toISOString(),
    hasToken: !!PAGE_ACCESS_TOKEN,
    tokenPrefix: PAGE_ACCESS_TOKEN ? PAGE_ACCESS_TOKEN.substring(0, 6) : null,
    hasAppSecret: !!APP_SECRET,
    rulesCount: loadRules().length
  });
});

app.get("/webhook", (req, res) => {
  if (req.query["hub.mode"] === "subscribe" && req.query["hub.verify_token"] === VERIFY_TOKEN) {
    return res.status(200).send(req.query["hub.challenge"]);
  }
  res.sendStatus(403);
});

function verifySignature(req) {
  const sig = req.headers["x-hub-signature-256"];
  if (!sig || !APP_SECRET) return false;
  const expected = "sha256=" + crypto.createHmac("sha256", APP_SECRET)
    .update(req.rawBody).digest("hex");
  try { return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected)); }
  catch { return false; }
}

app.post("/webhook", async (req, res) => {
  console.log("POST /webhook recu !");
  verifySignature(req);
  res.sendStatus(200);

  const entries = req.body.entry || [];
  for (const entry of entries) {
    const changes = entry.changes || [];
    for (const change of changes) {
      if (change.field === "comments") {
        await handleComment(change.value);
      }
    }
  }
});

function buildMessage(rule) {
  const type = rule.type || "text";
  if (type === "text") return { text: rule.dm };
  if (type === "image") return {
    attachment: { type: "image", payload: { url: rule.imageUrl, is_reusable: true } }
  };
  if (type === "button") return {
    attachment: {
      type: "template",
      payload: {
        template_type: "button",
        text: rule.dm,
        buttons: [{ type: "web_url", url: rule.ctaUrl, title: rule.ctaText }]
      }
    }
  };
  if (type === "image_button") return {
    attachment: {
      type: "template",
      payload: {
        template_type: "generic",
        elements: [{
          title: rule.dm.substring(0, 80) || "Découvrir",
          subtitle: rule.subtitle ? rule.subtitle.substring(0, 80) : undefined,
          image_url: rule.imageUrl,
          buttons: [{ type: "web_url", url: rule.ctaUrl, title: rule.ctaText }]
        }]
      }
    }
  };
  return { text: rule.dm };
}

async function handleComment(c) {
  try {
    console.log(`   Commentaire: "${c.text}" de @${c.from?.username}`);
    if (!c.text || !c.from) return;
    if (IG_USER_ID && c.from.id === IG_USER_ID) return;

    const lower = c.text.toLowerCase();
    const rules = loadRules();
    const rule = rules.find(r =>
      r.keywords.some(k => lower.includes(k.toLowerCase()))
    );
    if (!rule) return console.log(`   Aucun mot-cle matche`);

    console.log(`   MATCH (${rule.keywords[0]}) type=${rule.type || "text"} - envoi DM...`);
    const message = buildMessage(rule);

    await axios.post(`${GRAPH}/me/messages`, {
      recipient: { comment_id: c.id },
      message: message
    }, { params: { access_token: PAGE_ACCESS_TOKEN } });
    console.log(`   DM envoye !`);

    // REPONSE PUBLIQUE ALEATOIRE
    const reply = pickRandomReply(rule.publicReply);
    if (reply) {
      await axios.post(`${GRAPH}/${c.id}/replies`, {
        message: reply
      }, { params: { access_token: PAGE_ACCESS_TOKEN } });
      console.log(`   Reponse publique postee : "${reply}"`);
    }
  } catch (e) {
    console.error("   Erreur envoi DM:", e.response?.data || e.message);
  }
}

const auth = basicAuth({ users: { [ADMIN_USER]: ADMIN_PASS }, challenge: true });

app.get("/admin", auth, (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});
app.use("/admin", auth, express.static(path.join(__dirname, "public")));

app.get("/api/rules", auth, (_req, res) => res.json(loadRules()));

app.post("/api/rules", auth, (req, res) => {
  const { keyword, type, dm, subtitle, imageUrl, ctaText, ctaUrl, publicReply } = req.body;
  if (!keyword) return res.status(400).json({ error: "Mot-cle requis" });

  if ((type === "text" || type === "button") && !dm) return res.status(400).json({ error: "Message texte requis" });
  if ((type === "image" || type === "image_button") && !imageUrl) return res.status(400).json({ error: "URL image requise" });
  if ((type === "button" || type === "image_button") && (!ctaText || !ctaUrl)) return res.status(400).json({ error: "Texte et URL du bouton requis" });
  if (ctaText && ctaText.length > 20) return res.status(400).json({ error: "Texte du bouton: 20 caracteres max" });

  const rules = loadRules();
  rules.push({
    id: Date.now().toString(),
    keywords: keyword.split(",").map(s => s.trim()).filter(Boolean),
    type: type || "text",
    dm: dm || "",
    subtitle: subtitle || null,
    imageUrl: imageUrl || null,
    ctaText: ctaText || null,
    ctaUrl: ctaUrl || null,
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

app.get("/", (_req, res) => res.send("Robot Instagram actif. Va sur /admin ou /health"));

app.listen(PORT, () => console.log(`En ligne sur :${PORT}`));
