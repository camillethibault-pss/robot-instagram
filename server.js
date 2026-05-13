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

// LOG TOUTES LES REQUETES (avant tout traitement)
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
  console.log("GET /webhook - challenge Meta");
  console.log("   mode:", req.query["hub.mode"]);
  console.log("   token recu:", req.query["hub.verify_token"]);
  console.log("   token attendu:", VERIFY_TOKEN);
  if (req.query["hub.mode"] === "subscribe" && req.query["hub.verify_token"] === VERIFY_TOKEN) {
    console.log("   Challenge OK, on renvoie:", req.query["hub.challenge"]);
    return res.status(200).send(req.query["hub.challenge"]);
  }
  console.log("   Challenge KO");
  res.sendStatus(403);
});

function verifySignature(req) {
  const sig = req.headers["x-hub-signature-256"];
  if (!sig) { console.log("Pas de header x-hub-signature-256"); return false; }
  if (!APP_SECRET) { console.log("APP_SECRET non defini"); return false; }
  const expected = "sha256=" + crypto.createHmac("sha256", APP_SECRET)
    .update(req.rawBody).digest("hex");
  try {
    const ok = crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
    if (!ok) console.log("Signature invalide (recu:", sig, "attendu:", expected, ")");
    return ok;
  } catch { return false; }
}

app.post("/webhook", async (req, res) => {
  console.log("POST /webhook recu !");
  const sigOK = verifySignature(req);
  console.log("   Signature OK ?", sigOK);
  res.sendStatus(200);

  const entries = req.body.entry || [];
  console.log(`   ${entries.length} entry(ies) a traiter`);

  for (const entry of entries) {
    const changes = entry.changes || [];
    for (const change of changes) {
      console.log(`   Field: ${change.field}`);
      if (change.field === "comments") {
        await handleComment(change.value);
      }
    }
  }
});

async function handleComment(c) {
  try {
    console.log(`   Commentaire recu: "${c.text}" de @${c.from?.username}`);
    if (!c.text || !c.from) { console.log("   Pas de texte ou from manquant"); return; }
    if (IG_USER_ID && c.from.id === IG_USER_ID) { console.log("   Commentaire de moi-meme"); return; }

    const lower = c.text.toLowerCase();
    const rules = loadRules();
    console.log(`   ${rules.length} regle(s) chargee(s)`);

    const rule = rules.find(r =>
      r.keywords.some(k => lower.includes(k.toLowerCase()))
    );
    if (!rule) return console.log(`   Aucun mot-cle matche dans "${c.text}"`);

    console.log(`   MATCH (${rule.keywords[0]}) - envoi DM...`);

    const dmUrl = `${GRAPH}/me/messages`;
    await axios.post(dmUrl, {
      recipient: { comment_id: c.id },
      message: { text: rule.dm }
    }, { params: { access_token: PAGE_ACCESS_TOKEN } });
    console.log(`   DM envoye !`);

    if (rule.publicReply) {
      await axios.post(`${GRAPH}/${c.id}/replies`, {
        message: rule.publicReply
      }, { params: { access_token: PAGE_ACCESS_TOKEN } });
      console.log(`   Reponse publique postee`);
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

app.get("/", (_req, res) => res.send("Robot Instagram actif. Va sur /admin ou /health"));

app.listen(PORT, () => console.log(`En ligne sur :${PORT}`));
