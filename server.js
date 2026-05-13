const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

const VERIFY_TOKEN = process.env.VERIFY_TOKEN || 'verify_me';
const PAGE_ACCESS_TOKEN = process.env.PAGE_ACCESS_TOKEN || '';
const APP_SECRET = process.env.APP_SECRET || '';

const RULES_FILE = path.join(__dirname, 'rules.json');

// ---------- Helpers ----------
function loadRules() {
  try {
    if (!fs.existsSync(RULES_FILE)) return [];
    const raw = fs.readFileSync(RULES_FILE, 'utf-8');
    return JSON.parse(raw || '[]');
  } catch (e) {
    console.error('Erreur lecture rules.json:', e.message);
    return [];
  }
}

function saveRules(rules) {
  fs.writeFileSync(RULES_FILE, JSON.stringify(rules, null, 2), 'utf-8');
}

function pickRandomReply(rawReply) {
  if (!rawReply) return '';
  const variants = rawReply.split(/\||\n/).map(s => s.trim()).filter(Boolean);
  if (variants.length === 0) return '';
  return variants[Math.floor(Math.random() * variants.length)];
}

function buildMessage(rule) {
  const type = rule.type || 'text';
  if (type === 'image') {
    return {
      attachment: {
        type: 'image',
        payload: { url: rule.imageUrl, is_reusable: true }
      }
    };
  }
  if (type === 'button') {
    return {
      attachment: {
        type: 'template',
        payload: {
          template_type: 'button',
          text: rule.dmText,
          buttons: [{ type: 'web_url', url: rule.ctaUrl, title: rule.ctaText }]
        }
      }
    };
  }
  if (type === 'image_button') {
    return {
      attachment: {
        type: 'template',
        payload: {
          template_type: 'generic',
          elements: [{
            title: rule.dmText,
            image_url: rule.imageUrl,
            buttons: [{ type: 'web_url', url: rule.ctaUrl, title: rule.ctaText }]
          }]
        }
      }
    };
  }
  return { text: rule.dmText };
}

// ---------- Middleware ----------
app.use(bodyParser.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// ---------- Routes Privacy & Terms ----------
app.get('/privacy', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
});
app.get('/terms', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'terms.html'));
});
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
app.get('/admin/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ---------- Static files ----------
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Health ----------
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    tokenPrefix: PAGE_ACCESS_TOKEN ? PAGE_ACCESS_TOKEN.slice(0, 6) : 'NONE',
    hasAppSecret: !!APP_SECRET,
    rulesCount: loadRules().length
  });
});

// ---------- Admin API ----------
app.get('/api/rules', (req, res) => {
  res.json(loadRules());
});

app.post('/api/rules', (req, res) => {
  const rules = loadRules();
  const newRule = { id: Date.now().toString(), ...req.body };
  rules.push(newRule);
  saveRules(rules);
  res.json(newRule);
});

app.delete('/api/rules/:id', (req, res) => {
  const rules = loadRules().filter(r => r.id !== req.params.id);
  saveRules(rules);
  res.json({ ok: true });
});

// ---------- Webhook verify ----------
app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];
  if (mode === 'subscribe' && token === VERIFY_TOKEN) {
    console.log('✅ Webhook verified');
    return res.status(200).send(challenge);
  }
  return res.sendStatus(403);
});

// ---------- Webhook receive ----------
app.post('/webhook', async (req, res) => {
  console.log('📩 Webhook reçu:', JSON.stringify(req.body));

  // Signature check (log only, do not block)
  if (APP_SECRET) {
    const sig = req.headers['x-hub-signature-256'] || '';
    const expected = 'sha256=' + crypto.createHmac('sha256', APP_SECRET).update(req.rawBody).digest('hex');
    if (sig !== expected) {
      console.warn('⚠️ Signature mismatch (on continue quand même)');
    }
  }

  res.sendStatus(200);

  try {
    const entries = req.body.entry || [];
    for (const entry of entries) {
      const changes = entry.changes || [];
      for (const change of changes) {
        if (change.field !== 'comments') continue;
        const value = change.value || {};
        const commentText = (value.text || '').toLowerCase();
        const commentId = value.id;
        const fromId = value.from && value.from.id;

        if (!commentText || !fromId) continue;

        const rules = loadRules();
        for (const rule of rules) {
          const keywords = (rule.keywords || '').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
          const matched = keywords.some(k => commentText.includes(k));
          if (!matched) continue;

          // Send DM
          try {
            const message = buildMessage(rule);
            await axios.post(
              `https://graph.instagram.com/v21.0/me/messages`,
              { recipient: { comment_id: commentId }, message },
              { params: { access_token: PAGE_ACCESS_TOKEN } }
            );
            console.log('✅ DM envoyé !');
          } catch (e) {
            console.error('❌ Erreur DM:', e.response?.data || e.message);
          }

          // Public reply
          if (rule.publicReply) {
            const reply = pickRandomReply(rule.publicReply);
            if (reply) {
              try {
                await axios.post(
                  `https://graph.instagram.com/v21.0/${commentId}/replies`,
                  { message: reply },
                  { params: { access_token: PAGE_ACCESS_TOKEN } }
                );
                console.log('✅ Réponse publique envoyée:', reply);
              } catch (e) {
                console.error('❌ Erreur reply publique:', e.response?.data || e.message);
              }
            }
          }
          break; // une seule règle par commentaire
        }
      }
    }
  } catch (e) {
    console.error('❌ Erreur traitement webhook:', e.message);
  }
});

app.listen(PORT, () => {
  console.log(`🚀 En ligne sur :${PORT}`);
});
