const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

const VERIFY_TOKEN  = process.env.VERIFY_TOKEN  || 'verify_me';
const PAGE_ACCESS_TOKEN = process.env.PAGE_ACCESS_TOKEN || '';
const APP_SECRET    = process.env.APP_SECRET    || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// Supabase
const SUPABASE_URL  = process.env.SUPABASE_URL  || '';
const SUPABASE_KEY  = process.env.SUPABASE_KEY  || '';

// Mémoire anti-doublon : on garde les IDs de commentaires déjà traités (max 1000)
const processedComments = new Set();

// ---------- Supabase helpers ----------
async function loadRules() {
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    console.warn('⚠️  Supabase non configuré — utilisation tableau vide');
    return [];
  }
  try {
    const res = await axios.get(`${SUPABASE_URL}/rest/v1/rules?order=created_at.asc`, {
      headers: {
        apikey: SUPABASE_KEY,
        Authorization: `Bearer ${SUPABASE_KEY}`,
        'Content-Type': 'application/json'
      }
    });
    return res.data || [];
  } catch (e) {
    console.error('❌ Erreur chargement règles Supabase:', e.response?.data || e.message);
    return [];
  }
}

async function createRule(rule) {
  const res = await axios.post(
    `${SUPABASE_URL}/rest/v1/rules`,
    rule,
    {
      headers: {
        apikey: SUPABASE_KEY,
        Authorization: `Bearer ${SUPABASE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation'
      }
    }
  );
  return res.data[0];
}

async function deleteRule(id) {
  await axios.delete(`${SUPABASE_URL}/rest/v1/rules?id=eq.${id}`, {
    headers: {
      apikey: SUPABASE_KEY,
      Authorization: `Bearer ${SUPABASE_KEY}`
    }
  });
}

// ---------- Message builder ----------
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
        payload: { url: rule.imageurl, is_reusable: true }
      }
    };
  }
  if (type === 'button') {
    return {
      attachment: {
        type: 'template',
        payload: {
          template_type: 'button',
          text: rule.dmtext,
          buttons: [{ type: 'web_url', url: rule.ctaurl, title: rule.ctatext }]
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
            title: rule.dmtext,
            image_url: rule.imageurl,
            buttons: [{ type: 'web_url', url: rule.ctaurl, title: rule.ctatext }]
          }]
        }
      }
    };
  }
  return { text: rule.dmtext };
}

// ---------- Middleware ----------
app.use(bodyParser.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Middleware auth pour les routes admin API
function requireAuth(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const b64 = auth.replace('Basic ', '');
  let password = '';
  try {
    password = Buffer.from(b64, 'base64').toString('utf-8').split(':')[1] || '';
  } catch (e) {}
  if (password === ADMIN_PASSWORD) return next();
  res.set('WWW-Authenticate', 'Basic realm="Admin"');
  return res.status(401).json({ error: 'Non autorisé' });
}

// ---------- Pages statiques ----------
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

app.use(express.static(path.join(__dirname, 'public')));

// ---------- Health ----------
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    tokenPrefix: PAGE_ACCESS_TOKEN ? PAGE_ACCESS_TOKEN.slice(0, 6) + '...' : 'NONE',
    hasAppSecret: !!APP_SECRET,
    supabase: !!(SUPABASE_URL && SUPABASE_KEY)
  });
});

// ---------- Admin API (protégée) ----------
app.get('/api/rules', requireAuth, async (req, res) => {
  const rules = await loadRules();
  res.json(rules);
});

app.post('/api/rules', requireAuth, async (req, res) => {
  try {
    const rule = await createRule(req.body);
    res.json(rule);
  } catch (e) {
    console.error('❌ Erreur création règle:', e.response?.data || e.message);
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/rules/:id', requireAuth, async (req, res) => {
  try {
    await deleteRule(req.params.id);
    res.json({ ok: true });
  } catch (e) {
    console.error('❌ Erreur suppression règle:', e.response?.data || e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------- Webhook verify ----------
app.get('/webhook', (req, res) => {
  const mode      = req.query['hub.mode'];
  const token     = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];
  if (mode === 'subscribe' && token === VERIFY_TOKEN) {
    console.log('✅ Webhook vérifié');
    return res.status(200).send(challenge);
  }
  return res.sendStatus(403);
});

// ---------- Webhook receive ----------
app.post('/webhook', async (req, res) => {
  console.log('📩 Webhook reçu:', JSON.stringify(req.body));

  // Vérification signature Meta
  if (APP_SECRET) {
    const sig      = req.headers['x-hub-signature-256'] || '';
    const expected = 'sha256=' + crypto.createHmac('sha256', APP_SECRET).update(req.rawBody).digest('hex');
    if (sig !== expected) {
      console.warn('🚫 Signature invalide — requête ignorée');
      return res.sendStatus(403);
    }
  }

  res.sendStatus(200);

  try {
    const entries = req.body.entry || [];
    for (const entry of entries) {
      const changes = entry.changes || [];
      for (const change of changes) {
        if (change.field !== 'comments') continue;
        const value       = change.value || {};
        const commentText = (value.text || '').toLowerCase();
        const commentId   = value.id;
        const fromId      = value.from && value.from.id;

        if (!commentText || !fromId || !commentId) continue;

        // Anti-doublon : on ignore si déjà traité
        if (processedComments.has(commentId)) {
          console.log('⏭️ Commentaire déjà traité, ignoré:', commentId);
          continue;
        }
        processedComments.add(commentId);
        // Nettoyage mémoire si trop grand
        if (processedComments.size > 1000) {
          const first = processedComments.values().next().value;
          processedComments.delete(first);
        }

        const rules = await loadRules();
        for (const rule of rules) {
          const keywords = (rule.keywords || '').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
          const matched  = keywords.some(k => commentText.includes(k));
          if (!matched) continue;

          // Envoi DM
          try {
            const message = buildMessage(rule);
            await axios.post(
              `https://graph.instagram.com/v21.0/me/messages`,
              { recipient: { comment_id: commentId }, message },
              { params: { access_token: PAGE_ACCESS_TOKEN } }
            );
            console.log('✅ DM envoyé à', fromId);
          } catch (e) {
            console.error('❌ Erreur DM:', e.response?.data || e.message);
          }

          // Réponse publique
          if (rule.publicreply) {
            const reply = pickRandomReply(rule.publicreply);
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
