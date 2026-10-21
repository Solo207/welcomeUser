// npm install express cookie-parser  ← run once if not already installed
const express      = require('express');
const cookieParser = require('cookie-parser');
const { randomUUID: uuidv4 } = require('crypto');
const fs   = require('fs');
const path = require('path');

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

// ── Config ────────────────────────────────────────────────────────────────────
const STORE_FILE     = path.join(__dirname, 'signups.json');
const TTL_MS          = 2 * 60 * 60 * 1000; // 2 hours — link + whole flow expires after this
const PIN_LENGTH       = 5;
const MAX_PIN_ATTEMPTS = 3; // link is invalidated after this many wrong codes
const MAX_PHONE_CHANGES = 3; // link is invalidated after this many "wrong number, go back" clicks
const MAX_RESEND        = 3; // link is invalidated after this many "resend code" taps
const RESEND_COOLDOWN_SECONDS = 60; // how long the resend button stays disabled after each send
const COUNTRY_CODE  = '234'; // shown as a fixed, uneditable +234 in front of the number boxes
const PHONE_LENGTH  = 10;    // digits the user types after +234 (no leading 0)

const ADMIN_CONTACT_URL = 'https://wa.me/2348138450036?text=Hello%2C%20I%20need%20your%20help';
const CONTACT_URL = 'https://wa.me/2349136086344?text=Hello';

// NOTE ON THIS URL: the message this was spec'd from pasted a markdown link where the
// *visible* text was ".../webhook/getEmail" but the *actual* href was
// ".../webhook-test/getEmail" (n8n's temporary "listen for test event" URL, only live
// while the workflow is open in the editor). I've defaulted to the production
// "webhook/..." path below since that's what should be used once deployed — swap to
// "webhook-test/getEmail" only if you're still building the workflow in the n8n editor.
// NOTE: SEND_CODE_URL / VERIFY_CODE_URL still point at the old getEmail / verifyEmail
// workflows. They now receive { wa_id, username, phone } and { code, wa_id, phone } —
// point them at new n8n webhooks if you create separate ones for the phone flow.
const SEND_CODE_URL    = 'https://sb-n8n.rhat7s.easypanel.host/webhook/getEmail';
const VERIFY_CODE_URL  = 'https://sb-n8n.rhat7s.easypanel.host/webhook/verifyEmail';
const TERMS_URL        = 'https://sb-n8n.rhat7s.easypanel.host/webhook/termsAndConditions';
const FINAL_URL        = 'https://sb-n8n.rhat7s.easypanel.host/webhook/final';

// ── Atomic write queue (avoids race conditions / file corruption) ─────────────
let storeWriteQueue = Promise.resolve();

function loadStore() {
  try { if (fs.existsSync(STORE_FILE)) return JSON.parse(fs.readFileSync(STORE_FILE, 'utf8')); }
  catch (e) { console.error('loadStore error:', e); }
  return {};
}

function saveStore(store) {
  storeWriteQueue = storeWriteQueue.then(() => {
    const tmp = STORE_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(store), 'utf8');
    fs.renameSync(tmp, STORE_FILE); // atomic on Linux
  }).catch(err => console.error('saveStore error:', err));
}

function isExpired(record) {
  return Date.now() > record.expiresAt;
}

// Builds and sends the final-webhook payload for either outcome. Always includes
// whatever the record has captured so far (phone/school/department/level may be null
// if the flow never got that far) plus a status field, and a reason code on failure so
// your n8n workflow can tell WHY it failed.
// Reason codes: 'link_expired' | 'max_pin_attempts' | 'max_phone_changes' |
//               'max_resend_attempts' | 'superseded_by_new_link'
async function sendFinalWebhook(record, status, reason) {
  const payload = {
    wa_id: record.wa_id,
    username: record.username,
    userId: record.userId ?? null,
    phone: record.phone || null,
    school: record.school || null,
    department: record.department || null,
    level: record.level || null,
    status // 'success' | 'failed'
  };
  if (reason) payload.reason = reason;
  payload[status === 'success' ? 'submitted_at' : 'failed_at'] = new Date().toISOString();

  const result = await callWebhook(FINAL_URL, payload);
  if (!result.reachable || !result.httpOk) {
    console.error(`Final webhook (status=${status}${reason ? ', reason=' + reason : ''}) did not succeed:`, result.status);
  }
  return result;
}

// Every case scenario ends with the final webhook being called exactly once — this
// covers the "abandoned link" case: nobody clicked anything, it just timed out.
// stage 'done' records are skipped since they already sent a success call.
async function cleanup(store) {
  const now = Date.now();
  const expiredIds = Object.keys(store).filter(id => now > store[id].expiresAt);
  if (!expiredIds.length) return store;

  await Promise.all(expiredIds.map(async id => {
    const record = store[id];
    if (record.stage !== 'done') {
      try { await sendFinalWebhook(record, 'failed', 'link_expired'); }
      catch (e) { console.error('Expiry webhook failed:', e); }
    }
  }));

  expiredIds.forEach(id => delete store[id]);
  saveStore(store);
  return store;
}

// Enforces "one active link per wa_id": before a new signup link is minted, any other
// record already sitting in the store for this same wa_id that hasn't reached 'done'
// gets killed off first — its final webhook fires with reason 'superseded_by_new_link',
// then it's deleted. This means the moment a fresh link is issued, every older link for
// that wa_id 404s (GET /signup/:id no longer finds the record) even if it was mid-flow.
// 'done' records are left alone since they already completed and sent a success call.
async function invalidateActiveByWaId(store, waId) {
  const staleIds = Object.keys(store).filter(id => store[id].wa_id === waId && store[id].stage !== 'done');
  if (!staleIds.length) return;

  await Promise.all(staleIds.map(async id => {
    try { await sendFinalWebhook(store[id], 'failed', 'superseded_by_new_link'); }
    catch (e) { console.error('Supersede webhook failed:', e); }
  }));

  staleIds.forEach(id => delete store[id]);
  saveStore(store);
}

setInterval(async () => {
  const store = loadStore();
  const before = Object.keys(store).length;
  const after = await cleanup(store);
  const afterCount = Object.keys(after).length;
  if (before !== afterCount) console.log(`Periodic cleanup: removed ${before - afterCount} expired signup(s)`);
}, 5 * 60 * 1000);

// ── Small helpers ─────────────────────────────────────────────────────────────
function setSessionCookie(res, id, token) {
  res.cookie('ssess_' + id, token, { maxAge: TTL_MS, httpOnly: false, sameSite: 'lax' });
}

function escapeHtml(str) {
  return String(str ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
}

// Safe to drop inside a <script> tag — also guards against premature </script> breaks.
function safeJson(obj) {
  return JSON.stringify(obj).replace(/</g, '\\u003c').replace(/>/g, '\\u003e');
}

function isValidPhone(digits) {
  return typeof digits === 'string' && new RegExp('^[1-9][0-9]{' + (PHONE_LENGTH - 1) + '}$').test(digits);
}

// '2348031234567' → '+234 803 123 4567'
function formatPhone(full) {
  const local = String(full || '').slice(COUNTRY_CODE.length);
  return `+${COUNTRY_CODE} ${local.slice(0, 3)} ${local.slice(3, 6)} ${local.slice(6)}`.trim();
}

// Only plain http(s) URLs are accepted as the post-registration redirect target — this
// rules out javascript:, data: and similar schemes.
function isValidRedirectUrl(u) {
  if (typeof u !== 'string') return false;
  try { const p = new URL(u.trim()); return p.protocol === 'https:' || p.protocol === 'http:'; }
  catch (e) { return false; }
}

function isValidPin(code) {
  return typeof code === 'string' && new RegExp(`^\\d{${PIN_LENGTH}}$`).test(code);
}

async function callWebhook(url, payload) {
  try {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    // Read as text first — this n8n webhook can respond with a plain string (e.g.
    // "email already exist") instead of JSON. Calling r.json() directly on that would
    // throw, get swallowed, and leave `data` null with no trace of what was said.
    const raw = await r.text();
    let data = null;
    try { data = raw ? JSON.parse(raw) : null; } catch (e) { /* not JSON — callers fall back to `raw` */ }
    return { reachable: true, httpOk: r.ok, status: r.status, data, raw };
  } catch (e) {
    console.error('Webhook call failed:', url, e.message);
    return { reachable: false, httpOk: false, status: 0, data: null, raw: '' };
  }
}

// ── Routes ────────────────────────────────────────────────────────────────────

// POST /create-signup  { wa_id, username, url, userId } → { link, id }
// `userId` is never shown on any page — it is stored and handed back in every webhook payload.
// `url` is where the user is sent (same tab, immediately) once step 3 is complete.
// If this wa_id already has an active (non-done) link, it's invalidated first — see
// invalidateActiveByWaId — so at most one signup link can ever be "live" per wa_id.
app.post('/create-signup', async (req, res) => {
  const { wa_id, username, url, userId } = req.body || {};
  const hasUserId = (typeof userId === 'string' && userId.trim() !== '') || typeof userId === 'number';
  if (!wa_id || !username || !url || !hasUserId) return res.status(400).json({ error: 'Missing wa_id, username, url or userId' });
  if (!isValidRedirectUrl(url)) return res.status(400).json({ error: 'url must be a valid http(s) URL' });

  const id      = uuidv4();
  const waIdStr = String(wa_id);
  const store   = await cleanup(loadStore());
  await invalidateActiveByWaId(store, waIdStr);

  store[id] = {
    wa_id: waIdStr,
    username: String(username),
    redirectUrl: String(url).trim(),
    userId: typeof userId === 'string' ? userId.trim() : userId, // hidden — only ever sent back out via webhooks
    createdAt: Date.now(),
    expiresAt: Date.now() + TTL_MS,
    claimed: false,
    sessionToken: null,
    stage: 'phone',            // phone → pin → details → done
    phone: null,               // full number incl. country code, e.g. 2348031234567
    academicOptions: null,
    attempts: 0,
    phoneChanges: 0,
    resendCount: 0,
    lastCodeSentAt: null       // set whenever a code actually goes out — drives the resend cooldown
  };
  saveStore(store);

  const host     = req.headers['x-forwarded-host'] || req.headers.host;
  const protocol = req.headers['x-forwarded-proto'] || 'http';
  res.json({ link: `${protocol}://${host}/signup/${id}`, id, expiresIn: '2 hours' });
});

// GET /signup/:id — serves whichever stage the record is actually on server-side.
// This is what makes it impossible to reach the pin page (or beyond) without a real,
// server-confirmed phone step: the HTML for a later stage is never generated or sent
// until this record's `stage` field has actually advanced.
app.get('/signup/:id', async (req, res) => {
  const store  = await cleanup(loadStore());
  const record = store[req.params.id];
  if (!record) return res.status(404).send(expiredPage());

  const cookieName    = 'ssess_' + req.params.id;
  const sessionCookie = req.cookies?.[cookieName];

  if (!record.claimed) {
    const token = uuidv4();
    record.claimed      = true;
    record.sessionToken = token;
    saveStore(store);
    setSessionCookie(res, req.params.id, token);
    return res.send(renderPage(req.params.id, record));
  }

  if (sessionCookie === record.sessionToken) return res.send(renderPage(req.params.id, record));

  return res.status(403).send(claimedPage(req.params.id));
});

// POST /signup/:id/recover — cookie recovery without a token in the URL
app.post('/signup/:id/recover', (req, res) => {
  const store  = loadStore();
  const record = store[req.params.id];
  if (!record) return res.status(404).json({ ok: false, error: 'Signup link not found' });

  const { token } = req.body || {};
  if (!token || token !== record.sessionToken) return res.status(403).json({ ok: false, error: 'Invalid token' });

  setSessionCookie(res, req.params.id, record.sessionToken);
  res.json({ ok: true });
});

// Shared guard for every stage-gated POST route: checks the record exists, the session
// cookie matches, the link hasn't expired (firing the failed final-webhook if it has),
// and — if a stage is required — that the record is actually on that stage. Returns
// {store, record} on success, or null after already sending the appropriate response.
async function loadGuardedRecord(req, res, expectedStage) {
  const store  = loadStore();
  const record = store[req.params.id];
  const cookieName = 'ssess_' + req.params.id;

  if (!record) { res.status(404).json({ ok: false, error: 'Signup link not found.' }); return null; }
  if (req.cookies?.[cookieName] !== record.sessionToken) { res.status(403).json({ ok: false, error: 'Unauthorized' }); return null; }

  if (isExpired(record)) {
    await sendFinalWebhook(record, 'failed', 'link_expired');
    delete store[req.params.id];
    saveStore(store);
    res.status(410).json({ ok: false, locked: true, error: 'This link has expired. Contact RoughBOOK on WhatsApp to start again.' });
    return null;
  }

  if (expectedStage && record.stage !== expectedStage) {
    res.status(400).json({ ok: false, error: 'This step is not available right now.' });
    return null;
  }

  return { store, record };
}

// POST /signup/:id/phone  { phone } → sends verification code via n8n, advances to 'pin'
// `phone` is the 10 digits typed after the fixed +234; the full number is built here.
app.post('/signup/:id/phone', async (req, res) => {
  const ctx = await loadGuardedRecord(req, res, 'phone');
  if (!ctx) return;
  const { store, record } = ctx;

  const digits = String(req.body?.phone || '').replace(/\D/g, '');
  if (!isValidPhone(digits)) {
    return res.status(400).json({ ok: false, error: `Please enter all ${PHONE_LENGTH} digits of your WhatsApp number.` });
  }
  const fullNumber = COUNTRY_CODE + digits;

  const result = await callWebhook(SEND_CODE_URL, { wa_id: record.wa_id, username: record.username, userId: record.userId ?? null, phone: fullNumber });
  if (!result.reachable) return res.status(502).json({ ok: false, error: 'Could not reach the verification service. Please try again.' });

  // The webhook can respond with a plain-text body (e.g. "already exists") rather than
  // JSON, so the check has to look at the raw text too, not just JSON fields.
  const responseText = String(result.data?.error || result.data?.message || result.raw || '');
  const phoneTaken = result.data?.exists === true
    || result.data?.phoneExists === true
    || /already\s*(exist|registered|in use|taken)/i.test(responseText);
  if (phoneTaken) {
    return res.status(400).json({ ok: false, error: 'That number is already registered — please enter another.' });
  }

  if (!result.httpOk || result.data?.ok === false || result.data?.error) {
    return res.status(400).json({ ok: false, error: result.data?.error || result.data?.message || 'Could not send a verification code to that number. Please try again.' });
  }

  record.phone          = fullNumber;
  record.stage          = 'pin';
  record.attempts       = 0;
  record.resendCount    = 0;
  record.lastCodeSentAt = Date.now();
  saveStore(store);
  res.json({ ok: true });
});

// POST /signup/:id/resend — resends the code via the same send-code webhook, capped at
// MAX_RESEND uses. A network/webhook failure doesn't burn an attempt.
app.post('/signup/:id/resend', async (req, res) => {
  const ctx = await loadGuardedRecord(req, res, 'pin');
  if (!ctx) return;
  const { store, record } = ctx;

  record.resendCount = (record.resendCount || 0) + 1;
  if (record.resendCount > MAX_RESEND) {
    await sendFinalWebhook(record, 'failed', 'max_resend_attempts');
    delete store[req.params.id];
    saveStore(store);
    return res.json({ ok: false, locked: true, error: 'Too many resend attempts. Contact RoughBOOK on WhatsApp to start again.' });
  }

  const result = await callWebhook(SEND_CODE_URL, { wa_id: record.wa_id, username: record.username, userId: record.userId ?? null, phone: record.phone });
  if (!result.reachable || !result.httpOk || result.data?.ok === false || result.data?.error) {
    record.resendCount -= 1; // don't charge an attempt if it didn't actually go out
    saveStore(store);
    return res.status(502).json({ ok: false, error: 'Could not resend the code. Please try again.' });
  }

  record.attempts       = 0; // fresh code, fresh attempt count
  record.lastCodeSentAt = Date.now();
  saveStore(store);
  res.json({ ok: true, remaining: MAX_RESEND - record.resendCount, resendReadyAt: record.lastCodeSentAt + RESEND_COOLDOWN_SECONDS * 1000 });
});

// POST /signup/:id/verify  { code } → checks pin via n8n, advances to 'details'
app.post('/signup/:id/verify', async (req, res) => {
  const ctx = await loadGuardedRecord(req, res, 'pin');
  if (!ctx) return;
  const { store, record } = ctx;

  const code = String(req.body?.code || '').trim();
  if (!isValidPin(code)) return res.status(400).json({ ok: false, error: `Please enter the ${PIN_LENGTH}-digit code.` });

  const result = await callWebhook(VERIFY_CODE_URL, { code, wa_id: record.wa_id, userId: record.userId ?? null, phone: record.phone });
  if (!result.reachable) return res.status(502).json({ ok: false, error: 'Could not reach the verification service. Please try again.' });

  if (Array.isArray(result.data)) {
    const options = result.data.filter(o => o && o.school && o.department && o.level);
    if (!options.length) return res.status(502).json({ ok: false, error: 'No account options were returned. Please contact support.' });
    record.academicOptions = options;
    record.stage    = 'details';
    record.attempts = 0;
    saveStore(store);
    return res.json({ ok: true });
  }

  // Anything else (including the documented "incorrect code, try again" shape) is a failure.
  record.attempts = (record.attempts || 0) + 1;
  if (record.attempts >= MAX_PIN_ATTEMPTS) {
    await sendFinalWebhook(record, 'failed', 'max_pin_attempts');
    delete store[req.params.id];
    saveStore(store);
    return res.json({ ok: false, locked: true, error: 'Too many incorrect attempts. Contact RoughBOOK on WhatsApp to start again.' });
  }
  saveStore(store);
  const remaining = MAX_PIN_ATTEMPTS - record.attempts;
  const msg = result.data?.error || result.data?.message || 'Incorrect code, try again.';
  res.json({ ok: false, error: `${msg} (${remaining} attempt${remaining === 1 ? '' : 's'} left)` });
});

// POST /signup/:id/back-to-phone — lets the user correct a mistyped number from the pin
// page. Keeps the old (wrong) number pre-filled so they can just fix the typo, and caps
// how many times this can happen so the send-code webhook can't be spammed indefinitely.
app.post('/signup/:id/back-to-phone', async (req, res) => {
  const ctx = await loadGuardedRecord(req, res, 'pin');
  if (!ctx) return;
  const { store, record } = ctx;

  record.phoneChanges = (record.phoneChanges || 0) + 1;
  if (record.phoneChanges > MAX_PHONE_CHANGES) {
    await sendFinalWebhook(record, 'failed', 'max_phone_changes');
    delete store[req.params.id];
    saveStore(store);
    return res.json({ ok: false, locked: true, error: 'Too many number changes. Contact RoughBOOK on WhatsApp to start again.' });
  }

  record.stage    = 'phone';
  record.attempts = 0;
  saveStore(store);
  res.json({ ok: true });
});

// POST /signup/:id/complete  { school, department, level, agreed } → finishes registration
app.post('/signup/:id/complete', async (req, res) => {
  const ctx = await loadGuardedRecord(req, res, 'details');
  if (!ctx) return;
  const { store, record } = ctx;

  const { school, department, level, agreed } = req.body || {};
  if (!school || !department || !level) return res.status(400).json({ ok: false, error: 'Please fill in school, department, and level.' });
  if (agreed !== true) return res.status(400).json({ ok: false, error: 'You must agree to the Terms and Conditions to continue.' });

  const validCombo = (record.academicOptions || []).some(o => o.school === school && o.department === department && o.level === level);
  if (!validCombo) return res.status(400).json({ ok: false, error: 'That school / department / level combination is not valid.' });

  const payload = {
    wa_id: record.wa_id,
    username: record.username,
    userId: record.userId ?? null,
    phone: record.phone,
    school, department, level,
    agreed_terms: true,
    status: 'success',
    submitted_at: new Date().toISOString()
  };

  const result = await callWebhook(FINAL_URL, payload);
  if (!result.reachable) return res.status(502).json({ ok: false, error: 'Could not reach the registration service. Please try again.' });
  if (!result.httpOk || result.data?.ok === false || result.data?.error) {
    return res.status(400).json({ ok: false, error: result.data?.error || result.data?.message || 'Registration could not be completed. Please try again.' });
  }

  record.school = school; record.department = department; record.level = level;
  record.stage  = 'done';
  saveStore(store);
  // The client redirects straight to this (same tab, no delay).
  res.json({ ok: true, redirectUrl: record.redirectUrl || CONTACT_URL });
});

app.get('/', (req, res) => res.json({ status: 'ok', service: 'RoughBOOK Signup' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Signup app running on port ${PORT}`));

// ── Shared page shell ─────────────────────────────────────────────────────────
const FAVICON = `data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='7' fill='%23090b18'/><circle cx='16' cy='16' r='10' fill='none' stroke='%233b82f6' stroke-width='2'/><polyline points='11,16 14.5,20 21,12' fill='none' stroke='%2322c55e' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round'/></svg>`;

const BASE_STYLE = `
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
  :root{
    --bg:#090b18;--surface:#0d1626;--surface2:#121d30;--border:#1e2d45;
    --accent:#3b82f6;--accent2:#60a5fa;--good:#22c55e;--bad:#ef4444;
    --amber:#f59e0b;--text:#e2e8f0;--muted:#64748b;--mono:'JetBrains Mono',monospace;
  }
  body{background:var(--bg);color:var(--text);font-family:'Sora',sans-serif;min-height:100vh;margin:0;overflow-x:hidden;}

  /* Slow-spinning colour wash behind everything else — the "depth" layer */
  .bg-aura{
    position:fixed;inset:-25%;z-index:0;pointer-events:none;opacity:.9;
    background:conic-gradient(from 0deg at 50% 50%,
      rgba(59,130,246,.24), rgba(20,184,166,.18), rgba(124,58,237,.24),
      rgba(59,130,246,.18), rgba(20,184,166,.20), rgba(59,130,246,.24));
    filter:blur(65px);
    animation:auraSpin 20s linear infinite;
  }
  @keyframes auraSpin{ to{ transform:rotate(360deg); } }

  /* Faint drifting starfield for texture */
  .bg-particles{
    position:fixed;inset:-40px;z-index:0;pointer-events:none;opacity:.8;
    background-image:
      radial-gradient(5px 5px at 12% 22%, rgba(226,232,240,.75) 0%, transparent 60%),
      radial-gradient(4.6px 4.6px at 68% 14%, rgba(226,232,240,.6) 0%, transparent 60%),
      radial-gradient(5px 4.6px at 38% 68%, rgba(226,232,240,.65) 0%, transparent 60%),
      radial-gradient(3.6px 5.6px at 86% 52%, rgba(226,232,240,.55) 0%, transparent 60%),
      radial-gradient(5px 4px at 8% 82%, rgba(226,232,240,.6) 0%, transparent 60%),
      radial-gradient(5.6px 4.6px at 55% 90%, rgba(226,232,240,.55) 0%, transparent 60%),
      radial-gradient(5px 4px at 92% 28%, rgba(226,232,240,.65) 0%, transparent 60%),
      radial-gradient(5.6px 4.6px at 28% 46%, rgba(226,232,240,.5) 0%, transparent 60%),
      radial-gradient(5px 4px at 78% 78%, rgba(226,232,240,.55) 0%, transparent 60%);
    animation:driftParticles 14s ease-in-out infinite;
  }
  @keyframes driftParticles{
    0%,100%{transform:translate(0,0);}
    50%{transform:translate(-32px,-44px);}
  }

  .bg-grid{position:fixed;inset:0;z-index:0;pointer-events:none;
    background-image:linear-gradient(rgba(99,102,241,.11) 1px,transparent 1px),linear-gradient(90deg,rgba(99,102,241,.11) 1px,transparent 1px);
    background-size:44px 44px;animation:gridPulse 4s ease-in-out infinite;}
  @keyframes gridPulse{0%,100%{opacity:.55;}50%{opacity:1;}}
  .bg-orb{position:fixed;border-radius:50%;pointer-events:none;z-index:0;filter:blur(60px);}
  .bg-orb-1{width:600px;height:600px;top:-160px;right:-120px;background:radial-gradient(circle,rgba(99,102,241,.32) 0%,transparent 70%);animation:orbFloat 7s ease-in-out infinite;}
  .bg-orb-2{width:480px;height:480px;bottom:5%;left:-120px;background:radial-gradient(circle,rgba(20,184,166,.28) 0%,transparent 70%);animation:orbFloat 9s ease-in-out infinite reverse;}
  .bg-orb-3{width:360px;height:360px;top:38%;left:62%;background:radial-gradient(circle,rgba(124,58,237,.28) 0%,transparent 70%);animation:orbFloat 10s ease-in-out infinite;}
  @keyframes orbFloat{0%,100%{transform:translateY(0) scale(1);}50%{transform:translateY(-50px) scale(1.1);}}
  .wrap{max-width:440px;margin:0 auto;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px 16px;position:relative;z-index:1;}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:18px;padding:32px 26px;width:100%;animation:slideIn .35s cubic-bezier(.4,0,.2,1);}
  @keyframes slideIn{from{opacity:0;transform:translateY(14px);}to{opacity:1;transform:translateY(0);}}
  @keyframes fadeIn{from{opacity:0;}to{opacity:1;}}
  .eyebrow{font-family:var(--mono);font-size:.7rem;color:var(--accent);letter-spacing:.14em;text-transform:uppercase;margin-bottom:6px;}
  h1{font-size:1.35rem;font-weight:600;margin-bottom:8px;}
  .sub{color:var(--muted);font-size:.86rem;line-height:1.55;margin-bottom:22px;}
  .steps{display:flex;gap:6px;margin-bottom:22px;}
  .step-dot{height:3px;flex:1;border-radius:2px;background:var(--border);}
  .step-dot.done{background:var(--good);} .step-dot.active{background:var(--accent);}
  label{display:block;font-size:.78rem;color:var(--muted);margin-bottom:6px;letter-spacing:.02em;}
  input[type=text],input[type=email],select{
    width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:10px;color:var(--text);
    font-family:'Sora',sans-serif;font-size:.92rem;padding:13px 14px;outline:none;transition:border-color .2s;margin-bottom:4px;
  }
  input:focus,select:focus{border-color:var(--accent);}
  input[readonly]{color:var(--text);cursor:default;background:var(--surface2);}
  select:disabled{opacity:.45;cursor:not-allowed;}
  .field{margin-bottom:18px;}
  .err{color:var(--bad);font-size:.78rem;margin-top:6px;min-height:1em;display:none;}
  .err.show{display:block;animation:fadeIn .2s ease;}
  .banner{font-size:.82rem;padding:12px 14px;border-radius:10px;margin-bottom:16px;display:none;line-height:1.5;}
  .banner.show{display:block;animation:fadeIn .2s ease;}
  .banner.bad{background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25);color:#fca5a5;}
  .banner.good{background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.25);color:#86efac;}
  .btn{width:100%;padding:14px;border-radius:12px;border:none;font-family:'Sora',sans-serif;font-size:.92rem;font-weight:600;
    cursor:pointer;transition:all .2s;background:linear-gradient(135deg,var(--accent),#7c3aed);color:#fff;}
  .btn:hover:not(:disabled){transform:translateY(-1px);box-shadow:0 6px 20px rgba(99,102,241,.35);}
  .btn:disabled{opacity:.4;cursor:not-allowed;transform:none;box-shadow:none;}
  .pin-row{display:flex;gap:8px;margin-bottom:6px;}
  .pin-box{width:100%;aspect-ratio:1;text-align:center;font-family:var(--mono);font-size:1.3rem;font-weight:600;
    background:var(--surface2);border:1px solid var(--border);border-radius:10px;color:var(--text);outline:none;transition:border-color .2s;}
  .pin-box:focus{border-color:var(--accent);}
  .phone-field{display:flex;align-items:stretch;background:var(--surface2);border:1px solid var(--border);border-radius:10px;overflow:hidden;
    cursor:text;margin-bottom:4px;transition:border-color .2s;}
  .phone-field:focus-within{border-color:var(--accent);}
  .phone-field.bad{border-color:var(--bad);}
  .phone-prefix{display:flex;align-items:center;padding:0 12px 0 14px;border-right:1px solid var(--border);color:var(--muted);
    font-family:var(--mono);font-size:1.05rem;font-weight:600;user-select:none;-webkit-user-select:none;cursor:default;}
  .phone-field input{flex:1;min-width:0;width:auto;margin:0;padding:13px 14px;background:transparent;border:none;outline:none;color:var(--text);
    font-family:var(--mono);font-size:1.05rem;font-weight:600;letter-spacing:.08em;}
  .phone-field input::placeholder{color:var(--muted);opacity:.45;font-weight:400;}
  .checkbox-row{display:flex;align-items:flex-start;gap:10px;margin:18px 0 22px;}
  .checkbox-row input{width:18px;height:18px;margin-top:1px;accent-color:var(--accent);flex-shrink:0;}
  .checkbox-row label{margin:0;font-size:.82rem;color:var(--muted);line-height:1.5;}
  .checkbox-row a{color:var(--accent2);text-decoration:underline;}
  .center-icon{font-size:2.4rem;text-align:center;margin-bottom:14px;}
  .expiry-timer{font-family:var(--mono);font-size:.7rem;color:var(--muted);text-align:right;margin-bottom:14px;}
  .expiry-timer.warn{color:var(--amber);}
  .expiry-timer.danger{color:var(--bad);}
  .resend-row{text-align:center;margin-top:16px;}
  .resend-btn{background:none;border:none;color:var(--accent2);font-family:'Sora',sans-serif;font-size:.82rem;cursor:pointer;text-decoration:underline;}
  .resend-btn:disabled{color:var(--muted);cursor:default;text-decoration:none;}
  .helper-note{font-size:.74rem;color:var(--muted);line-height:1.5;margin:-8px 0 18px;}
  .helper-note a{color:var(--accent2);text-decoration:underline;}
  @media(max-width:380px){.card{padding:26px 18px;}}
`;

function shell(bodyHtml, title, tokenScript) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>${escapeHtml(title)}</title>
  <link rel="icon" type="image/svg+xml" href="${FAVICON}"/>
  <link href="https://fonts.googleapis.com/css2?family=Sora:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
  <style>${BASE_STYLE}</style></head><body>
  <div class="bg-aura"></div><div class="bg-particles"></div><div class="bg-grid"></div>
  <div class="bg-orb bg-orb-1"></div><div class="bg-orb bg-orb-2"></div><div class="bg-orb bg-orb-3"></div>
  <div class="wrap"><div class="card">${bodyHtml}</div></div>
  ${tokenScript || ''}
  </body></html>`;
}

// Keeps the session token available client-side so claimedPage() can recover a
// dropped cookie (e.g. a WhatsApp in-app browser that blocks third-party cookies)
// without ever putting the token in the URL.
function tokenPersistScript(id, sessionToken) {
  return `<script>try{localStorage.setItem('st_' + ${safeJson(id)}, ${safeJson(sessionToken)});}catch(e){}</script>`;
}

// Live "link expires in …" countdown shown on every active stage page. Reloads the
// page when it hits zero so the server can serve the (now-expired) state — cleanup()
// on that GET is what actually fires the failed final-webhook.
function expiryTimerScript(expiresAt) {
  return `<script>
    (function(){
      var expiresAt = ${expiresAt};
      var el = document.getElementById('expiryTimer');
      if (!el) return;
      function tick(){
        var msLeft = expiresAt - Date.now();
        if (msLeft <= 0) { location.reload(); return; }
        var totalSec = Math.floor(msLeft / 1000);
        var h = Math.floor(totalSec / 3600), m = Math.floor((totalSec % 3600) / 60), s = totalSec % 60;
        var pad = function(n){ return String(n).padStart(2, '0'); };
        el.textContent = 'Link expires in ' + (h > 0 ? h + ':' + pad(m) : m) + ':' + pad(s);
        el.className = 'expiry-timer' + (msLeft < 5*60*1000 ? ' danger' : (msLeft < 15*60*1000 ? ' warn' : ''));
      }
      tick();
      setInterval(tick, 1000);
    })();
  </script>`;
}

function stepDots(active) {
  const labels = ['phone','pin','details'];
  return `<div class="steps">${labels.map((l,i) => {
    const cls = i < labels.indexOf(active) ? 'done' : (i === labels.indexOf(active) ? 'active' : '');
    return `<div class="step-dot ${cls}"></div>`;
  }).join('')}</div>`;
}

function renderPage(id, record) {
  if (record.stage === 'phone')   return phonePage(id, record);
  if (record.stage === 'pin')     return pinPage(id, record);
  if (record.stage === 'details') return detailsPage(id, record);
  if (record.stage === 'done')    return donePage(id, record);
  return expiredPage();
}

// ── Stage 1: phone ────────────────────────────────────────────────────────────
function phonePage(id, record) {
  const idJson        = safeJson(id);
  const identityLabel = `${record.username} • ${record.wa_id}`;
  // Coming back from the pin page ("Wrong number?") re-fills the box so the user only
  // has to fix the typo.
  const prefill = record.phone ? String(record.phone).slice(COUNTRY_CODE.length) : '';
  const body = `
    <div class="expiry-timer" id="expiryTimer"></div>
    <div class="eyebrow">RoughBOOK Registration</div>
    <h1>Let's verify your number</h1>
    ${stepDots('phone')}
    <div class="sub">Enter the WhatsApp number you'd like linked to your account and we'll send you a verification code.</div>
    <div class="field">
      <label>Registering as</label>
      <input type="text" readonly value="${escapeHtml(identityLabel)}" tabindex="-1"/>
    </div>
    <div class="banner bad" id="banner"></div>
    <div class="field">
      <label for="phone">WhatsApp number</label>
      <div class="phone-field" id="phoneField">
        <span class="phone-prefix">+${COUNTRY_CODE}</span>
        <input id="phone" type="tel" inputmode="numeric" autocomplete="tel-national" placeholder="803 123 4567" aria-describedby="phoneErr"/>
      </div>
      <div class="err" id="phoneErr">Please enter all ${PHONE_LENGTH} digits (without the leading 0).</div>
    </div>
    <button class="btn" id="submitBtn">Send verification code</button>
    <script>
      const ID        = ${idJson};
      const PHONE_LEN = ${PHONE_LENGTH};
      const PREFILL   = ${safeJson(prefill)};
      const field     = document.getElementById('phoneField');
      const phoneIn   = document.getElementById('phone');
      const phoneErr  = document.getElementById('phoneErr');
      const banner    = document.getElementById('banner');
      const btn       = document.getElementById('submitBtn');

      // Whatever is typed, pasted or autofilled (0803…, +234 803…, 234803…) → the digits
      // that follow the fixed +234, capped at PHONE_LEN.
      function normalize(raw) {
        let d = String(raw || '').replace(/[^0-9]/g, '');
        if (d.indexOf('234') === 0 && d.length > PHONE_LEN) d = d.slice(3); // country code came along
        d = d.replace(/^0+/, '');                                            // +234 already stands in for the 0
        return d.slice(0, PHONE_LEN);
      }
      // '8031234567' → '803 123 4567'
      function format(d) {
        return d.slice(0, 3) + (d.length > 3 ? ' ' + d.slice(3, 6) : '') + (d.length > 6 ? ' ' + d.slice(6) : '');
      }
      function caretAfterDigit(formatted, n) {
        if (n <= 0) return 0;
        let seen = 0;
        for (let i = 0; i < formatted.length; i++) {
          if (/[0-9]/.test(formatted.charAt(i)) && ++seen === n) return i + 1;
        }
        return formatted.length;
      }
      function currentDigits() { return phoneIn.value.replace(/[^0-9]/g, ''); }
      function isComplete() { return currentDigits().length === PHONE_LEN; }
      function validate(showError) {
        const ok = isComplete();
        if (showError) { phoneErr.classList.toggle('show', !ok); field.classList.toggle('bad', !ok); }
        else if (ok) { phoneErr.classList.remove('show'); field.classList.remove('bad'); }
        return ok;
      }

      phoneIn.addEventListener('input', () => {
        const raw        = phoneIn.value;
        const rawDigits  = raw.replace(/[^0-9]/g, '');
        const caret      = phoneIn.selectionStart == null ? raw.length : phoneIn.selectionStart;
        const digitsLeft = raw.slice(0, caret).replace(/[^0-9]/g, '').length;
        const digits     = normalize(raw);
        const formatted  = format(digits);
        phoneIn.value = formatted;
        // Keep the caret where the user was typing. Cutting digits off the END (number
        // already full) doesn't move anything before the caret; only a stripped leading
        // 0 / +234 shifts positions, in which case park the caret at the end.
        const pos = rawDigits.indexOf(digits) === 0
          ? caretAfterDigit(formatted, Math.min(digitsLeft, digits.length))
          : formatted.length;
        try { phoneIn.setSelectionRange(pos, pos); } catch (e) {}
        validate(false);
      });
      phoneIn.addEventListener('keydown', (e) => { if (e.key === 'Enter') btn.click(); });
      // Tapping the +234 chip or the padding around the box still puts the cursor in it.
      field.addEventListener('mousedown', (e) => { if (e.target !== phoneIn) { e.preventDefault(); phoneIn.focus(); } });

      if (PREFILL) phoneIn.value = format(normalize(PREFILL));
      phoneIn.focus();
      phoneIn.setSelectionRange(phoneIn.value.length, phoneIn.value.length);

      // If a submit fails purely due to a dropped connection (not a real error response),
      // wait for the browser to report it's back online (or 8s, whichever first) and retry
      // automatically — no need for the user to tap the button again.
      function retryOnReconnect(attemptFn, bannerEl) {
        bannerEl.classList.remove('good'); bannerEl.classList.add('bad');
        bannerEl.textContent = "No connection — we'll retry automatically once you're back online.";
        bannerEl.classList.add('show');
        let fired = false, timer;
        function retryNow() {
          if (fired) return;
          fired = true;
          window.removeEventListener('online', retryNow);
          clearTimeout(timer);
          bannerEl.textContent = 'Reconnected — retrying…';
          attemptFn();
        }
        window.addEventListener('online', retryNow);
        timer = setTimeout(retryNow, 8000);
      }

      async function attemptSendPhone() {
        btn.disabled = true; btn.textContent = 'Sending…';
        try {
          const r = await fetch('/signup/' + ID + '/phone', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
            body: JSON.stringify({ phone: currentDigits() })
          });
          const data = await r.json();
          if (data.ok) { location.reload(); return; }
          banner.classList.remove('good'); banner.classList.add('bad');
          banner.textContent = data.error || 'Something went wrong. Please try again.';
          banner.classList.add('show');
          if (data.locked) { btn.disabled = true; setTimeout(() => location.reload(), 1800); return; }
          btn.disabled = false; btn.textContent = 'Send verification code';
        } catch (e) {
          retryOnReconnect(attemptSendPhone, banner);
        }
      }

      btn.addEventListener('click', () => {
        banner.classList.remove('show');
        if (!validate(true)) { phoneIn.focus(); return; }
        attemptSendPhone();
      });
    </script>`;
  return shell(body, 'RoughBOOK — Verify Number', tokenPersistScript(id, record.sessionToken) + expiryTimerScript(record.expiresAt));
}

// ── Stage 2: pin ──────────────────────────────────────────────────────────────
function pinPage(id, record) {
  const idJson = safeJson(id);
  const boxes = Array.from({ length: PIN_LENGTH }, (_, i) =>
    `<input class="pin-box" maxlength="1" inputmode="numeric" pattern="[0-9]*" data-i="${i}"/>`).join('');
  // Real timestamp of when the last code went out, so the cooldown on the resend button
  // reflects actual elapsed time — not a fresh RESEND_COOLDOWN_SECONDS every time this
  // page happens to reload. Falls back to "now" only for the (shouldn't-happen) case of
  // a missing timestamp, which just means the button starts disabled for a full cooldown.
  const resendReadyAt = (record.lastCodeSentAt || Date.now()) + RESEND_COOLDOWN_SECONDS * 1000;
  const body = `
    <div class="expiry-timer" id="expiryTimer"></div>
    <div class="eyebrow">RoughBOOK Registration</div>
    <h1>Enter your code</h1>
    ${stepDots('pin')}
    <div class="sub">We sent a ${PIN_LENGTH}-digit code to <strong>${escapeHtml(formatPhone(record.phone))}</strong>.</div>
    <div class="banner bad" id="banner"></div>
    <div class="pin-row">${boxes}</div>
    <div class="err" id="pinErr" style="text-align:center;margin-bottom:14px;">Please enter all ${PIN_LENGTH} digits.</div>
    <button class="btn" id="submitBtn">Verify code</button>
    <div class="resend-row"><button type="button" class="resend-btn" id="resendBtn" disabled>Resend code</button></div>
    <div style="text-align:center;margin-top:10px;">
      <a href="#" id="wrongPhoneLink" style="color:var(--muted);font-size:.8rem;text-decoration:underline;">Wrong number? Go back</a>
    </div>
    <script>
     const ID = ${idJson};
const PIN_LEN = ${PIN_LENGTH};
const RESEND_SECONDS = ${RESEND_COOLDOWN_SECONDS};
let RESEND_READY_AT = ${resendReadyAt};
const boxesEls = Array.from(document.querySelectorAll('.pin-box'));
const pinErr     = document.getElementById('pinErr');
const banner     = document.getElementById('banner');
const btn        = document.getElementById('submitBtn');
const resendBtn  = document.getElementById('resendBtn');
const wrongPhoneLink = document.getElementById('wrongPhoneLink');
let verifying = false; // guards against double-submit (auto-trigger + manual tap racing)

function disableEverything() {
  boxesEls.forEach(b => b.disabled = true);
  btn.disabled = true;
  resendBtn.disabled = true;
  wrongPhoneLink.style.pointerEvents = 'none';
  wrongPhoneLink.style.opacity = '.4';
}
function showBanner(msg, good) {
  banner.textContent = msg;
  banner.classList.toggle('good', !!good);
  banner.classList.toggle('bad', !good);
  banner.classList.add('show');
}
function lockedOut(msg) {
  showBanner(msg, false);
  disableEverything();
  setTimeout(() => location.reload(), 1800);
}

function retryOnReconnect(attemptFn) {
  showBanner("No connection — we'll retry automatically once you're back online.", false);
  let fired = false, timer;
  function retryNow() {
    if (fired) return;
    fired = true;
    window.removeEventListener('online', retryNow);
    clearTimeout(timer);
    showBanner('Reconnected — retrying…', false);
    attemptFn();
  }
  window.addEventListener('online', retryNow);
  timer = setTimeout(retryNow, 8000);
}

function currentCode() { return boxesEls.map(b => b.value).join(''); }

// Fires the moment all PIN_LEN digits are present — no button tap required.
function maybeAutoSubmit() {
  if (verifying) return;
  if (currentCode().length === PIN_LEN) {
    pinErr.classList.remove('show');
    attemptVerify();
  }
}

boxesEls.forEach((el, i) => {
  el.addEventListener('input', () => {
    el.value = el.value.replace(/[^0-9]/g, '').slice(0, 1);
    if (el.value && i < boxesEls.length - 1) boxesEls[i + 1].focus();
    maybeAutoSubmit();
  });
  el.addEventListener('keydown', (e) => {
    if (e.key === 'Backspace' && !el.value && i > 0) boxesEls[i - 1].focus();
  });
  el.addEventListener('paste', (e) => {
    e.preventDefault();
    const digits = (e.clipboardData.getData('text') || '').replace(/[^0-9]/g, '').split('');
    boxesEls.forEach((b, j) => { b.value = digits[j] || ''; });
    (boxesEls[Math.min(digits.length, boxesEls.length) - 1] || boxesEls[0]).focus();
    maybeAutoSubmit();
  });
});

async function attemptVerify() {
  verifying = true;
  btn.disabled = true; btn.textContent = 'Verifying…';
  try {
    const r = await fetch('/signup/' + ID + '/verify', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
      body: JSON.stringify({ code: currentCode() })
    });
    const data = await r.json();
    if (data.ok) { location.reload(); return; }
    if (data.locked) { lockedOut(data.error || 'Too many incorrect attempts.'); return; }
    showBanner(data.error || 'Incorrect code, try again.', false);
    boxesEls.forEach(b => b.value = '');
    boxesEls[0].focus();
    btn.disabled = false; btn.textContent = 'Verify code';
    verifying = false;
  } catch (e) {
    verifying = false;
    retryOnReconnect(attemptVerify);
  }
}

// Manual tap still works as a fallback (e.g. if autofill drops an input event).
btn.addEventListener('click', () => {
  banner.classList.remove('show');
  const code = currentCode();
  if (code.length !== PIN_LEN) { pinErr.classList.add('show'); return; }
  pinErr.classList.remove('show');
  attemptVerify();
});
boxesEls[0].focus();

async function attemptBackToPhone() {
  try {
    const r = await fetch('/signup/' + ID + '/back-to-phone', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: '{}'
    });
    const data = await r.json();
    if (data.locked) { lockedOut(data.error); return; }
    if (data.ok) { location.reload(); return; }
    showBanner(data.error || 'Something went wrong. Please try again.', false);
  } catch (err) {
    retryOnReconnect(attemptBackToPhone);
  }
}

wrongPhoneLink.addEventListener('click', (e) => {
  e.preventDefault();
  banner.classList.remove('show');
  attemptBackToPhone();
});

let resendCooldown = 0;
let cooldownInterval = null;
function startResendCooldown(seconds) {
  clearInterval(cooldownInterval);
  resendCooldown = seconds;
  resendBtn.disabled = true;
  resendBtn.textContent = 'Resend code (' + resendCooldown + 's)';
  cooldownInterval = setInterval(() => {
    resendCooldown--;
    if (resendCooldown <= 0) {
      clearInterval(cooldownInterval);
      resendBtn.disabled = false;
      resendBtn.textContent = 'Resend code';
    } else {
      resendBtn.textContent = 'Resend code (' + resendCooldown + 's)';
    }
  }, 1000);
}

function syncResendCooldown() {
  const remaining = Math.ceil((RESEND_READY_AT - Date.now()) / 1000);
  if (remaining > 0) startResendCooldown(remaining);
  else { clearInterval(cooldownInterval); resendBtn.disabled = false; resendBtn.textContent = 'Resend code'; }
}

async function attemptResend() {
  resendBtn.disabled = true;
  try {
    const r = await fetch('/signup/' + ID + '/resend', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: '{}'
    });
    const data = await r.json();
    if (data.locked) { lockedOut(data.error); return; }
    if (data.ok) {
      showBanner('A new code has been sent.', true);
      boxesEls.forEach(b => b.value = '');
      boxesEls[0].focus();
      RESEND_READY_AT = data.resendReadyAt || (Date.now() + RESEND_SECONDS * 1000);
      syncResendCooldown();
      return;
    }
    showBanner(data.error || 'Could not resend the code.', false);
    resendBtn.disabled = false;
  } catch (e) {
    retryOnReconnect(attemptResend);
  }
}

resendBtn.addEventListener('click', () => {
  banner.classList.remove('show');
  attemptResend();
});
syncResendCooldown();
    </script>`;
  return shell(body, 'RoughBOOK — Enter Code', tokenPersistScript(id, record.sessionToken) + expiryTimerScript(record.expiresAt));
}

// ── Stage 3: details ──────────────────────────────────────────────────────────
function detailsPage(id, record) {
  const idJson      = safeJson(id);
  const optionsJson = safeJson(record.academicOptions);
  const body = `
    <div class="expiry-timer" id="expiryTimer"></div>
    <div class="eyebrow">RoughBOOK Registration</div>
    <h1>Almost done</h1>
    ${stepDots('details')}
    <div class="sub">Tell us where you study.</div>
    <div class="banner bad" id="banner"></div>
    <div class="field">
      <label for="school">School</label>
      <select id="school"><option value="">Select school</option></select>
    </div>
    <div class="field">
      <label for="department">Department</label>
      <select id="department" disabled><option value="">Select department</option></select>
    </div>
    <div class="field">
      <label for="level">Level</label>
      <select id="level" disabled><option value="">Select level</option></select>
    </div>
    <div class="helper-note">Can't find your school, department, or level? <a href="${ADMIN_CONTACT_URL}" target="_blank" rel="noopener noreferrer">Contact the admin</a>.</div>
    <div class="checkbox-row">
      <input type="checkbox" id="agree"/>
      <label for="agree">I agree to the <a href="${TERMS_URL}" target="_blank" rel="noopener noreferrer">Terms and Conditions</a>.</label>
    </div>
    <button class="btn" id="submitBtn" disabled>Complete registration</button>
    <script>
      const ID = ${idJson};
      const OPTIONS = ${optionsJson};
      const schoolSel = document.getElementById('school');
      const deptSel    = document.getElementById('department');
      const levelSel   = document.getElementById('level');
      const agreeBox   = document.getElementById('agree');
      const btn        = document.getElementById('submitBtn');
      const banner     = document.getElementById('banner');

      const schools = [...new Set(OPTIONS.map(o => o.school))];
      schools.forEach(s => schoolSel.add(new Option(s, s)));

      function checkValid() {
        btn.disabled = !(schoolSel.value && deptSel.value && levelSel.value && agreeBox.checked);
      }

      schoolSel.addEventListener('change', () => {
        deptSel.innerHTML = '<option value="">Select department</option>';
        levelSel.innerHTML = '<option value="">Select level</option>';
        levelSel.disabled = true;
        if (!schoolSel.value) { deptSel.disabled = true; checkValid(); return; }
        const depts = [...new Set(OPTIONS.filter(o => o.school === schoolSel.value).map(o => o.department))];
        depts.forEach(d => deptSel.add(new Option(d, d)));
        deptSel.disabled = false;
        checkValid();
      });

      deptSel.addEventListener('change', () => {
        levelSel.innerHTML = '<option value="">Select level</option>';
        if (!deptSel.value) { levelSel.disabled = true; checkValid(); return; }
        const levels = [...new Set(OPTIONS.filter(o => o.school === schoolSel.value && o.department === deptSel.value).map(o => o.level))];
        levels.forEach(l => levelSel.add(new Option(l, l)));
        levelSel.disabled = false;
        checkValid();
      });

      levelSel.addEventListener('change', checkValid);
      agreeBox.addEventListener('change', checkValid);

      // If a submit fails purely due to a dropped connection (not a real error response),
      // wait for the browser to report it's back online (or 8s, whichever first) and retry
      // automatically — no need for the user to tap the button again.
      function retryOnReconnect(attemptFn) {
        banner.classList.remove('good'); banner.classList.add('bad');
        banner.textContent = "No connection — we'll retry automatically once you're back online.";
        banner.classList.add('show');
        let fired = false, timer;
        function retryNow() {
          if (fired) return;
          fired = true;
          window.removeEventListener('online', retryNow);
          clearTimeout(timer);
          banner.textContent = 'Reconnected — retrying…';
          attemptFn();
        }
        window.addEventListener('online', retryNow);
        timer = setTimeout(retryNow, 8000);
      }

      async function attemptComplete() {
        btn.disabled = true; btn.textContent = 'Submitting…';
        try {
          const r = await fetch('/signup/' + ID + '/complete', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
            body: JSON.stringify({ school: schoolSel.value, department: deptSel.value, level: levelSel.value, agreed: agreeBox.checked })
          });
          const data = await r.json();
          if (data.ok) {
            try { localStorage.removeItem('st_' + ID); } catch (e) {}
            // replace() (not href) so the Back button can't return to a finished form
            if (data.redirectUrl) window.location.replace(data.redirectUrl); else location.reload();
            return;
          }
          banner.classList.remove('good'); banner.classList.add('bad');
          banner.textContent = data.error || 'Something went wrong. Please try again.';
          banner.classList.add('show');
          if (data.locked) { btn.disabled = true; setTimeout(() => location.reload(), 1800); return; }
          btn.disabled = false; btn.textContent = 'Complete registration';
          checkValid();
        } catch (e) {
          retryOnReconnect(attemptComplete);
        }
      }

      btn.addEventListener('click', () => {
        banner.classList.remove('show');
        attemptComplete();
      });
    </script>`;
  return shell(body, 'RoughBOOK — Academic Details', tokenPersistScript(id, record.sessionToken) + expiryTimerScript(record.expiresAt));
}

// ── Stage 4: done ─────────────────────────────────────────────────────────────
// Normally the browser has already been sent to the redirect url straight from the
// /complete response and never lands here. This page covers a reload / Back / revisit of
// a finished link — it redirects immediately too, with a tap-through link as a fallback.
function donePage(id, record) {
  const url = record.redirectUrl || CONTACT_URL;
  const body = `
    <div class="center-icon">🎉</div>
    <h1 style="text-align:center;">You're all set, ${escapeHtml(record.username)}!</h1>
    <div class="sub" style="text-align:center;margin-bottom:0;">Taking you there now… <a href="${escapeHtml(url)}" style="color:var(--accent2);text-decoration:underline;">Tap here</a> if nothing happens.</div>`;
  const script = `<script>try{localStorage.removeItem('st_' + ${safeJson(id)});}catch(e){} window.location.replace(${safeJson(url)});</script>`;
  return shell(body, 'RoughBOOK — Registration Complete', script);
}

// ── Expired / recovery pages ──────────────────────────────────────────────────
function expiredPage() {
  const body = `
    <div class="center-icon">⏳</div>
    <h1 style="text-align:center;">Link expired</h1>
    <div class="sub" style="text-align:center;">This signup link is no longer valid — it may have expired, been used too many times, been replaced by a newer link, or already been completed.</div>
    <div class="sub" style="text-align:center;margin-bottom:0;"><a href="${CONTACT_URL}" target="_blank" rel="noopener noreferrer" style="color:var(--accent2);font-weight:600;text-decoration:underline;">Contact RoughBOOK</a> on WhatsApp to start again.</div>`;
  return shell(body, 'RoughBOOK — Link Expired');
}

function claimedPage(id) {
  const idJson = safeJson(id);
  const body = `
    <div class="center-icon" id="iconChecking">🔒</div>
    <h1 style="text-align:center;" id="titleChecking">Reconnecting…</h1>
    <div class="sub" style="text-align:center;" id="msgChecking">Verifying your session…</div>
    <div id="errorBox" style="display:none;">
      <div class="center-icon">⚠️</div>
      <h1 style="text-align:center;color:var(--bad);">Link unavailable</h1>
      <div class="sub" style="text-align:center;margin-bottom:0;">This signup link is already in use by another session.</div>
    </div>
    <script>
      (function() {
        var tok = localStorage.getItem('st_' + ${idJson});
        if (!tok) { showError(); return; }
        fetch('/signup/' + ${idJson} + '/recover', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
          body: JSON.stringify({ token: tok })
        }).then(function(r) {
          if (r.ok) location.href = '/signup/' + ${idJson};
          else showError();
        }).catch(showError);
        function showError() {
          document.getElementById('iconChecking').style.display = 'none';
          document.getElementById('titleChecking').style.display = 'none';
          document.getElementById('msgChecking').style.display = 'none';
          document.getElementById('errorBox').style.display = 'block';
        }
      })();
    </script>`;
  return shell(body, 'RoughBOOK — Reconnecting');
}
