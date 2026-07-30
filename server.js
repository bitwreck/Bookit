'use strict';
require('dotenv').config();

const express     = require('express');
const cors        = require('cors');
const path        = require('path');
const rateLimit   = require('express-rate-limit');
const apiRouter   = require('./routes/api');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ─────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Rate-limit the API (global)
app.use('/api', rateLimit({
  windowMs: 60 * 1000,   // 1 minute
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, slow down.' },
}));

// Rate-limit login endpoint more aggressively
app.use('/api/admin/login', rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 10,
  message: { error: 'Too many login attempts' },
}));

// ── Routes ─────────────────────────────────────────────────
app.use('/api', apiRouter);

// SPA fallback – serve index.html for unknown routes
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── JSON body parse error handler ─────────────────────────
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON in request body' });
  }
  next(err);
});

// ── Global error handler ───────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error(err.stack || err.message || err);
  res.status(err.status || 500).json({ error: err.message || 'Internal server error' });
});

// ── Start ──────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  Booking Tool running at http://localhost:${PORT}`);
  console.log(`  Admin panel:           http://localhost:${PORT}/admin.html`);
  console.log(`  Default login:         admin / Admin1234!\n`);
  startPurgeScheduler();
});

// ── Background purge scheduler ────────────────────────────
const db = require('./database');

function toMs(value, unit) {
  const v = parseInt(value) || 1;
  switch (unit) {
    case 'days':   return v * 24 * 60 * 60 * 1000;
    case 'weeks':  return v *  7 * 24 * 60 * 60 * 1000;
    case 'months': return v * 30 * 24 * 60 * 60 * 1000;
    default:       return v * 30 * 24 * 60 * 60 * 1000;
  }
}

async function startPurgeScheduler() {
  // Check every hour whether a scheduled purge is due
  setInterval(async () => {
    try {
      const [rows] = await db.execute("SELECT `key`, `value` FROM settings WHERE `key` LIKE 'purge_%'");
      const s = {};
      rows.forEach(r => { s[r.key] = r.value; });

      if (s.purge_enabled !== 'true') return;

      const scheduleMs = toMs(s.purge_schedule_value, s.purge_schedule_unit);
      const lastRun    = s.purge_last_run ? new Date(s.purge_last_run).getTime() : 0;

      if (Date.now() - lastRun < scheduleMs) return;  // not due yet

      const { runPurge } = require('./routes/api');
      await runPurge();
    } catch (err) {
      console.error('[Purge] Scheduler error:', err.message);
    }
  }, 60 * 60 * 1000); // check every hour

  console.log('  Purge scheduler started (checks every hour)\n');
}
