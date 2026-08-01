'use strict';
const express    = require('express');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const ldap       = require('ldapjs');
const db         = require('../database');
const requireAdmin = require('../middleware/auth');

const router = express.Router();

// ═══════════════════════════════════════════════════════════
// Async error wrapper (Express 4 doesn't catch async throws)
// ═══════════════════════════════════════════════════════════
const ah = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════
function pad(n) { return String(n).padStart(2, '0'); }

/** Extract the real client IP, handling common proxy headers. */
function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.socket?.remoteAddress || null;
}

/** Write one row to the activity log (fire-and-forget). */
async function logActivity(action, appt, actor, ip) {
  try {
    await db.execute(
      `INSERT INTO activity_log (action, appointment_title, resource_name, resource_color, actor, ip_address)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [action, appt.title, appt.resource_name || '', appt.resource_color || '#64748b', actor || null, ip || null]
    );
  } catch (e) {
    console.error('activity_log insert failed:', e.message);
  }
}

function toISOLocal(dt) {
  // dt is a JS Date already in UTC from MariaDB (pool timezone Z)
  return dt instanceof Date ? dt.toISOString() : dt;
}

// MariaDB DATETIME columns reject ISO strings with 'Z' or milliseconds.
// Convert any ISO string → 'YYYY-MM-DD HH:MM:SS' (UTC).
function toDBDatetime(val) {
  return new Date(val).toISOString().slice(0, 19).replace('T', ' ');
}

/** Build an RFC-5545 ICS string for one appointment. */
function buildICS(appt) {
  const fmt = (d) => {
    const dt = new Date(d);
    return [
      dt.getUTCFullYear(),
      pad(dt.getUTCMonth() + 1),
      pad(dt.getUTCDate()),
      'T',
      pad(dt.getUTCHours()),
      pad(dt.getUTCMinutes()),
      pad(dt.getUTCSeconds()),
      'Z',
    ].join('');
  };

  const now   = fmt(new Date());
  const uid   = `appt-${appt.id}@booking-tool`;
  const lines = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'PRODID:-//BookingTool//EN',
    'CALSCALE:GREGORIAN',
    'METHOD:PUBLISH',
    'BEGIN:VEVENT',
    `UID:${uid}`,
    `DTSTAMP:${now}`,
    `DTSTART:${fmt(appt.start_time)}`,
    `DTEND:${fmt(appt.end_time)}`,
    `SUMMARY:${(appt.title || '').replace(/\n/g, '\\n')}`,
    `DESCRIPTION:${(appt.description || '').replace(/\n/g, '\\n')}`,
    `ORGANIZER;CN=${appt.booked_by_name}:MAILTO:${appt.booked_by_email}`,
    `X-RESOURCE:${appt.resource_name || ''}`,
    'END:VEVENT',
    'END:VCALENDAR',
  ];
  return lines.join('\r\n');
}

// ═══════════════════════════════════════════════════════════
// Admin Auth
// ═══════════════════════════════════════════════════════════
router.post('/admin/login', ah(async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: 'username and password required' });

  const [rows] = await db.execute(
    'SELECT * FROM admins WHERE username = ?', [username]
  );
  const admin = rows[0];
  if (!admin) return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, admin.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign(
    { id: admin.id, username: admin.username },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '8h' }
  );
  res.json({ token, username: admin.username });
}));

/** Change admin password (requires current auth) */
router.put('/admin/password', requireAdmin, ah(async (req, res) => {
  const { newPassword } = req.body || {};
  if (!newPassword || newPassword.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const hash = await bcrypt.hash(newPassword, 10);
  await db.execute('UPDATE admins SET password_hash = ? WHERE id = ?',
    [hash, req.admin.id]);
  res.json({ ok: true });
}));

// ═══════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════
// LDAP helpers
// ═══════════════════════════════════════════════════════════

/** Escape special characters in an LDAP filter value (RFC 4515). */
function escapeLdapFilter(str) {
  return String(str).replace(/[*()\\\/\0]/g, c =>
    '\\' + c.charCodeAt(0).toString(16).padStart(2, '0')
  );
}

/** Write an LDAP event to the ldap_log table (fire-and-forget). */
function logLdapEvent(event, email, detail, ip = null) {
  db.execute(
    'INSERT INTO ldap_log (event, email, detail, ip_address) VALUES (?, ?, ?, ?)',
    [event, email || null, detail || null, ip]
  ).catch(err => console.error('[LDAP] Failed to write ldap_log:', err.message));
}

/** Load all ldap_* keys from the settings table into a single object. */
async function getLDAPConfig() {
  const [rows] = await db.execute(
    "SELECT `key`, `value` FROM settings WHERE `key` LIKE 'ldap_%'"
  );
  const cfg = {};
  rows.forEach(r => { cfg[r.key] = r.value; });
  return cfg;
}

/** Promisify ldapjs client.bind */
function ldapBind(client, dn, password) {
  return new Promise((resolve, reject) =>
    client.bind(dn, password, err => (err ? reject(err) : resolve()))
  );
}

/** Promisify ldapjs client.search — resolves with array of entries */
function ldapSearch(client, base, opts) {
  return new Promise((resolve, reject) => {
    client.search(base, opts, (err, res) => {
      if (err) return reject(err);
      const entries = [];
      res.on('searchEntry', e => entries.push(e));
      res.on('error',       reject);
      res.on('end',         () => resolve(entries));
    });
  });
}

/**
 * Authenticate a user against the LDAP directory.
 * Returns { name, email, phone } on success, throws on failure.
 */
async function ldapAuthenticate(email, password, ip = null) {
  const cfg = await getLDAPConfig();
  if (cfg.ldap_enabled !== 'true') throw new Error('LDAP is not enabled');

  const client = ldap.createClient({
    url:            cfg.ldap_url,
    timeout:        8000,
    connectTimeout: 8000,
    reconnect:      false,           // don't retry — fail fast
    tlsOptions: {
      rejectUnauthorized: false,  // allow self-signed certs
      minVersion: 'TLSv1',        // permit older TLS versions some LDAP servers require
    },
  });

  // Attach a persistent error handler to prevent Node from crashing on
  // unhandled 'error' events emitted during ldapjs's reconnect backoff cycle
  client.on('error', err => {
    console.error('[LDAP] Client error:', err.message);
  });

  // Surface connection errors immediately
  await new Promise((resolve, reject) => {
    client.once('connect', resolve);
    client.once('error',   reject);
    setTimeout(resolve, 100);
  }).catch(() => {});

  try {
    // Bind with service account to search the directory
    try {
      await ldapBind(client, cfg.ldap_bind_dn, cfg.ldap_bind_pass);
    } catch (err) {
      const detail = `Service account bind failed (url=${cfg.ldap_url} dn=${cfg.ldap_bind_dn}): ${err.message}`;
      console.error(`[LDAP] ${detail}`);
      logLdapEvent('bind_failed', email, detail, ip);
      throw err;
    }

    // Build search filter — replace {{username}} with the escaped email
    const escapedEmail = escapeLdapFilter(email);
    const filter = (cfg.ldap_user_filter || '(mail={{username}})')
      .replace(/\{\{username\}\}/g, escapedEmail);

    const attrs = [cfg.ldap_name_attr, cfg.ldap_email_attr];
    if (cfg.ldap_phone_attr) attrs.push(cfg.ldap_phone_attr);

    console.log(`[LDAP] Searching for user: ${email} (filter=${filter} base=${cfg.ldap_base_dn})`);
    let entries;
    try {
      entries = await ldapSearch(client, cfg.ldap_base_dn, {
        filter,
        scope:      'sub',
        attributes: attrs,
      });
    } catch (err) {
      const detail = `Search failed (base=${cfg.ldap_base_dn} filter=${filter}): ${err.message}`;
      console.error(`[LDAP] ${detail}`);
      logLdapEvent('search_failed', email, detail, ip);
      throw err;
    }

    if (!entries.length) {
      const detail = `No directory entry found (filter=${filter} base=${cfg.ldap_base_dn})`;
      console.warn(`[LDAP] ${detail}`);
      logLdapEvent('user_not_found', email, detail, ip);
      throw new Error('No matching user found in directory');
    }

    const entry  = entries[0];
    const obj    = entry.object || {};
    const userDN = entry.objectName;

    // Re-bind as the user to verify their password
    try {
      await ldapBind(client, userDN, password);
    } catch (err) {
      const detail = `Invalid credentials for dn=${userDN}: ${err.message}`;
      console.warn(`[LDAP] ${detail}`);
      logLdapEvent('auth_failed', email, detail, ip);
      throw err;
    }

    console.log(`[LDAP] Authentication successful for: ${email}`);
    logLdapEvent('success', email, `Authenticated via ${cfg.ldap_url}`, ip);
    return {
      name:  obj[cfg.ldap_name_attr]  || email,
      email: (obj[cfg.ldap_email_attr] || email).toLowerCase(),
      phone: cfg.ldap_phone_attr ? (obj[cfg.ldap_phone_attr] || null) : null,
    };
  } finally {
    client.unbind();
  }
}

// ═══════════════════════════════════════════════════════════
// User Auth
// ═══════════════════════════════════════════════════════════
router.post('/auth/register', ah(async (req, res) => {
  const { first_name, last_name, email, phone, timezone, password } = req.body || {};
  if (!first_name?.trim() || !last_name?.trim() || !email?.trim())
    return res.status(400).json({ error: 'First name, last name, and email are required' });
  if (!password || password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const name  = `${first_name.trim()} ${last_name.trim()}`;
  const clean = email.trim().toLowerCase();
  const tz    = timezone?.trim() || 'UTC';

  const [[existing]] = await db.execute('SELECT id FROM users WHERE email = ?', [clean]);
  if (existing)
    return res.status(409).json({ error: 'An account with this email already exists. Please sign in.' });

  const password_hash = await bcrypt.hash(password, 10);

  const [result] = await db.execute(
    'INSERT INTO users (name, email, phone, timezone, password_hash) VALUES (?, ?, ?, ?, ?)',
    [name, clean, phone?.trim() || null, tz, password_hash]
  );

  const token = jwt.sign(
    { type: 'user', userId: result.insertId, name, email: clean, phone: phone?.trim() || null, timezone: tz, authSource: 'local' },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );

  res.status(201).json({ token, user: { id: result.insertId, name, email: clean, phone: phone?.trim() || null, timezone: tz, authSource: 'local' } });
}));

router.post('/auth/login', ah(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email?.trim()) return res.status(400).json({ error: 'Email is required' });
  if (!password)      return res.status(400).json({ error: 'Password is required' });

  const clean = email.trim().toLowerCase();

  // Look up user first to determine auth source
  const [[user]] = await db.execute(
    'SELECT id, name, email, phone, timezone, auth_source, password_hash FROM users WHERE email = ?', [clean]
  );

  // ── LDAP path ─────────────────────────────────────────────
  if (user?.auth_source === 'ldap') {
    const ip = getClientIP(req);
    let ldapUser;
    try {
      ldapUser = await ldapAuthenticate(clean, password, ip);
    } catch (err) {
      const msg = err.message?.includes('Invalid Credentials') || err.message?.includes('bind')
        ? 'Invalid email or password.'
        : (err.message || 'LDAP authentication failed.');
      return res.status(401).json({ error: msg });
    }

    // Update name/phone and last_login_at from LDAP on each login
    await db.execute(
      `UPDATE users SET name=?, phone=?, last_login_at=NOW() WHERE email=?`,
      [ldapUser.name, ldapUser.phone, ldapUser.email]
    );
    const [[updated]] = await db.execute(
      'SELECT id, name, email, phone, timezone FROM users WHERE email = ?', [ldapUser.email]
    );

    const token = jwt.sign(
      { type: 'user', userId: updated.id, name: updated.name, email: updated.email,
        phone: updated.phone || null, timezone: updated.timezone || 'UTC', authSource: 'ldap' },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );
    return res.json({
      token,
      user: { id: updated.id, name: updated.name, email: updated.email,
              phone: updated.phone || null, timezone: updated.timezone || 'UTC', authSource: 'ldap' },
    });
  }

  // ── LDAP path: user not in DB yet (first LDAP login) ──────
  if (!user) {
    // Try LDAP — if LDAP is enabled and user is not in DB, attempt LDAP auth
    const ldapEnabled = await getSetting('ldap_enabled', 'false');
    if (ldapEnabled === 'true') {
      const ip = getClientIP(req);
      let ldapUser;
      try {
        ldapUser = await ldapAuthenticate(clean, password, ip);
      } catch {
        return res.status(401).json({ error: 'No account found with this email. Please register first.' });
      }
      const tz = 'UTC';
      await db.execute(
        `INSERT INTO users (name, email, phone, timezone, auth_source, last_login_at)
         VALUES (?, ?, ?, ?, 'ldap', NOW())
         ON DUPLICATE KEY UPDATE name=VALUES(name), phone=VALUES(phone), auth_source='ldap', last_login_at=NOW()`,
        [ldapUser.name, ldapUser.email, ldapUser.phone, tz]
      );
      const [[newUser]] = await db.execute(
        'SELECT id, name, email, phone, timezone FROM users WHERE email = ?', [ldapUser.email]
      );
      const token = jwt.sign(
        { type: 'user', userId: newUser.id, name: newUser.name, email: newUser.email,
          phone: newUser.phone || null, timezone: newUser.timezone || 'UTC', authSource: 'ldap' },
        process.env.JWT_SECRET,
        { expiresIn: '30d' }
      );
      return res.json({
        token,
        user: { id: newUser.id, name: newUser.name, email: newUser.email,
                phone: newUser.phone || null, timezone: newUser.timezone || 'UTC', authSource: 'ldap' },
      });
    }
    return res.status(404).json({ error: 'No account found with this email. Please register first.' });
  }

  // ── Local path: verify password ───────────────────────────
  if (!user.password_hash)
    return res.status(401).json({ error: 'This account has no password set. Please contact an administrator.' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Incorrect password.' });

  // Fire-and-forget — don't block the response
  db.execute('UPDATE users SET last_login_at=NOW() WHERE id=?', [user.id]).catch(() => {});

  const token = jwt.sign(
    { type: 'user', userId: user.id, name: user.name, email: user.email,
      phone: user.phone || null, timezone: user.timezone || 'UTC', authSource: 'local' },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );
  res.json({
    token,
    user: { id: user.id, name: user.name, email: user.email,
            phone: user.phone || null, timezone: user.timezone || 'UTC', authSource: 'local' },
  });
}));

router.put('/auth/profile', ah(async (req, res) => {
  const auth = (req.headers.authorization || '').replace('Bearer ', '');
  if (!auth) return res.status(401).json({ error: 'Not authenticated' });

  let payload;
  try {
    payload = jwt.verify(auth, process.env.JWT_SECRET);
    if (payload.type !== 'user') throw new Error('wrong type');
  } catch {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }

  // Look up auth_source so we can restrict LDAP users
  const [[dbUser]] = await db.execute(
    'SELECT id, name, email, phone, timezone, auth_source FROM users WHERE id = ?', [payload.userId]
  );
  if (!dbUser) return res.status(404).json({ error: 'User not found' });

  const isLdap = dbUser.auth_source === 'ldap';
  const tz = (req.body?.timezone || '').trim() || payload.timezone || 'UTC';

  if (isLdap) {
    // LDAP users may only update timezone
    await db.execute('UPDATE users SET timezone = ? WHERE id = ?', [tz, payload.userId]);
  } else {
    const { first_name, last_name, email, phone } = req.body || {};
    if (!first_name?.trim() || !last_name?.trim() || !email?.trim())
      return res.status(400).json({ error: 'First name, last name, and email are required' });

    const name  = `${first_name.trim()} ${last_name.trim()}`;
    const clean = email.trim().toLowerCase();

    if (clean !== payload.email) {
      const [[existing]] = await db.execute(
        'SELECT id FROM users WHERE email = ? AND id != ?', [clean, payload.userId]
      );
      if (existing)
        return res.status(409).json({ error: 'That email is already used by another account.' });
    }

    await db.execute(
      'UPDATE users SET name = ?, email = ?, phone = ?, timezone = ? WHERE id = ?',
      [name, clean, phone?.trim() || null, tz, payload.userId]
    );
  }

  const [[user]] = await db.execute(
    'SELECT id, name, email, phone, timezone, auth_source FROM users WHERE id = ?', [payload.userId]
  );

  // Re-issue token with updated claims
  const token = jwt.sign(
    { type: 'user', userId: user.id, name: user.name, email: user.email,
      phone: user.phone, timezone: user.timezone, authSource: user.auth_source },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );

  res.json({ token, user: { ...user, authSource: user.auth_source } });
}));

router.get('/auth/me', ah(async (req, res) => {
  const auth = (req.headers.authorization || '').replace('Bearer ', '');
  if (!auth) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const payload = jwt.verify(auth, process.env.JWT_SECRET);
    if (payload.type !== 'user') return res.status(401).json({ error: 'Invalid token' });
    const [[user]] = await db.execute(
      'SELECT id, name, email, phone, timezone, auth_source FROM users WHERE id = ?', [payload.userId]
    );
    if (!user) return res.status(401).json({ error: 'User not found' });
    res.json({ ...user, authSource: user.auth_source });
  } catch {
    res.status(401).json({ error: 'Session expired. Please sign in again.' });
  }
}));

// ═══════════════════════════════════════════════════════════
// Settings
// ═══════════════════════════════════════════════════════════

/** Read a single setting value, returns the default if not found. */
async function getSetting(key, defaultValue = null) {
  const [[row]] = await db.execute(
    'SELECT `value` FROM settings WHERE `key` = ?', [key]
  );
  return row ? row.value : defaultValue;
}

/** Public: minimal settings needed by the public frontend. */
router.get('/settings', ah(async (_req, res) => {
  const ldapEnabled = await getSetting('ldap_enabled', 'false');
  res.json({
    ldap_enabled: ldapEnabled === 'true',
  });
}));

/** Admin: full settings (bind password intentionally omitted). */
router.get('/admin/settings', requireAdmin, ah(async (_req, res) => {
  const [rows] = await db.execute("SELECT `key`, `value` FROM settings");
  const s = {};
  rows.forEach(r => { s[r.key] = r.value; });
  res.json({
    https_redirect:      s.https_redirect !== 'false',   // default true
    ldap_enabled:        s.ldap_enabled === 'true',
    ldap_url:            s.ldap_url          || '',
    ldap_base_dn:        s.ldap_base_dn      || '',
    ldap_bind_dn:        s.ldap_bind_dn      || '',
    ldap_user_filter:    s.ldap_user_filter  || '(mail={{username}})',
    ldap_name_attr:      s.ldap_name_attr    || 'cn',
    ldap_email_attr:     s.ldap_email_attr   || 'mail',
    ldap_phone_attr:     s.ldap_phone_attr   || 'telephoneNumber',
    purge_enabled:        s.purge_enabled        === 'true',
    purge_retention_value:parseInt(s.purge_retention_value) || 12,
    purge_retention_unit: s.purge_retention_unit  || 'months',
    purge_schedule_value: parseInt(s.purge_schedule_value)  || 1,
    purge_schedule_unit:  s.purge_schedule_unit   || 'months',
    purge_last_run:       s.purge_last_run         || null,
  });
}));

/** Admin: update settings. */
router.put('/settings', requireAdmin, ah(async (req, res) => {
  const {
    ldap_enabled, ldap_url, ldap_base_dn, ldap_bind_dn, ldap_bind_pass,
    ldap_user_filter, ldap_name_attr, ldap_email_attr, ldap_phone_attr,
  } = req.body || {};

  const upsert = async (key, value) => db.execute(
    'INSERT INTO settings (`key`, `value`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)',
    [key, value]
  );

  const { https_redirect } = req.body || {};
  if (https_redirect !== undefined)
    await upsert('https_redirect', https_redirect ? 'true' : 'false');

  if (ldap_enabled !== undefined) await upsert('ldap_enabled', ldap_enabled ? 'true' : 'false');
  if (ldap_url       !== undefined) await upsert('ldap_url',       ldap_url);
  if (ldap_base_dn   !== undefined) await upsert('ldap_base_dn',   ldap_base_dn);
  if (ldap_bind_dn   !== undefined) await upsert('ldap_bind_dn',   ldap_bind_dn);
  if (ldap_bind_pass !== undefined) await upsert('ldap_bind_pass', ldap_bind_pass);
  if (ldap_user_filter !== undefined) await upsert('ldap_user_filter', ldap_user_filter);
  if (ldap_name_attr   !== undefined) await upsert('ldap_name_attr',   ldap_name_attr);
  if (ldap_email_attr  !== undefined) await upsert('ldap_email_attr',  ldap_email_attr);
  if (ldap_phone_attr  !== undefined) await upsert('ldap_phone_attr',  ldap_phone_attr);

  // Purge settings
  const { purge_enabled, purge_retention_value, purge_retention_unit,
          purge_schedule_value, purge_schedule_unit } = req.body || {};
  if (purge_enabled         !== undefined) await upsert('purge_enabled',         purge_enabled ? 'true' : 'false');
  if (purge_retention_value !== undefined) await upsert('purge_retention_value', String(parseInt(purge_retention_value) || 12));
  if (purge_retention_unit  !== undefined) await upsert('purge_retention_unit',  purge_retention_unit);
  if (purge_schedule_value  !== undefined) await upsert('purge_schedule_value',  String(parseInt(purge_schedule_value)  || 1));
  if (purge_schedule_unit   !== undefined) await upsert('purge_schedule_unit',   purge_schedule_unit);

  res.json({ ok: true });
}));

// ═══════════════════════════════════════════════════════════
// Activity feed
// ═══════════════════════════════════════════════════════════
router.get('/activity', ah(async (req, res) => {
  const VALID_LIMITS = [5, 25, 50, 75, 100];
  const limit  = VALID_LIMITS.includes(parseInt(req.query.limit)) ? parseInt(req.query.limit) : 5;
  const page   = Math.max(1, parseInt(req.query.page) || 1);
  const offset = (page - 1) * limit;

  const [[{ total }]] = await db.execute('SELECT COUNT(*) AS total FROM activity_log');
  const [rows] = await db.execute(
    'SELECT * FROM activity_log ORDER BY created_at DESC LIMIT ? OFFSET ?',
    [limit, offset]
  );

  res.json({
    total,
    page,
    limit,
    pages: Math.ceil(total / limit),
    data: rows.map(r => ({ ...r, created_at: toISOLocal(r.created_at) })),
  });
}));

// ═══════════════════════════════════════════════════════════
// Categories
// ═══════════════════════════════════════════════════════════
router.get('/categories', ah(async (_req, res) => {
  const [rows] = await db.execute(
    'SELECT id, name FROM categories ORDER BY name ASC'
  );
  res.json(rows);
}));

router.post('/categories', requireAdmin, ah(async (req, res) => {
  const name = (req.body?.name || '').trim();
  if (!name) return res.status(400).json({ error: 'name is required' });
  try {
    const [result] = await db.execute(
      'INSERT INTO categories (name) VALUES (?)', [name]
    );
    res.status(201).json({ id: result.insertId, name });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY')
      return res.status(409).json({ error: 'A category with that name already exists.' });
    throw err;
  }
}));

router.put('/categories/:id', requireAdmin, ah(async (req, res) => {
  const name = (req.body?.name || '').trim();
  if (!name) return res.status(400).json({ error: 'name is required' });
  try {
    const [result] = await db.execute(
      'UPDATE categories SET name = ? WHERE id = ?', [name, req.params.id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ id: parseInt(req.params.id), name });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY')
      return res.status(409).json({ error: 'A category with that name already exists.' });
    throw err;
  }
}));

router.delete('/categories/:id', requireAdmin, ah(async (req, res) => {
  // Block deletion if any resources still use this category
  const [[{ count }]] = await db.execute(
    'SELECT COUNT(*) AS count FROM resources WHERE category_id = ?', [req.params.id]
  );
  if (count > 0)
    return res.status(409).json({
      error: `Cannot delete: ${count} resource(s) are assigned to this category. Reassign them first.`
    });
  const [result] = await db.execute('DELETE FROM categories WHERE id = ?', [req.params.id]);
  if (result.affectedRows === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
}));

// ═══════════════════════════════════════════════════════════
// Resources
// ═══════════════════════════════════════════════════════════
router.get('/resources', ah(async (_req, res) => {
  const [rows] = await db.execute(
    `SELECT r.*, c.name AS category_name,
            COUNT(a.id) AS booking_count
     FROM resources r
     JOIN categories c ON c.id = r.category_id
     LEFT JOIN appointments a
            ON a.resource_id = r.id AND a.status != 'cancelled' AND a.user_id IS NOT NULL
     GROUP BY r.id, r.name, r.description, r.color, r.category_id, c.name, r.created_at, r.updated_at
     ORDER BY c.name ASC, r.name ASC`
  );
  res.json(rows);
}));

router.post('/resources', requireAdmin, ah(async (req, res) => {
  const { name, description, color, category_id } = req.body || {};
  if (!name)        return res.status(400).json({ error: 'name is required' });
  if (!category_id) return res.status(400).json({ error: 'category_id is required' });

  const safeColor = /^#[0-9a-fA-F]{6}$/.test(color) ? color : '#64748b';
  const [result] = await db.execute(
    'INSERT INTO resources (name, description, color, category_id) VALUES (?, ?, ?, ?)',
    [name, description || null, safeColor, category_id]
  );
  const [rows] = await db.execute(
    `SELECT r.*, c.name AS category_name FROM resources r
     JOIN categories c ON c.id = r.category_id WHERE r.id = ?`,
    [result.insertId]
  );
  res.status(201).json(rows[0]);
}));

router.put('/resources/:id', requireAdmin, ah(async (req, res) => {
  const { name, description, color, category_id } = req.body || {};
  if (!name)        return res.status(400).json({ error: 'name is required' });
  if (!category_id) return res.status(400).json({ error: 'category_id is required' });

  const safeColor = /^#[0-9a-fA-F]{6}$/.test(color) ? color : '#64748b';
  await db.execute(
    'UPDATE resources SET name = ?, description = ?, color = ?, category_id = ? WHERE id = ?',
    [name, description || null, safeColor, category_id, req.params.id]
  );
  const [rows] = await db.execute(
    `SELECT r.*, c.name AS category_name FROM resources r
     JOIN categories c ON c.id = r.category_id WHERE r.id = ?`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Not found' });
  res.json(rows[0]);
}));

router.delete('/resources/:id', requireAdmin, ah(async (req, res) => {
  const [result] = await db.execute('DELETE FROM resources WHERE id = ?', [req.params.id]);
  if (result.affectedRows === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
}));

// ═══════════════════════════════════════════════════════════
// Appointments
// ═══════════════════════════════════════════════════════════
router.get('/appointments', ah(async (req, res) => {
  const { resource_id, start, end, status, search, date_from, date_to, category_id, sort_by, sort_dir } = req.query;
  // Support array of IDs for category filtering: resource_id[]=1&resource_id[]=2
  const resourceIds = req.query['resource_id[]']
    ? [].concat(req.query['resource_id[]']).map(Number).filter(Boolean)
    : null;

  // Pagination is opt-in: only when ?page= is present (admin table)
  const wantPagination = req.query.page !== undefined;
  const VALID_LIMITS   = [25, 50, 75, 100];
  const limit  = VALID_LIMITS.includes(parseInt(req.query.limit)) ? parseInt(req.query.limit) : 25;
  const page   = Math.max(1, parseInt(req.query.page) || 1);
  const offset = (page - 1) * limit;

  // Sort params (admin paginated use only; public calendar always uses start_time ASC)
  const VALID_SORT = { id: 'a.id', title: 'a.title', start_time: 'a.start_time', end_time: 'a.end_time', status: 'a.status' };
  const sortCol = VALID_SORT[sort_by] || 'a.start_time';
  const sortDir = sort_dir === 'asc' ? 'ASC' : 'DESC';

  // Build reusable WHERE clause + params array
  let where = ' WHERE 1=1';
  const params = [];

  if (resourceIds && resourceIds.length) {
    where += ` AND a.resource_id IN (${resourceIds.map(() => '?').join(',')})`;
    params.push(...resourceIds);
  } else if (resource_id) { where += ' AND a.resource_id = ?'; params.push(resource_id); }

  if (category_id) { where += ' AND r.category_id = ?'; params.push(category_id); }

  if (start)     { where += ' AND a.end_time >= ?';          params.push(start); }
  if (end)       { where += ' AND a.start_time <= ?';        params.push(end); }
  if (date_from) { where += ' AND a.start_time >= ?';        params.push(date_from + ' 00:00:00'); }
  if (date_to)   { where += ' AND a.start_time <= ?';        params.push(date_to   + ' 23:59:59'); }

  if (status && status !== 'all') { where += ' AND a.status = ?'; params.push(status); }
  else if (!status)               { where += " AND a.status != 'cancelled'"; }
  // status=all → no filter (admin view)

  if (search) {
    where += ' AND (a.title LIKE ? OR a.booked_by_name LIKE ? OR a.booked_by_email LIKE ?)';
    const term = `%${search}%`;
    params.push(term, term, term);
  }

  const join = ' FROM appointments a JOIN resources r ON r.id = a.resource_id';
  const cols = 'SELECT a.*, r.name AS resource_name, r.color AS resource_color';

  const mapRow = r => ({
    ...r,
    start_time: toISOLocal(r.start_time),
    end_time:   toISOLocal(r.end_time),
    created_at: toISOLocal(r.created_at),
    updated_at: toISOLocal(r.updated_at),
  });

  if (wantPagination) {
    const [[{ total }]] = await db.execute(`SELECT COUNT(*) AS total${join}${where}`, params);
    const [rows] = await db.execute(
      `${cols}${join}${where} ORDER BY ${sortCol} ${sortDir} LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );
    return res.json({ total, page, limit, pages: Math.ceil(total / limit), data: rows.map(mapRow) });
  }

  // Non-paginated path (public calendar, conflict checks, etc.) — always start_time ASC
  const [rows] = await db.execute(`${cols}${join}${where} ORDER BY a.start_time ASC`, params);
  res.json(rows.map(mapRow));
}));

// My Bookings — returns the authenticated user's non-cancelled appointments.
// Must be registered BEFORE /:id to avoid route collision.
// GET /api/appointments/mine
router.get('/appointments/mine', ah(async (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Not authenticated' });

  let payload;
  try { payload = require('jsonwebtoken').verify(token, process.env.JWT_SECRET); }
  catch { return res.status(401).json({ error: 'Invalid or expired token' }); }
  if (payload.type !== 'user') return res.status(403).json({ error: 'Forbidden' });

  const now = new Date();
  const [rows] = await db.execute(
    `SELECT a.*, r.name AS resource_name, r.color AS resource_color
     FROM appointments a
     JOIN resources r ON r.id = a.resource_id
     WHERE a.user_id = ? AND a.status != 'cancelled'
     ORDER BY a.start_time ASC`,
    [payload.id]
  );

  const mapMine = r => ({
    ...r,
    start_time: toISOLocal(r.start_time),
    end_time:   toISOLocal(r.end_time),
    created_at: toISOLocal(r.created_at),
    updated_at: toISOLocal(r.updated_at),
    is_past:    r.end_time < now,
  });

  res.json(rows.map(mapMine));
}));

// Real-time conflict check — must be registered BEFORE /:id to avoid route collision.
// GET /api/appointments/check-conflict?resource_id=1&start=...&end=...&exclude_id=5
router.get('/appointments/check-conflict', ah(async (req, res) => {
  const { resource_id, start, end, exclude_id } = req.query;
  if (!resource_id || !start || !end)
    return res.status(400).json({ error: 'resource_id, start, and end are required' });

  let sql = `
    SELECT a.id, a.title, a.start_time, a.end_time,
           a.booked_by_name
    FROM appointments a
    WHERE a.resource_id = ? AND a.status != 'cancelled'
      AND a.start_time < ? AND a.end_time > ?
  `;
  const params = [resource_id, end, start];

  if (exclude_id) { sql += ' AND a.id != ?'; params.push(exclude_id); }

  const [rows] = await db.execute(sql, params);
  res.json({
    conflict: rows.length > 0,
    bookings: rows.map(r => ({
      id:         r.id,
      title:      r.title,
      booked_by:  r.booked_by_name,
      start_time: toISOLocal(r.start_time),
      end_time:   toISOLocal(r.end_time),
    })),
  });
}));

router.get('/appointments/:id', ah(async (req, res) => {
  const [rows] = await db.execute(
    `SELECT a.*, r.name AS resource_name, r.color AS resource_color
     FROM appointments a JOIN resources r ON r.id = a.resource_id
     WHERE a.id = ?`, [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Not found' });
  const r = rows[0];
  res.json({
    ...r,
    start_time: toISOLocal(r.start_time),
    end_time:   toISOLocal(r.end_time),
  });
}));

router.post('/appointments', ah(async (req, res) => {
  // Require authenticated user
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'You must be signed in to create a booking' });
  let userPayload;
  try {
    userPayload = require('jsonwebtoken').verify(token, process.env.JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Invalid or expired session — please sign in again' });
  }
  if (userPayload.type !== 'user') return res.status(403).json({ error: 'Forbidden' });

  const { resource_id, title, description, booked_by_name,
          booked_by_email, booked_by_phone, start_time, end_time, timezone } = req.body || {};

  if (!resource_id || !title || !booked_by_name || !booked_by_email || !start_time || !end_time)
    return res.status(400).json({ error: 'Missing required fields' });

  // Validate resource exists
  const [rr] = await db.execute('SELECT id FROM resources WHERE id = ?', [resource_id]);
  if (!rr[0]) return res.status(400).json({ error: 'Invalid resource_id' });

  // Basic conflict check
  const [conflicts] = await db.execute(
    `SELECT id FROM appointments
     WHERE resource_id = ? AND status != 'cancelled'
       AND start_time < ? AND end_time > ?`,
    [resource_id, end_time, start_time]
  );
  if (conflicts.length > 0)
    return res.status(409).json({ error: 'Time slot conflicts with an existing booking' });

  // Upsert user record (name + phone may update on repeat bookings)
  let userId = null;
  try {
    await db.execute(
      `INSERT INTO users (name, email, phone)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE
         name  = VALUES(name),
         phone = COALESCE(VALUES(phone), phone)`,
      [booked_by_name, booked_by_email, booked_by_phone || null]
    );
    const [[user]] = await db.execute('SELECT id FROM users WHERE email = ?', [booked_by_email]);
    userId = user ? user.id : null;
  } catch (e) {
    console.error('user upsert failed:', e.message);
  }

  const [result] = await db.execute(
    `INSERT INTO appointments
       (resource_id, user_id, title, description, booked_by_name, booked_by_email,
        booked_by_phone, start_time, end_time, timezone, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'confirmed')`,
    [resource_id, userId, title, description || null,
     booked_by_name, booked_by_email, booked_by_phone || null,
     toDBDatetime(start_time), toDBDatetime(end_time), timezone || 'UTC']
  );

  const [rows] = await db.execute(
    `SELECT a.*, r.name AS resource_name, r.color AS resource_color
     FROM appointments a JOIN resources r ON r.id = a.resource_id
     WHERE a.id = ?`, [result.insertId]
  );
  const appt = rows[0];
  await logActivity('created', appt, booked_by_email, getClientIP(req));
  res.status(201).json({
    ...appt,
    start_time: toISOLocal(appt.start_time),
    end_time:   toISOLocal(appt.end_time),
  });
}));

router.put('/appointments/:id', requireAdmin, ah(async (req, res) => {
  const { title, description, booked_by_name, booked_by_email,
          start_time, end_time, timezone, status } = req.body || {};

  const [existing] = await db.execute('SELECT * FROM appointments WHERE id = ?', [req.params.id]);
  if (!existing[0]) return res.status(404).json({ error: 'Not found' });

  const upd = {
    title:           title           ?? existing[0].title,
    description:     description     ?? existing[0].description,
    booked_by_name:  booked_by_name  ?? existing[0].booked_by_name,
    booked_by_email: booked_by_email ?? existing[0].booked_by_email,
    start_time:      start_time ? toDBDatetime(start_time) : existing[0].start_time,
    end_time:        end_time   ? toDBDatetime(end_time)   : existing[0].end_time,
    timezone:        timezone        ?? existing[0].timezone,
    status:          status          ?? existing[0].status,
  };

  await db.execute(
    `UPDATE appointments SET title=?, description=?, booked_by_name=?,
       booked_by_email=?, start_time=?, end_time=?, timezone=?, status=?
     WHERE id=?`,
    [upd.title, upd.description, upd.booked_by_name, upd.booked_by_email,
     upd.start_time, upd.end_time, upd.timezone, upd.status, req.params.id]
  );

  const [rows] = await db.execute(
    `SELECT a.*, r.name AS resource_name, r.color AS resource_color
     FROM appointments a JOIN resources r ON r.id = a.resource_id WHERE a.id = ?`,
    [req.params.id]
  );
  const appt = rows[0];
  res.json({ ...appt, start_time: toISOLocal(appt.start_time), end_time: toISOLocal(appt.end_time) });
}));

router.delete('/appointments/:id', requireAdmin, ah(async (req, res) => {
  // Fetch before deleting so we can log it
  const [pre] = await db.execute(
    `SELECT a.title, r.name AS resource_name, r.color AS resource_color
     FROM appointments a JOIN resources r ON r.id = a.resource_id WHERE a.id = ?`,
    [req.params.id]
  );
  const [result] = await db.execute('DELETE FROM appointments WHERE id = ?', [req.params.id]);
  if (result.affectedRows === 0) return res.status(404).json({ error: 'Not found' });
  if (pre[0]) await logActivity('deleted', pre[0], 'admin', getClientIP(req));
  res.json({ ok: true });
}));

// ── Cancel booking (requires auth + password for local users) ─
router.post('/appointments/:id/cancel', ah(async (req, res) => {
  // Verify JWT
  const auth = (req.headers.authorization || '').replace('Bearer ', '');
  if (!auth) return res.status(401).json({ error: 'Sign in to cancel a booking' });

  let decoded;
  try {
    decoded = jwt.verify(auth, process.env.JWT_SECRET);
    if (decoded.type !== 'user') throw new Error('wrong type');
  } catch {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }

  const [rows] = await db.execute(
    `SELECT a.*, r.name AS resource_name, r.color AS resource_color
     FROM appointments a JOIN resources r ON r.id = a.resource_id WHERE a.id = ?`,
    [req.params.id]
  );
  const appt = rows[0];
  if (!appt) return res.status(404).json({ error: 'Booking not found' });
  if (appt.status === 'cancelled')
    return res.status(409).json({ error: 'Booking is already cancelled' });

  // Verify ownership
  if (appt.booked_by_email.toLowerCase() !== decoded.email.toLowerCase())
    return res.status(403).json({ error: 'You can only cancel your own bookings' });

  // Local users must supply their password
  const [[user]] = await db.execute(
    'SELECT auth_source, password_hash FROM users WHERE id = ?', [decoded.userId]
  );

  if (!user) return res.status(404).json({ error: 'User not found' });

  if (user.auth_source !== 'ldap') {
    const { password } = req.body || {};
    if (!password) return res.status(400).json({ error: 'Password is required to cancel' });
    if (!user.password_hash)
      return res.status(401).json({ error: 'Account has no password set. Contact an administrator.' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Incorrect password' });
  }

  await db.execute("UPDATE appointments SET status = 'cancelled' WHERE id = ?", [req.params.id]);
  await logActivity('cancelled', appt, decoded.email, getClientIP(req));
  res.json({ ok: true });
}));

// ═══════════════════════════════════════════════════════════
// Users (admin only)
// ═══════════════════════════════════════════════════════════
router.get('/users', requireAdmin, ah(async (req, res) => {
  const VALID_LIMITS = [25, 50, 75, 100];
  const limit  = VALID_LIMITS.includes(parseInt(req.query.limit)) ? parseInt(req.query.limit) : 25;
  const page   = Math.max(1, parseInt(req.query.page) || 1);
  const offset = (page - 1) * limit;
  const search = (req.query.search || '').trim();

  // Sort
  const VALID_SORT = {
    id:              'u.id',
    name:            'u.name',
    email:           'u.email',
    auth_source:     'u.auth_source',
    booking_count:   'booking_count',
    last_login_at:   'u.last_login_at',
    last_booking_at: 'last_booking_at',
    created_at:      'u.created_at',
  };
  const sortCol = VALID_SORT[req.query.sort_by] || 'u.created_at';
  const sortDir = req.query.sort_dir === 'asc' ? 'ASC' : 'DESC';

  let where = '';
  const baseParams = [];
  if (search) {
    where = ' WHERE (u.name LIKE ? OR u.email LIKE ?)';
    const term = `%${search}%`;
    baseParams.push(term, term);
  }

  const [[{ total }]] = await db.execute(
    `SELECT COUNT(*) AS total FROM users u${where}`,
    baseParams
  );
  const [rows] = await db.execute(
    `SELECT u.id, u.name, u.email, u.phone, u.auth_source, u.last_login_at, u.created_at,
            COUNT(a.id) AS booking_count,
            (SELECT MAX(b.created_at) FROM appointments b WHERE b.user_id = u.id) AS last_booking_at
     FROM users u
     LEFT JOIN appointments a ON a.user_id = u.id AND a.status != 'cancelled'${where}
     GROUP BY u.id, u.name, u.email, u.phone, u.auth_source, u.last_login_at, u.created_at
     ORDER BY ${sortCol} ${sortDir}
     LIMIT ? OFFSET ?`,
    [...baseParams, limit, offset]
  );

  res.json({
    total,
    page,
    limit,
    pages: Math.ceil(total / limit),
    data: rows.map(r => ({
      ...r,
      last_login_at:   toISOLocal(r.last_login_at),
      last_booking_at: toISOLocal(r.last_booking_at),
      created_at:      toISOLocal(r.created_at),
    })),
  });
}));

router.put('/users/:id', requireAdmin, ah(async (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid user ID' });

  const [[user]] = await db.execute('SELECT id, auth_source FROM users WHERE id = ?', [id]);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.auth_source === 'ldap')
    return res.status(400).json({ error: 'LDAP users cannot be edited — their details come from the directory.' });

  const { name, email, phone, timezone } = req.body || {};
  if (!name?.trim() || !email?.trim())
    return res.status(400).json({ error: 'Name and email are required' });

  // Check email uniqueness (excluding this user)
  const [[existing]] = await db.execute(
    'SELECT id FROM users WHERE email = ? AND id != ?', [email.trim().toLowerCase(), id]
  );
  if (existing) return res.status(409).json({ error: 'Email is already in use by another account' });

  await db.execute(
    'UPDATE users SET name = ?, email = ?, phone = ?, timezone = ? WHERE id = ?',
    [name.trim(), email.trim().toLowerCase(), phone?.trim() || null, timezone || 'UTC', id]
  );

  const [[updated]] = await db.execute(
    'SELECT id, name, email, phone, timezone, auth_source FROM users WHERE id = ?', [id]
  );
  res.json(updated);
}));

router.delete('/users/:id', requireAdmin, ah(async (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid user ID' });

  const [[user]] = await db.execute('SELECT id, name, email FROM users WHERE id = ?', [id]);
  if (!user) return res.status(404).json({ error: 'User not found' });

  // Cancel any future appointments belonging to this user before deleting
  const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
  const [cancelled] = await db.execute(
    `UPDATE appointments SET status = 'cancelled'
     WHERE user_id = ? AND status != 'cancelled' AND start_time > ?`,
    [id, now]
  );

  await db.execute('DELETE FROM users WHERE id = ?', [id]);
  res.json({ ok: true, message: `User ${user.email} deleted`, cancelledBookings: cancelled.affectedRows });
}));

// ── ICS download ───────────────────────────────────────────
router.get('/appointments/:id/ics', ah(async (req, res) => {
  const [rows] = await db.execute(
    `SELECT a.*, r.name AS resource_name FROM appointments a
     JOIN resources r ON r.id = a.resource_id WHERE a.id = ?`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Not found' });

  const ics = buildICS(rows[0]);
  res.setHeader('Content-Type', 'text/calendar; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="booking-${req.params.id}.ics"`);
  res.send(ics);
}));

// ═══════════════════════════════════════════════════════════
// LDAP connection test (admin only)
// ═══════════════════════════════════════════════════════════
router.post('/auth/ldap-test', requireAdmin, ah(async (req, res) => {
  const { url, bind_dn, bind_pass, base_dn } = req.body || {};
  if (!url || !bind_dn || !base_dn)
    return res.status(400).json({ error: 'url, bind_dn, and base_dn are required' });

  const ip = getClientIP(req);
  const client = ldap.createClient({ url, timeout: 8000, connectTimeout: 8000, reconnect: false, tlsOptions: { rejectUnauthorized: false, minVersion: 'TLSv1' } });
  client.on('error', err => console.error('[LDAP] Test client error:', err.message));
  try {
    await new Promise((resolve, reject) => {
      client.bind(bind_dn, bind_pass || '', err => (err ? reject(err) : resolve()));
    });
    client.unbind();
    logLdapEvent('success', null, `Admin connection test passed (url=${url} dn=${bind_dn})`, ip);
    res.json({ ok: true, message: 'Connection and bind successful.' });
  } catch (err) {
    try { client.unbind(); } catch {}
    logLdapEvent('bind_failed', null, `Admin connection test failed (url=${url} dn=${bind_dn}): ${err.message}`, ip);
    res.status(400).json({ error: err.message || 'LDAP bind failed.' });
  }
}));

// ═══════════════════════════════════════════════════════════
// Data purge
// ═══════════════════════════════════════════════════════════

/** Convert a value+unit pair to milliseconds. */
function toMs(value, unit) {
  const v = parseInt(value) || 1;
  switch (unit) {
    case 'days':   return v * 24 * 60 * 60 * 1000;
    case 'weeks':  return v *  7 * 24 * 60 * 60 * 1000;
    case 'months': return v * 30 * 24 * 60 * 60 * 1000;
    default:       return v * 30 * 24 * 60 * 60 * 1000;
  }
}

/** Run the purge — deletes appointments older than the configured retention period. */
async function runPurge() {
  const [rows] = await db.execute("SELECT `key`, `value` FROM settings WHERE `key` LIKE 'purge_%'");
  const s = {};
  rows.forEach(r => { s[r.key] = r.value; });

  if (s.purge_enabled !== 'true') return { skipped: true };

  const retentionMs = toMs(s.purge_retention_value, s.purge_retention_unit);
  const cutoff = new Date(Date.now() - retentionMs);
  const cutoffStr = cutoff.toISOString().slice(0, 19).replace('T', ' ');

  const [apptResult] = await db.execute(
    "DELETE FROM appointments WHERE end_time < ?", [cutoffStr]
  );

  const [logResult] = await db.execute(
    "DELETE FROM activity_log WHERE created_at < ?", [cutoffStr]
  );

  const [ldapLogResult] = await db.execute(
    "DELETE FROM ldap_log WHERE created_at < ?", [cutoffStr]
  );

  const now = new Date().toISOString();
  await db.execute(
    "INSERT INTO settings (`key`, `value`) VALUES ('purge_last_run', ?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)",
    [now]
  );

  console.log(`[Purge] Deleted ${apptResult.affectedRows} appointment(s), ${logResult.affectedRows} activity log entry/entries, ${ldapLogResult.affectedRows} LDAP log entry/entries older than ${s.purge_retention_value} ${s.purge_retention_unit} (cutoff: ${cutoffStr})`);
  return { deleted: apptResult.affectedRows, logsDeleted: logResult.affectedRows, ldapLogsDeleted: ldapLogResult.affectedRows, cutoff: cutoffStr, ranAt: now };
}

/** Manual purge trigger (admin only). */
router.post('/admin/purge', requireAdmin, ah(async (_req, res) => {
  const result = await runPurge();
  if (result.skipped) return res.status(400).json({ error: 'Purge is disabled. Enable it in Settings first.' });
  res.json(result);
}));

// LDAP log (admin only)
router.get('/admin/ldap-log', requireAdmin, ah(async (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit) || 10, 50);
  const page   = Math.max(1, parseInt(req.query.page) || 1);
  const offset = (page - 1) * limit;

  const [[{ total }]] = await db.execute('SELECT COUNT(*) AS total FROM ldap_log');
  const [rows] = await db.execute(
    `SELECT id, event, email, detail, ip_address, created_at
     FROM ldap_log ORDER BY created_at DESC LIMIT ? OFFSET ?`,
    [limit, offset]
  );
  res.json({ total, page, limit, pages: Math.min(Math.ceil(total / limit), 5), data: rows });
}));

// ═══════════════════════════════════════════════════════════
// Admin dashboard stats
// ═══════════════════════════════════════════════════════════
router.get('/admin/stats', requireAdmin, ah(async (_req, res) => {
  const now    = new Date();
  const todayS = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const todayE = new Date(todayS.getTime() + 86400000);
  const week7ago = new Date(todayS.getTime() - 6 * 86400000);

  const fmt = d => d.toISOString().slice(0, 19).replace('T', ' ');
  const nowStr = fmt(now);

  const [
    [[{ confirmed_past }]],
    [[{ today }]],
    [[{ upcoming }]],
    [[{ resource_count }]],
    [[{ total_hours }]],
    [utilization],
    [weeklyRaw],
    [recent],
  ] = await Promise.all([
    // Past confirmed bookings (end_time already passed)
    db.execute("SELECT COUNT(*) AS confirmed_past FROM appointments WHERE status = 'confirmed' AND user_id IS NOT NULL AND end_time < ?", [nowStr]),
    db.execute(
      "SELECT COUNT(*) AS today FROM appointments WHERE status != 'cancelled' AND user_id IS NOT NULL AND start_time < ? AND end_time > ?",
      [fmt(todayE), fmt(todayS)]
    ),
    // All upcoming non-cancelled (start_time in the future)
    db.execute(
      "SELECT COUNT(*) AS upcoming FROM appointments WHERE status != 'cancelled' AND user_id IS NOT NULL AND start_time > ?",
      [nowStr]
    ),
    db.execute("SELECT COUNT(*) AS resource_count FROM resources"),
    db.execute("SELECT COALESCE(ROUND(SUM(TIMESTAMPDIFF(MINUTE, start_time, end_time)) / 60.0, 1), 0) AS total_hours FROM appointments WHERE status != 'cancelled' AND user_id IS NOT NULL"),
    db.execute(`
      SELECT r.id, r.name, r.color,
             COALESCE(ROUND(SUM(TIMESTAMPDIFF(MINUTE, a.start_time, a.end_time)) / 60.0, 1), 0) AS hours
      FROM resources r
      LEFT JOIN appointments a ON a.resource_id = r.id AND a.status != 'cancelled' AND a.user_id IS NOT NULL
      GROUP BY r.id, r.name, r.color
      ORDER BY hours DESC
    `),
    db.execute(`
      SELECT DATE(start_time) AS day, COUNT(*) AS count
      FROM appointments
      WHERE status != 'cancelled' AND user_id IS NOT NULL
        AND start_time >= ? AND start_time < ?
      GROUP BY DATE(start_time)
    `, [fmt(week7ago), fmt(todayE)]),
    db.execute(`
      SELECT a.id, a.title, a.start_time, a.end_time, a.status, a.created_at,
             r.name AS resource_name, r.color AS resource_color
      FROM appointments a
      JOIN resources r ON r.id = a.resource_id
      WHERE a.status != 'cancelled' AND a.user_id IS NOT NULL
      ORDER BY a.created_at DESC LIMIT 8
    `),
  ]);

  // Fill 7-day weekly array (fill missing days with 0)
  const weeklyMap = {};
  weeklyRaw.forEach(r => {
    const key = r.day instanceof Date
      ? r.day.toISOString().slice(0, 10)
      : String(r.day).slice(0, 10);
    weeklyMap[key] = r.count;
  });
  const weekly = [];
  for (let i = 6; i >= 0; i--) {
    const d   = new Date(todayS.getTime() - i * 86400000);
    const key = d.toISOString().slice(0, 10);
    const label = d.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
    weekly.push({ label, count: weeklyMap[key] || 0 });
  }

  res.json({
    confirmed_past, today, upcoming,
    resource_count,
    total_hours,
    utilization,
    weekly,
    recent: recent.map(r => ({
      ...r,
      start_time: toISOLocal(r.start_time),
      end_time:   toISOLocal(r.end_time),
      created_at: toISOLocal(r.created_at),
    })),
  });
}));

// ═══════════════════════════════════════════════════════════
// Public stats
// ═══════════════════════════════════════════════════════════
router.get('/stats/top-users', ah(async (_req, res) => {
  // Top 10 users by total confirmed booking duration (in minutes)
  const [rows] = await db.execute(
    `SELECT u.name,
            COUNT(a.id)                                                      AS booking_count,
            ROUND(SUM(TIMESTAMPDIFF(MINUTE, a.start_time, a.end_time)) / 60, 1) AS total_hours
     FROM users u
     JOIN appointments a ON a.booked_by_email = u.email
                        AND a.status != 'cancelled'
                        AND a.end_time <= NOW()
     GROUP BY u.id, u.name
     ORDER BY total_hours DESC, booking_count DESC
     LIMIT 10`
  );
  res.json(rows);
}));

module.exports = router;
module.exports.runPurge = runPurge;
