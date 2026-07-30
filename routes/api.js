'use strict';
const crypto     = require('crypto');
const express    = require('express');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const ldap       = require('ldapjs');
const db         = require('../database');
const requireAdmin = require('../middleware/auth');
const { sendCancellationCode } = require('../services/notifications');

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
  });

  // Surface connection errors immediately
  await new Promise((resolve, reject) => {
    client.once('connect', resolve);
    client.once('error',   reject);
    // If already connected (synchronous connect), bind will tell us
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
    const escapedEmail = ldap.escapeFilter(email);
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
// User Auth (passwordless – email only)
// ═══════════════════════════════════════════════════════════
router.post('/auth/register', ah(async (req, res) => {
  const { first_name, last_name, email, phone, timezone } = req.body || {};
  if (!first_name?.trim() || !last_name?.trim() || !email?.trim())
    return res.status(400).json({ error: 'First name, last name, and email are required' });

  const name  = `${first_name.trim()} ${last_name.trim()}`;
  const clean = email.trim().toLowerCase();
  const tz    = timezone?.trim() || 'UTC';

  const [[existing]] = await db.execute('SELECT id FROM users WHERE email = ?', [clean]);
  if (existing)
    return res.status(409).json({ error: 'An account with this email already exists. Please sign in.' });

  const [result] = await db.execute(
    'INSERT INTO users (name, email, phone, timezone) VALUES (?, ?, ?, ?)',
    [name, clean, phone?.trim() || null, tz]
  );

  const token = jwt.sign(
    { type: 'user', userId: result.insertId, name, email: clean, phone: phone?.trim() || null, timezone: tz },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );

  res.status(201).json({ token, user: { id: result.insertId, name, email: clean, phone: phone?.trim() || null, timezone: tz } });
}));

router.post('/auth/login', ah(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email?.trim()) return res.status(400).json({ error: 'Email is required' });

  const clean = email.trim().toLowerCase();

  // ── LDAP path: password supplied ──────────────────────────
  if (password) {
    const ip = getClientIP(req);
    let ldapUser;
    try {
      ldapUser = await ldapAuthenticate(clean, password, ip);
    } catch (err) {
      // logLdapEvent already called inside ldapAuthenticate; just sanitize for client
      const msg = err.message?.includes('Invalid Credentials') || err.message?.includes('bind')
        ? 'Invalid email or password.'
        : (err.message || 'LDAP authentication failed.');
      return res.status(401).json({ error: msg });
    }

    // Upsert the LDAP user — create on first login, update name/phone on subsequent logins
    const tz = 'UTC';
    await db.execute(
      `INSERT INTO users (name, email, phone, timezone, auth_source)
       VALUES (?, ?, ?, ?, 'ldap')
       ON DUPLICATE KEY UPDATE name=VALUES(name), phone=VALUES(phone), auth_source='ldap'`,
      [ldapUser.name, ldapUser.email, ldapUser.phone, tz]
    );

    const [[user]] = await db.execute(
      'SELECT id, name, email, phone, timezone FROM users WHERE email = ?', [ldapUser.email]
    );

    const token = jwt.sign(
      { type: 'user', userId: user.id, name: user.name, email: user.email,
        phone: user.phone || null, timezone: user.timezone || 'UTC', authSource: 'ldap' },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );
    return res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email,
              phone: user.phone || null, timezone: user.timezone || 'UTC', authSource: 'ldap' },
    });
  }

  // ── Local path: email-only (passwordless) ─────────────────
  const [[user]] = await db.execute(
    'SELECT id, name, email, phone, timezone, auth_source FROM users WHERE email = ?', [clean]
  );
  if (!user)
    return res.status(404).json({ error: 'No account found with this email. Please register first.' });

  // Prevent LDAP users from bypassing password check
  if (user.auth_source === 'ldap')
    return res.status(401).json({ error: 'This account uses LDAP login. Please enter your password.' });

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

  const { first_name, last_name, email, phone, timezone } = req.body || {};
  if (!first_name?.trim() || !last_name?.trim() || !email?.trim())
    return res.status(400).json({ error: 'First name, last name, and email are required' });

  const name  = `${first_name.trim()} ${last_name.trim()}`;
  const clean = email.trim().toLowerCase();
  const tz    = timezone?.trim() || payload.timezone || 'UTC';

  // Check if new email is already taken by another account
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

  const [[user]] = await db.execute(
    'SELECT id, name, email, phone, timezone FROM users WHERE id = ?', [payload.userId]
  );

  // Re-issue token with updated claims
  const token = jwt.sign(
    { type: 'user', userId: user.id, name: user.name, email: user.email, phone: user.phone, timezone: user.timezone },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );

  res.json({ token, user });
}));

router.get('/auth/me', ah(async (req, res) => {
  const auth = (req.headers.authorization || '').replace('Bearer ', '');
  if (!auth) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const payload = jwt.verify(auth, process.env.JWT_SECRET);
    if (payload.type !== 'user') return res.status(401).json({ error: 'Invalid token' });
    const [[user]] = await db.execute(
      'SELECT id, name, email, phone, timezone FROM users WHERE id = ?', [payload.userId]
    );
    if (!user) return res.status(401).json({ error: 'User not found' });
    res.json(user);
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

/** Settings — public gets minimal set; admin JWT gets full set (minus bind password). */
router.get('/settings', ah(async (req, res) => {
  const requireCancelCode = await getSetting('require_cancel_code', 'true');

  // Check for admin token to return full settings
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  let isAdmin = false;
  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      isAdmin = decoded.type === 'admin';
    } catch {}
  }

  if (!isAdmin) {
    // Public: only what the frontend needs to show/hide UI elements
    const ldapEnabled = await getSetting('ldap_enabled', 'false');
    return res.json({
      require_cancel_code: requireCancelCode === 'true',
      ldap_enabled: ldapEnabled === 'true',
    });
  }

  // Admin: full settings (bind password intentionally omitted)
  const [rows] = await db.execute("SELECT `key`, `value` FROM settings");
  const s = {};
  rows.forEach(r => { s[r.key] = r.value; });
  res.json({
    require_cancel_code: s.require_cancel_code === 'true',
    ldap_enabled:        s.ldap_enabled === 'true',
    ldap_url:            s.ldap_url            || '',
    ldap_base_dn:        s.ldap_base_dn        || '',
    ldap_bind_dn:        s.ldap_bind_dn        || '',
    ldap_user_filter:    s.ldap_user_filter     || '(mail={{username}})',
    ldap_name_attr:      s.ldap_name_attr       || 'cn',
    ldap_email_attr:     s.ldap_email_attr      || 'mail',
    ldap_phone_attr:     s.ldap_phone_attr      || 'telephoneNumber',
  });
}));

/** Admin: update settings. */
router.put('/settings', requireAdmin, ah(async (req, res) => {
  const {
    require_cancel_code,
    ldap_enabled, ldap_url, ldap_base_dn, ldap_bind_dn, ldap_bind_pass,
    ldap_user_filter, ldap_name_attr, ldap_email_attr, ldap_phone_attr,
  } = req.body || {};

  const upsert = async (key, value) => db.execute(
    'INSERT INTO settings (`key`, `value`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)',
    [key, value]
  );

  if (require_cancel_code !== undefined)
    await upsert('require_cancel_code', require_cancel_code ? 'true' : 'false');

  if (ldap_enabled !== undefined) await upsert('ldap_enabled', ldap_enabled ? 'true' : 'false');
  if (ldap_url       !== undefined) await upsert('ldap_url',       ldap_url);
  if (ldap_base_dn   !== undefined) await upsert('ldap_base_dn',   ldap_base_dn);
  if (ldap_bind_dn   !== undefined) await upsert('ldap_bind_dn',   ldap_bind_dn);
  if (ldap_bind_pass !== undefined) await upsert('ldap_bind_pass', ldap_bind_pass);
  if (ldap_user_filter !== undefined) await upsert('ldap_user_filter', ldap_user_filter);
  if (ldap_name_attr   !== undefined) await upsert('ldap_name_attr',   ldap_name_attr);
  if (ldap_email_attr  !== undefined) await upsert('ldap_email_attr',  ldap_email_attr);
  if (ldap_phone_attr  !== undefined) await upsert('ldap_phone_attr',  ldap_phone_attr);

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
// Resources
// ═══════════════════════════════════════════════════════════
router.get('/resources', ah(async (_req, res) => {
  const [rows] = await db.execute(
    `SELECT r.*,
            COUNT(a.id) AS booking_count
     FROM resources r
     LEFT JOIN appointments a
            ON a.resource_id = r.id AND a.status != 'cancelled'
     GROUP BY r.id, r.name, r.description, r.color, r.created_at, r.updated_at
     ORDER BY booking_count DESC, r.name ASC`
  );
  res.json(rows);
}));

router.post('/resources', requireAdmin, ah(async (req, res) => {
  const { name, description, color } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name is required' });

  const safeColor = /^#[0-9a-fA-F]{6}$/.test(color) ? color : '#64748b';
  const [result] = await db.execute(
    'INSERT INTO resources (name, description, color) VALUES (?, ?, ?)',
    [name, description || null, safeColor]
  );
  const [rows] = await db.execute('SELECT * FROM resources WHERE id = ?', [result.insertId]);
  res.status(201).json(rows[0]);
}));

router.put('/resources/:id', requireAdmin, ah(async (req, res) => {
  const { name, description, color } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name is required' });

  const safeColor = /^#[0-9a-fA-F]{6}$/.test(color) ? color : '#64748b';
  await db.execute(
    'UPDATE resources SET name = ?, description = ?, color = ? WHERE id = ?',
    [name, description || null, safeColor, req.params.id]
  );
  const [rows] = await db.execute('SELECT * FROM resources WHERE id = ?', [req.params.id]);
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
  const { resource_id, start, end, status } = req.query;

  let sql = `
    SELECT a.*, r.name AS resource_name, r.color AS resource_color
    FROM appointments a
    JOIN resources r ON r.id = a.resource_id
    WHERE 1=1
  `;
  const params = [];

  if (resource_id) { sql += ' AND a.resource_id = ?';  params.push(resource_id); }
  if (start)        { sql += ' AND a.end_time >= ?';    params.push(start); }
  if (end)          { sql += ' AND a.start_time <= ?';  params.push(end); }
  if (status && status !== 'all') { sql += ' AND a.status = ?'; params.push(status); }
  else if (!status)               { sql += " AND a.status != 'cancelled'"; }
  // status=all → no filter (admin view)

  sql += ' ORDER BY a.start_time ASC';

  const [rows] = await db.execute(sql, params);

  // Convert Date objects → ISO strings
  res.json(rows.map(r => ({
    ...r,
    start_time: toISOLocal(r.start_time),
    end_time:   toISOLocal(r.end_time),
    created_at: toISOLocal(r.created_at),
    updated_at: toISOLocal(r.updated_at),
  })));
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

// ── Step 1: Request a cancellation code ───────────────────
router.post('/appointments/:id/request-cancel', ah(async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email is required' });

  const [rows] = await db.execute(
    `SELECT a.*, r.name AS resource_name, r.color AS resource_color
     FROM appointments a JOIN resources r ON r.id = a.resource_id WHERE a.id = ?`,
    [req.params.id]
  );
  const appt = rows[0];
  if (!appt) return res.status(404).json({ error: 'Booking not found' });
  if (appt.status === 'cancelled')
    return res.status(409).json({ error: 'Booking is already cancelled' });
  if (appt.booked_by_email.toLowerCase() !== email.trim().toLowerCase())
    return res.status(403).json({ error: 'Email does not match the booking' });

  // Check whether code verification is required
  const requireCode = (await getSetting('require_cancel_code', 'true')) === 'true';

  if (!requireCode) {
    // Direct cancel — no code needed, email match was enough
    const [rr] = await db.execute(
      'SELECT name AS resource_name, color AS resource_color FROM resources WHERE id = ?',
      [appt.resource_id]
    );
    await db.execute("UPDATE appointments SET status = 'cancelled' WHERE id = ?", [req.params.id]);
    await logActivity('cancelled', { title: appt.title, ...rr[0] }, email, getClientIP(req));
    return res.json({ ok: true, direct: true });
  }

  // Generate a 6-digit numeric code
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const codeHash = crypto.createHash('sha256').update(code).digest('hex');
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 min from now

  // Invalidate any previous unused codes for this appointment
  await db.execute(
    'UPDATE cancellation_codes SET used = 1 WHERE appointment_id = ? AND used = 0',
    [req.params.id]
  );

  // Store new code
  await db.execute(
    `INSERT INTO cancellation_codes (appointment_id, code_hash, expires_at)
     VALUES (?, ?, ?)`,
    [req.params.id, codeHash, expiresAt.toISOString().replace('T', ' ').substring(0, 19)]
  );

  // Send code via email (and SMS if phone is on the booking)
  await sendCancellationCode(appt, code);

  res.json({ ok: true, message: 'Cancellation code sent' });
}));

// ── Step 2: Confirm cancellation with the code ─────────────
router.post('/appointments/:id/cancel', ah(async (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.status(400).json({ error: 'Cancellation code is required' });

  const [rows] = await db.execute(
    `SELECT a.*, r.name AS resource_name, r.color AS resource_color
     FROM appointments a JOIN resources r ON r.id = a.resource_id WHERE a.id = ?`,
    [req.params.id]
  );
  const appt = rows[0];
  if (!appt) return res.status(404).json({ error: 'Booking not found' });
  if (appt.status === 'cancelled')
    return res.status(409).json({ error: 'Booking is already cancelled' });

  const codeHash = crypto.createHash('sha256').update(code.trim()).digest('hex');

  const [codeRows] = await db.execute(
    `SELECT * FROM cancellation_codes
     WHERE appointment_id = ? AND code_hash = ? AND used = 0 AND expires_at > NOW()
     ORDER BY created_at DESC LIMIT 1`,
    [req.params.id, codeHash]
  );
  if (!codeRows[0])
    return res.status(400).json({ error: 'Invalid or expired cancellation code' });

  // Mark code used and cancel appointment
  await db.execute('UPDATE cancellation_codes SET used = 1 WHERE id = ?', [codeRows[0].id]);
  await db.execute("UPDATE appointments SET status = 'cancelled' WHERE id = ?", [req.params.id]);
  await logActivity('cancelled', appt, appt.booked_by_email, getClientIP(req));
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

  const [[{ total }]] = await db.execute('SELECT COUNT(*) AS total FROM users');
  const [rows] = await db.execute(
    `SELECT u.id, u.name, u.email, u.phone, u.auth_source, u.created_at,
            COUNT(a.id) AS booking_count
     FROM users u
     LEFT JOIN appointments a ON a.user_id = u.id AND a.status != 'cancelled'
     GROUP BY u.id, u.name, u.email, u.phone, u.created_at
     ORDER BY u.created_at DESC
     LIMIT ? OFFSET ?`,
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

router.delete('/users/:id', requireAdmin, ah(async (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid user ID' });

  const [[user]] = await db.execute('SELECT id, name, email FROM users WHERE id = ?', [id]);
  if (!user) return res.status(404).json({ error: 'User not found' });

  await db.execute('DELETE FROM users WHERE id = ?', [id]);
  res.json({ ok: true, message: `User ${user.email} deleted` });
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
  const client = ldap.createClient({ url, timeout: 8000, connectTimeout: 8000 });
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

// LDAP log (admin only)
router.get('/admin/ldap-log', requireAdmin, ah(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 500);
  const [rows] = await db.execute(
    `SELECT id, event, email, detail, ip_address, created_at
     FROM ldap_log ORDER BY created_at DESC LIMIT ?`,
    [limit]
  );
  res.json(rows);
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
