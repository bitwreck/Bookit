#!/usr/bin/env node
/**
 * Prepares front-end vendor files in public/vendor/.
 * - JS files are copied directly from node_modules (no network needed).
 * - FullCalendar CSS is downloaded once from the CDN (not in the npm package).
 *
 * Run manually: node scripts/download-vendor.js
 * Runs automatically via the "postinstall" npm script.
 */
'use strict';

const fs    = require('fs');
const path  = require('path');
const http  = require('http');
const https = require('https');
const url   = require('url');

const VENDOR_DIR   = path.join(__dirname, '..', 'public', 'vendor');
const NODE_MODULES = path.join(__dirname, '..', 'node_modules');

fs.mkdirSync(VENDOR_DIR, { recursive: true });

// ── Files copied from node_modules ──────────────────────────
const COPY_FILES = [
  { src: 'fullcalendar/index.global.min.js',          dest: 'fullcalendar.min.js' },
  { src: 'luxon/build/global/luxon.min.js',           dest: 'luxon.min.js' },
  { src: '@fullcalendar/luxon3/index.global.min.js',  dest: 'fullcalendar-luxon3.min.js' },
  { src: 'lucide/dist/umd/lucide.min.js',             dest: 'lucide.min.js' },
];

// ── Files downloaded from CDN (not available in npm package) ─
const DOWNLOAD_FILES = [
  {
    url:  'https://cdn.jsdelivr.net/npm/fullcalendar@6.1.11/index.global.min.css',
    dest: 'fullcalendar.min.css',
  },
];

// ── Download with redirect following ────────────────────────
function download(fileUrl, destPath, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) return reject(new Error('Too many redirects'));

    const parsed   = url.parse(fileUrl);
    const protocol = parsed.protocol === 'https:' ? https : http;

    protocol.get(fileUrl, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        // Follow redirect — resolve relative URLs against current host
        const next = url.resolve(fileUrl, res.headers.location);
        res.resume();
        return download(next, destPath, redirects + 1).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} from ${fileUrl}`));
      }
      const tmp  = destPath + '.tmp';
      const file = fs.createWriteStream(tmp);
      res.pipe(file);
      file.on('finish', () => {
        file.close(() => {
          fs.renameSync(tmp, destPath);
          resolve();
        });
      });
      file.on('error', err => { fs.unlink(tmp, () => {}); reject(err); });
    }).on('error', reject);
  });
}

// ── Main ─────────────────────────────────────────────────────
(async () => {
  let allOk = true;

  // Copy from node_modules
  for (const { src, dest } of COPY_FILES) {
    const srcPath  = path.join(NODE_MODULES, src);
    const destPath = path.join(VENDOR_DIR, dest);
    if (!fs.existsSync(srcPath)) {
      console.error(`  MISSING  ${src} — run: npm install`);
      allOk = false;
      continue;
    }
    fs.copyFileSync(srcPath, destPath);
    const kb = (fs.statSync(destPath).size / 1024).toFixed(1);
    console.log(`  copied   ${dest}  (${kb} KB)`);
  }

  // Download from CDN
  for (const { url: fileUrl, dest } of DOWNLOAD_FILES) {
    const destPath = path.join(VENDOR_DIR, dest);
    if (fs.existsSync(destPath)) {
      const kb = (fs.statSync(destPath).size / 1024).toFixed(1);
      console.log(`  skip     ${dest}  (${kb} KB, already exists)`);
      continue;
    }
    process.stdout.write(`  fetch    ${dest} … `);
    try {
      await download(fileUrl, destPath);
      const kb = (fs.statSync(destPath).size / 1024).toFixed(1);
      console.log(`${kb} KB`);
    } catch (err) {
      console.error(`FAILED\n           ${err.message}`);
      allOk = false;
    }
  }

  if (allOk) {
    console.log('\n  All vendor files ready in public/vendor/\n');
  } else {
    console.error('\n  Some vendor files could not be prepared.\n');
    process.exit(1);
  }
})();
