#!/usr/bin/env node
/**
 * Prepares front-end vendor files in public/vendor/.
 * All files are copied directly from node_modules — no network needed.
 * FullCalendar v6 global bundle injects its own CSS via JS (no separate CSS file).
 *
 * Run manually: node scripts/download-vendor.js
 * Also runs automatically via the "postinstall" npm script.
 */
'use strict';

const fs   = require('fs');
const path = require('path');

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

// ── Main ─────────────────────────────────────────────────────
// Note: FullCalendar v6 global bundle injects its own CSS via JS — no separate CSS file needed.
let allOk = true;

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

if (allOk) {
  console.log('\n  All vendor files ready in public/vendor/\n');
} else {
  console.error('\n  Some vendor files could not be prepared.\n');
  process.exit(1);
}
