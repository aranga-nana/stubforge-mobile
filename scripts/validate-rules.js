#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const STUB_ROOT = path.join(process.cwd(), 'stubs');
let errors = 0;

function walk(dir, fn) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, fn); else fn(full);
  }
}

if (!fs.existsSync(STUB_ROOT)) {
  console.error('No stubs directory found');
  process.exit(1);
}

const ruleFiles = [];
walk(STUB_ROOT, f => { if (/rule.*\.json$/.test(path.basename(f))) ruleFiles.push(f); });

if (ruleFiles.length === 0) {
  console.warn('No rule files found.');
  process.exit(0);
}

for (const file of ruleFiles) {
  try {
    const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!raw.id) { console.error('Missing id in', file); errors++; }
    if (!raw.match) { console.error('Missing match in', file); errors++; }
    if (!raw.response || !raw.response.file) { console.error('Missing response.file in', file); errors++; }
    else {
      const respPath = path.join(path.dirname(file), raw.response.file);
      if (!fs.existsSync(respPath)) { console.error('Response file missing:', respPath); errors++; }
    }
  } catch (e) {
    console.error('Invalid JSON in', file, e.message); errors++;
  }
}

if (errors > 0) {
  console.error(`Validation failed with ${errors} error(s).`);
  process.exit(1);
}
console.log(`Validated ${ruleFiles.length} rule file(s). All good.`);
