#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const legacy = [
  'StubServer-OAuth2-PKCE.postman_collection.json',
  'StubServer-Local.postman_environment.json'
];
const dir = path.join(__dirname, '..', 'postman');
let removed = 0;
for (const f of legacy) {
  const full = path.join(dir, f);
  if (fs.existsSync(full)) {
    fs.unlinkSync(full);
    console.log('Removed legacy Postman file:', f);
    removed++;
  }
}
if (!removed) console.log('No legacy Postman files present.');
