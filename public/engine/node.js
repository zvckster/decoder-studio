/*
 * Node entry point: loads the browser engine files (plain scripts that
 * register on globalThis.WDG) and exports the namespace.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

if (!globalThis.WDG || !globalThis.WDG.analyze) {
  const files = JSON.parse(fs.readFileSync(path.join(__dirname, 'manifest.json'), 'utf8'));
  for (const f of files) {
    const file = path.join(__dirname, f);
    vm.runInThisContext(fs.readFileSync(file, 'utf8'), { filename: file });
  }
}
module.exports = globalThis.WDG;
