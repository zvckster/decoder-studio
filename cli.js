#!/usr/bin/env node
/*
 * Wazuh Decoder Studio: command line.
 *
 *   node cli.js generate <logfile> --name <decoder> [options]
 *   node cli.js test <decoders.xml> <logfile> [--json]
 *
 * generate options:
 *   --format auto|cef|leef|kv|json|csv|xml|template
 *   --scheme wazuh|wcs|custom       field naming (default wazuh)
 *   --prefix <text>                 prefix for dynamic field names
 *   --mode robust|strict            capture patterns (default robust)
 *   --strategy siblings|compact     decoder layout (default siblings)
 *   --json-mode plugin|regex
 *   --transport syslog|file|api     how logs reach Wazuh (default syslog)
 *   --out <file>                    decoder XML (default stdout)
 *   --rules <file>                  also write companion rules
 *   --rule-id <n>                   base rule ID (default 100100)
 *
 * Exit code is 1 when verification finds errors (handy in CI).
 */
'use strict';
const fs = require('fs');
const W = require('./public/engine/node.js');

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) args[k] = true;
      else {
        args[k] = next;
        i++;
      }
    } else args._.push(a);
  }
  return args;
}

function printIssues(issues) {
  const icon = { error: 'x', warn: '!', info: '-' };
  for (const i of issues) process.stderr.write(`  ${icon[i.level]} ${i.level.padEnd(5)} ${i.text}\n`);
}

function generate(args) {
  const [file] = args._.slice(1);
  if (!file || !args.name) {
    process.stderr.write('usage: node cli.js generate <logfile> --name <decoder> [options]\n');
    process.exit(2);
  }
  const text = fs.readFileSync(file, 'utf8');
  const analysis = W.analyze(text, {
    format: args.format || 'auto',
    scheme: args.scheme || 'wazuh',
    prefix: args.prefix || '',
    stripPri: (args.transport || (args['file-input'] ? 'file' : 'syslog')) === 'syslog',
  });
  const model = W.generate(analysis, {
    name: args.name,
    mode: args.mode || 'robust',
    strategy: args.strategy || 'siblings',
    jsonMode: args['json-mode'] || 'plugin',
  });
  const verdict = W.linter.verify(model, analysis);
  if (args.out) fs.writeFileSync(args.out, model.xml);
  else process.stdout.write(model.xml);
  if (args.rules) {
    const rules = W.generateRules(analysis, model, { baseId: Number(args['rule-id']) || 100100 });
    fs.writeFileSync(args.rules, rules.xml);
  }
  const c = verdict.coverage;
  process.stderr.write(
    `\n${analysis.formatLabel} · ${analysis.stats.parsed}/${analysis.stats.lines} lines parsed · ${c.decoded}/${c.lines} decoded · ${Math.round(c.fieldRate * 100)}% field coverage\n`
  );
  printIssues([...analysis.warnings, ...model.notes, ...verdict.issues]);
  process.exit(verdict.issues.some((i) => i.level === 'error') ? 1 : 0);
}

function testCmd(args) {
  const [xmlFile, logFile] = args._.slice(1);
  if (!xmlFile || !logFile) {
    process.stderr.write('usage: node cli.js test <decoders.xml> <logfile> [--json]\n');
    process.exit(2);
  }
  const parsed = W.xmlreader.readDecoders(fs.readFileSync(xmlFile, 'utf8'));
  const lines = W.util.splitLines(fs.readFileSync(logFile, 'utf8'));
  const issues = W.linter.lintDecoders(parsed.decoders);
  const sim = W.simulator.simulate(parsed.decoders, lines, { stripPri: (args.transport || (args['file-input'] ? 'file' : 'syslog')) === 'syslog' });
  if (args.json) {
    process.stdout.write(JSON.stringify({ errors: [...parsed.errors, ...sim.errors], issues, results: sim.results.map((r) => ({ decoder: r.decoder, fields: r.fields })) }, null, 2) + '\n');
  } else {
    sim.results.forEach((r, i) => process.stdout.write(`\n# line ${i + 1}\n${W.simulator.logtest(r)}\n`));
  }
  printIssues([...parsed.errors.map((t) => ({ level: 'error', text: t })), ...sim.errors.map((t) => ({ level: 'error', text: t })), ...issues]);
  process.exit(parsed.errors.length || sim.errors.length || issues.some((i) => i.level === 'error') ? 1 : 0);
}

const args = parseArgs(process.argv.slice(2));
if (args._[0] === 'generate') generate(args);
else if (args._[0] === 'test') testCmd(args);
else {
  process.stdout.write(fs.readFileSync(__filename, 'utf8').split('*/')[0].replace(/^#!.*\n\/\*\n?/, '').replace(/^ \* ?/gm, '') + '\n');
}
