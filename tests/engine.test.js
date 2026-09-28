'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const W = require('../engine/node.js');

const sample = (id) => W.samples.find((s) => s.id === id);
const build = (id, cfg) => {
  const s = sample(id);
  const analysis = W.analyze(s.text);
  const model = W.generate(analysis, Object.assign({ name: s.source }, cfg));
  const verdict = W.linter.verify(model, analysis);
  return { s, analysis, model, verdict };
};

// ---------------------------------------------------------------- predecoder
test('predecoder: CEF after a syslog header becomes program_name "CEF"', () => {
  const p = W.predecode('Aug 23 11:30:15 ap-syslog-1 CEF:0|Trend Micro|Apex|1|2|n|3|src=1.2.3.4');
  assert.equal(p.hostname, 'ap-syslog-1');
  assert.equal(p.program_name, 'CEF');
  assert.equal(p.log, '0|Trend Micro|Apex|1|2|n|3|src=1.2.3.4');
});

test('predecoder: program[pid]: and ISO-8601 timestamps', () => {
  const p = W.predecode('2025-08-23T11:30:15.123+02:00 web01 nginx[812]: GET / 200');
  assert.equal(p.timestamp, '2025-08-23T11:30:15.123+02:00');
  assert.equal(p.hostname, 'web01');
  assert.equal(p.program_name, 'nginx');
  assert.equal(p.log, 'GET / 200');
});

test('predecoder: hostname followed by a non-program token keeps program_name null', () => {
  const p = W.predecode('Aug 23 11:30:15 fw01 date=2025-08-23 time=11:30:15 devname="x"');
  assert.equal(p.program_name, null);
  assert.equal(p.hostname, 'fw01');
  assert.equal(p.log, 'date=2025-08-23 time=11:30:15 devname="x"');
});

test('predecoder: strips <PRI> only when asked, RFC 5424 is not pre-decoded', () => {
  const line = '<134>1 2025-08-23T11:30:15.003Z idp01 app 1 ID - msg';
  assert.equal(W.predecode(line).log, '1 2025-08-23T11:30:15.003Z idp01 app 1 ID - msg');
  assert.equal(W.predecode(line, { stripPri: false }).log, line);
  assert.equal(W.predecode(line).program_name, null);
});

test('predecoder: Solaris style "program: msg" without hostname', () => {
  const p = W.predecode('Dec 29 10:00:01 sshd: Accepted password');
  assert.equal(p.program_name, 'sshd');
  assert.equal(p.hostname, null);
  assert.equal(p.log, 'Accepted password');
});

// ---------------------------------------------------------------- end-to-end
for (const s of W.samples) {
  test(`end-to-end: ${s.id} decodes every sample line with full field coverage`, () => {
    const { analysis, model, verdict } = build(s.id);
    assert.equal(analysis.stats.failed, 0, 'all lines parse');
    const errors = verdict.issues.filter((i) => i.level === 'error');
    assert.deepEqual(errors, [], 'no lint/load errors');
    assert.equal(verdict.coverage.decoded, verdict.coverage.parsable, 'every parsable line reaches the decoder');
    assert.equal(verdict.coverage.fieldRate, 1, 'every selected field is extracted with the expected value');
    assert.ok(!/(^|[^\\])<(?![!\/]?[a-z_-]+[\s>]|!--)/i.test(model.xml.replace(/<\/?[a-z_]+(?: [a-z]+="[^"]*")*>/gi, '')), 'no raw "<" inside element contents');
  });

  test(`end-to-end: ${s.id} XML round-trips through the Wazuh-style reader`, () => {
    const { analysis, model } = build(s.id);
    const parsed = W.xmlreader.readDecoders(model.xml);
    assert.deepEqual(parsed.errors, []);
    assert.equal(parsed.decoders.length, model.decoders.length);
    const lines = analysis.lines.map((l) => l.raw);
    const a = W.simulator.simulate(model.decoders, lines);
    const b = W.simulator.simulate(parsed.decoders, lines);
    assert.deepEqual(
      b.results.map((r) => r.fields),
      a.results.map((r) => r.fields)
    );
  });

  test(`end-to-end: ${s.id} strict and compact modes stay valid`, () => {
    for (const cfg of [{ mode: 'strict' }, { strategy: 'compact' }]) {
      const { verdict } = build(s.id, cfg);
      assert.deepEqual(verdict.issues.filter((i) => i.level === 'error'), [], JSON.stringify(cfg));
      assert.equal(verdict.coverage.decoded, verdict.coverage.parsable, JSON.stringify(cfg));
    }
  });
}

// ---------------------------------------------------------------- format specifics
test('CEF: two parents (program_name CEF / prematch) share the children', () => {
  const { model } = build('cef-trendmicro');
  const roots = model.decoders.filter((d) => !d.parent);
  assert.equal(roots.length, 2);
  assert.equal(roots[0].programName.value, '^CEF$');
  assert.match(roots[0].prematch.value, /^\^\\d\+\\\|Trend Micro\\\|Apex Central\\\|$/);
  assert.match(roots[1].prematch.value, /^\^CEF:/);
});

test('CEF: values with spaces are not truncated and custom labels name the field', () => {
  const { verdict, analysis } = build('cef-trendmicro');
  const r = verdict.results[0];
  const msg = analysis.fields.find((f) => f.key === 'msg');
  assert.equal(r.fields.find((f) => f.name === msg.name).value, 'Policy violation detected on confidential data transfer.');
  assert.equal(r.fields.find((f) => f.name === 'system_name').value, 'Apex One as a Service');
  assert.equal(analysis.fields.find((f) => f.key === 'cn1').name, 'ThreatID');
  assert.equal(analysis.fields.find((f) => f.key === 'cn1Label').selected, false);
});

test('LEEF: custom delimiter and literal pipe prematch', () => {
  const { analysis, model } = build('leef-caret');
  assert.equal(analysis.options.delimiter, '^');
  assert.ok(model.decoders.some((d) => d.regex && d.regex.value.includes('([^\\^]*)')));
});

test('KV: quoted, unquoted and fingerprint prematch', () => {
  const { model, verdict } = build('kv-fortigate');
  const root = model.decoders.find((d) => !d.parent);
  assert.match(root.prematch.value, /devname=/);
  const r = verdict.results[2];
  assert.equal(r.fields.find((f) => f.name === 'message').value, 'Administrator admin logged in successfully from https(10.1.1.5)');
});

test('KV: unquoted values containing spaces run until the next key', () => {
  const a = W.analyze('app=x msg=hello big world user=bob\napp=x msg=bye user=alice');
  const m = W.generate(a, { name: 'x' });
  const v = W.linter.verify(m, a);
  assert.equal(v.results[0].fields.find((f) => f.name === 'message').value, 'hello big world');
  assert.equal(v.coverage.fieldRate, 1);
});

test('JSON: plain JSON yields rules on the built-in decoder, not a competing parent', () => {
  const { model, analysis } = build('json-plain');
  assert.equal(model.builtinJson, true);
  assert.equal(model.decoders.length, 0);
  const rules = W.generateRules(analysis, model);
  assert.match(rules.xml, /<decoded_as>json<\/decoded_as>/);
  assert.match(rules.xml, /<field name="vendor" type="pcre2">\^Contoso\$<\/field>/);
});

test('JSON: JSON after a program name / a prefix uses JSON_Decoder with the right offset', () => {
  const a = build('json-syslog').model.decoders[0];
  assert.equal(a.programName.value, '^kube-audit$');
  assert.equal(a.plugin.offset, null);
  const b = build('json-prefix').model.decoders[0];
  assert.equal(b.plugin.offset, 'after_prematch');
  assert.match(b.prematch.value, /\(\?=\\\{\)$/);
});

test('JSON: regex mode lets fields be renamed', () => {
  const { verdict, analysis } = build('json-prefix', { jsonMode: 'regex' });
  const actor = analysis.fields.find((f) => f.key === 'actor');
  assert.equal(verdict.results[0].fields.find((f) => f.name === actor.name).value, 'ops-bot');
});

test('CSV: header row detected, quoted cells with delimiters handled', () => {
  const { analysis, verdict } = build('csv-header');
  assert.deepEqual(analysis.options.header, ['timestamp', 'user', 'src_ip', 'country', 'result', 'reason']);
  const reason = analysis.fields.find((f) => f.key === 'reason');
  // results cover data lines only (the header row is excluded)
  assert.equal(verdict.results[1].fields.find((f) => f.name === reason.name).value, 'bad password, locked');
});

test('RFC 5424: envelope and structured data are extracted', () => {
  const { verdict } = build('rfc5424');
  const f = verdict.results[1].fields;
  assert.equal(f.find((x) => x.name === 'sd.region').value, 'us-east');
  assert.equal(f.find((x) => x.name === 'srcip').value, '198.51.100.23');
  assert.equal(f.find((x) => x.name === 'message').value, 'invalid credentials');
});

test('Free-form: templates and context naming (sshd-like)', () => {
  const { model } = build('freeform-ssh');
  const orders = model.decoders.filter((d) => d.regex).map((d) => d.order.join(','));
  assert.ok(orders.includes('dstuser,srcip,srcport'));
});

test('Free-form: access log naming', () => {
  const { model } = build('freeform-access');
  const child = model.decoders.find((d) => d.regex);
  assert.deepEqual(child.order.slice(0, 1), ['srcip']);
  assert.ok(child.order.includes('request'));
  assert.ok(child.order.includes('http_status'));
  assert.ok(child.order.includes('user_agent'));
});

// ---------------------------------------------------------------- Wazuh semantics
test('simulator: OS_Regex prematch with "|" is an OR (the classic CEF mistake)', () => {
  const bad = W.xmlreader.readDecoders('<decoder name="t"><prematch>CEF:0|Trend Micro|</prematch></decoder>').decoders;
  const r = W.simulator.simulate(bad, ['something mentioning Trend Micro only'], { builtinJson: false }).results[0];
  assert.equal(r.decoder, 't', 'OR semantics: matches unrelated log');
  const issues = W.linter.lintDecoders(bad);
  assert.ok(issues.some((i) => /means OR/.test(i.text)));
});

test('simulator: prematch-only parents never see logs that have a program_name', () => {
  const d = W.xmlreader.readDecoders('<decoder name="t"><prematch type="pcre2">^CEF:0\\|</prematch></decoder>').decoders;
  const r = W.simulator.simulate(d, ['Aug 23 11:30:15 host CEF:0|V|P|1|2|n|3|a=b'], { builtinJson: false }).results[0];
  assert.equal(r.decoder, null);
});

test('simulator: siblings with prematch are refused at load time', () => {
  const xml = `<decoder name="p"><prematch>x</prematch></decoder>
  <decoder name="c"><parent>p</parent><regex>(a)</regex><order>a</order></decoder>
  <decoder name="c"><parent>p</parent><prematch>y</prematch><regex>(b)</regex><order>b</order></decoder>`;
  const { errors } = W.simulator.load(W.xmlreader.readDecoders(xml).decoders);
  assert.ok(errors.some((e) => /cannot have a <prematch>/.test(e)));
});

test('simulator: a failing sibling is skipped, a failing single child stops decoding', () => {
  const xml = `<decoder name="p"><prematch>^x </prematch></decoder>
  <decoder name="c"><parent>p</parent><regex type="pcre2">a=(\\d+)</regex><order>a</order></decoder>
  <decoder name="c"><parent>p</parent><regex type="pcre2">b=(\\d+)</regex><order>b</order></decoder>
  <decoder name="c"><parent>p</parent><regex type="pcre2">c=(\\d+)</regex><order>c</order></decoder>`;
  const d = W.xmlreader.readDecoders(xml).decoders;
  const r = W.simulator.simulate(d, ['x a=1 c=3'], { builtinJson: false }).results[0];
  assert.deepEqual(r.fields.map((f) => f.name + '=' + f.value), ['a=1', 'c=3']);
});

test('simulator: built-in json decoder wins over a custom prematch-only JSON parent', () => {
  const d = W.xmlreader.readDecoders('<decoder name="mine"><prematch type="pcre2">^\\{</prematch><plugin_decoder>JSON_Decoder</plugin_decoder></decoder>').decoders;
  const r = W.simulator.simulate(d, ['{"a":"b"}']).results[0];
  assert.equal(r.decoder, 'json');
});

test('simulator: JSON_Decoder only maps its own static keys', () => {
  const r = W.simulator.simulate([], ['{"srcip":"1.2.3.4","user":"bob","systemname":"h"}']).results[0];
  assert.deepEqual(
    r.fields.map((f) => `${f.name}:${f.static}`),
    ['srcip:true', 'user:false', 'system_name:true']
  );
});

test('simulator: offset="after_regex" chains from the end of the previous sibling', () => {
  const xml = `<decoder name="p"><prematch>^q</prematch></decoder>
  <decoder name="c"><parent>p</parent><regex type="pcre2">^q (\\w+)</regex><order>a</order></decoder>
  <decoder name="c"><parent>p</parent><regex type="pcre2" offset="after_regex">^ (\\w+)</regex><order>b</order></decoder>`;
  const r = W.simulator.simulate(W.xmlreader.readDecoders(xml).decoders, ['q one two'], { builtinJson: false }).results[0];
  assert.deepEqual(r.fields.map((f) => f.value), ['one', 'two']);
});

test('xmlreader: entities are not decoded and \\< is content', () => {
  const d = W.xmlreader.readDecoders('<decoder name="x"><prematch>a&lt;b \\<c</prematch></decoder>').decoders[0];
  assert.equal(d.prematch.value, 'a&lt;b \\<c');
  assert.ok(W.linter.lintDecoders([d]).some((i) => /entity/.test(i.text)));
});

// ---------------------------------------------------------------- regex layer
test('regex: PCRE2 branch reset keeps a single field', () => {
  const c = W.regex.compile({ value: 'k=(?|"([^"]*)"|(\\S*))', type: 'pcre2' }, 'regex');
  assert.deepEqual(c.exec('k="a b"').groups, ['a b']);
  assert.deepEqual(c.exec('k=ab').groups, ['ab']);
  assert.equal(c.groupCount, 1);
});

test('regex: \\x3c, possessive, atomic, (?i), POSIX classes', () => {
  assert.deepEqual(W.regex.compile({ value: '\\x3c(\\w++)\\x3e', type: 'pcre2' }).exec('<Event>').groups, ['Event']);
  assert.ok(W.regex.compile({ value: '(?i)^abc', type: 'pcre2' }).exec('ABC'));
  assert.ok(W.regex.compile({ value: '(?>a+)b', type: 'pcre2' }).exec('aab'));
  assert.ok(W.regex.compile({ value: '^[[:digit:]]+$', type: 'pcre2' }).exec('123'));
});

test('regex: OS_Regex classes and case-insensitivity', () => {
  const c = W.regex.compile({ value: '^User (\\S+) from (\\d+.\\d+.\\d+.\\d+)' }, 'regex');
  assert.deepEqual(c.exec('user bob from 1.2.3.4').groups, ['bob', '1.2.3.4']);
});

test('escapeRegex never emits a raw "<"', () => {
  assert.equal(W.util.escapeRegex('<a|b>'), '\\x3ca\\|b\\x3e');
});

// ---------------------------------------------------------------- limits
test('compact strategy chunks regexes under the 1024-char element limit', () => {
  const keys = Array.from({ length: 80 }, (_, i) => `field_number_${i}`);
  const line = keys.map((k, i) => `${k}=v${i}`).join(' ');
  const a = W.analyze([line, line.replace(/v(\d+)/g, 'w$1')].join('\n'));
  const m = W.generate(a, { name: 'wide', strategy: 'compact' });
  const regexes = m.decoders.filter((d) => d.regex);
  assert.ok(regexes.length > 1 && regexes.length < 80);
  for (const d of regexes) assert.ok(d.regex.value.length < 1024);
  assert.equal(W.linter.verify(m, a).coverage.fieldRate, 1);
});

test('lint: regex over 1024 chars and missing prematch are errors', () => {
  const issues = W.linter.lintDecoders([{ name: 'p' }, { name: 'c', parent: 'p', regex: { value: '(a)' + 'b'.repeat(1100), type: 'pcre2' }, order: ['a'] }]);
  assert.ok(issues.some((i) => i.level === 'error' && /1024/.test(i.text)));
  assert.ok(issues.some((i) => i.level === 'error' && /neither <prematch> nor <program_name>/.test(i.text)));
});

// ---------------------------------------------------------------- rules
test('rules: event-ID rules carry names and levels from the samples', () => {
  const { analysis, model } = build('cef-trendmicro');
  const xml = W.generateRules(analysis, model).xml;
  assert.match(xml, /<decoded_as>trendmicro-apex<\/decoded_as>/);
  assert.match(xml, /<id>\^400110\$<\/id>/);
  assert.match(xml, /level="10"[\s\S]*?Virus\/Malware/);
  const parsed = W.xmlreader.parse(xml);
  assert.deepEqual(parsed.errors, []);
});

// ---------------------------------------------------------------- type library
test('types: every strict pattern compiles and accepts representative values', () => {
  const examples = {
    ipv4: '10.1.2.3', ipv6: 'fe80::1', ipport: '10.0.0.1:443', mac: '00-1B-63-84-45-E6', uuid: '123e4567-e89b-12d3-a456-426614174000',
    sha256: 'a'.repeat(64), sha1: 'b'.repeat(40), md5: 'c'.repeat(32), epoch: '1724412310000', integer: '-42', number: '3.14', hex: '0x1F',
    bool: 'true', iso8601: '2025-08-23T11:30:15.123Z', syslogtime: 'Aug 23 11:30:15', date: '2025/08/23', time: '11:30:15', email: 'a@b.example',
    url: 'https://x.example/a?b=c', unixpath: '/var/log/x.log', domainuser: 'CORP\\jdoe', filename: 'report.xlsx', fqdn: 'dc01.corp.example', word: 'alpha_1', token: 'x/y:z',
  };
  for (const t of W.types.TYPES) {
    if (!t.pattern) continue;
    const re = new RegExp('^(?:' + t.pattern + ')$');
    if (examples[t.id]) {
      assert.equal(W.types.classify(examples[t.id]), t.id, `classify ${t.id}`);
      assert.ok(re.test(examples[t.id]), `pattern of ${t.id}`);
    }
    assert.ok(!t.pattern.includes('<'), `${t.id} pattern has no raw <`);
  }
});

// ---------------------------------------------------------------- backtracking guard
test('regex: catastrophic-backtracking heuristic', () => {
  const risky = ['(a+)+', '(?:\S+)*', '((?:[^\\\t^]|\\[\t^])+?)+'];
  const safe = ['(?:[^"]|"")*', '(\d{1,3}\.){3}', '(?:ab)+', '^(?:(?:"(?:[^"]|"")*"|[^,"]*),){5}'];
  for (const r of risky) assert.equal(W.regex.backtrackRisk(r), true, r);
  for (const s of safe) assert.equal(W.regex.backtrackRisk(s), false, s);
});

test('generator: a risky or invalid custom prematch is refused', () => {
  const a = W.analyze(sample('kv-fortigate').text);
  for (const pm of ['(a+)+x', '([unclosed']) {
    const m = W.generate(a, { name: 'x', customPrematch: pm });
    assert.ok(m.notes.some((n) => n.level === 'error' && /Custom prematch ignored/.test(n.text)), pm);
    assert.notEqual(m.decoders[0].prematch.value, pm);
  }
  const ok = W.generate(a, { name: 'x', customPrematch: '^date=\S+ time=' });
  assert.equal(ok.decoders[0].prematch.value, '^date=\S+ time=');
});

test('JSON regex mode verifies on every JSON sample that is not plain', () => {
  for (const id of ['json-syslog', 'json-prefix']) {
    const { verdict } = build(id, { jsonMode: 'regex' });
    assert.equal(verdict.coverage.fieldRate, 1, id);
    assert.deepEqual(verdict.issues.filter((i) => i.level === 'error'), [], id);
  }
});

// ---------------------------------------------------------------- regressions and naming
test('access log with ";" inside the user agent is free-form, not CSV, and decodes', () => {
  const line = '205.197.2.175 - - [22/Aug/2017:17:43:56 +0000] www.sumologic.com "GET /wp-content/uploads/Screen-Shot-2017-04-13-at-7.12.35-PM-231x300.png HTTP/1.1" 304 0 "https://www.sumologic.com/aws/elb/aw...s-application/" "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0" 0.000';
  const a = W.analyze(line);
  assert.equal(a.format, 'template');
  const m = W.generate(a, { name: 'web' });
  const v = W.linter.verify(m, a);
  assert.equal(v.coverage.decoded, 1);
  assert.equal(v.coverage.fieldRate, 1);
  const order = m.decoders.find((d) => d.regex).order;
  for (const n of ['srcip', 'request', 'http_status', 'referrer', 'user_agent', 'response_time']) assert.ok(order.includes(n), n);
});

test('KV prematch anchors on the earliest shared keys', () => {
  const { model } = build('kv-fortigate');
  assert.match(model.decoders[0].prematch.value, /^\^date=.*time=.*devname=$/);
});

test('naming schemes: Native Wazuh, WCS v5 (custom.* for unknown fields), Custom mapping', () => {
  const text = sample('kv-fortigate').text;
  const wz = W.analyze(text, { scheme: 'wazuh' }).fields;
  const wcs = W.analyze(text, { scheme: 'wcs' }).fields;
  const cus = W.analyze(text, { scheme: 'custom', customMap: { srcip: 'client.address' } }).fields;
  const name = (fs, k) => fs.find((f) => f.key === k).name;
  assert.equal(name(wz, 'srcip'), 'srcip');
  assert.equal(name(wcs, 'srcip'), 'source.ip');
  assert.equal(name(wcs, 'vd'), 'custom.vd');
  assert.equal(name(cus, 'srcip'), 'client.address');
  assert.equal(name(cus, 'dstip'), 'dstip');
  assert.equal(W.fieldmap.normalizeScheme('ecs'), 'wcs');
  assert.equal(W.fieldmap.normalizeScheme('original'), 'custom');
});
