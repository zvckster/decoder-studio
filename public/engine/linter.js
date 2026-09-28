/*
 * Linter + coverage verification.
 *
 * Static checks encode Wazuh's load-time rules and the classic mistakes;
 * dynamic checks run the simulator over the sample logs and compare what
 * the decoder extracts with what the parser saw in each line.
 */
WDG_MODULE(function (W) {
  'use strict';

  const BUILTIN_NAMES = new Set(['json', 'sshd', 'sudo', 'pam', 'su', 'ossec', 'windows', 'web-accesslog', 'apache-errorlog', 'nginx-errorlog', 'iptables', 'kernel', 'named', 'postfix', 'dovecot', 'squid', 'auditd', 'pix', 'cisco-ios', 'sonicwall', 'pf', 'proftpd', 'vsftpd', 'openvpn', 'dhcpd']);
  const MAX_CONTENT = 1024;
  const MAX_ORDER = 256;

  function lintDecoders(decoders, opts) {
    const o = Object.assign({ generated: true }, opts);
    const issues = [];
    const add = (level, text, decoder) => issues.push({ level, text, decoder: decoder || null });
    let totalFields = 0;

    const rootNames = new Set(decoders.filter((d) => !d.parent).map((d) => d.name));
    for (const [idx, d] of decoders.entries()) {
      const where = `${d.parent ? 'child' : 'parent'} #${idx + 1}`;
      if (!d.name) add('error', `${where} has no name.`);
      else if (!/^[A-Za-z0-9_.\-]+$/.test(d.name)) add('warn', `Decoder name "${d.name}" contains unusual characters; stick to letters, digits, "-", "_" and ".".`, d.name);
      if (!d.parent && BUILTIN_NAMES.has(d.name)) add('warn', `"${d.name}" matches the name of a built-in Wazuh decoder: children are attached to every parent with that name. Pick a unique name.`, d.name);
      if (d.parent && !rootNames.has(d.parent) && !BUILTIN_NAMES.has(d.parent)) add('error', `Parent "${d.parent}" is not defined in this file.`, d.name);

      for (const [role, expr] of [['program_name', d.programName], ['prematch', d.prematch], ['regex', d.regex]]) {
        if (!expr) continue;
        const v = expr.value || '';
        const type = (expr.type || (role === 'program_name' ? 'osmatch' : 'osregex')).toLowerCase();
        if (v.length >= MAX_CONTENT) add('error', `<${role}> is ${v.length} characters long; Wazuh rejects element contents of 1024 characters or more. Split it into sibling decoders.`, d.name);
        if (/(^|[^\\])</.test(v)) add('error', `<${role}> contains a raw "<" which Wazuh's XML reader treats as a tag. Use \\x3c (PCRE2) or \\< instead, and avoid lookbehinds / named groups.`, d.name);
        if (/&(?:lt|gt|amp|quot|apos);/.test(v)) add('warn', `<${role}> contains an XML entity; Wazuh does not decode entities, so "&lt;" is matched literally.`, d.name);
        if (type === 'osregex' && /(^|[^\\])\|/.test(v) && /CEF:|LEEF:|\w\|\w/.test(v)) add('warn', `<${role}> is OS_Regex (the default) where "|" means OR: "${v.slice(0, 50)}" matches any one of its parts. Escape it as \\| or use type="pcre2".`, d.name);
        if (!['osregex', 'osmatch', 'pcre2'].includes(type)) add('warn', `Unknown type "${expr.type}" on <${role}>; Wazuh falls back to the default.`, d.name);
        if (role === 'prematch' && type === 'osmatch') add('error', '<prematch> supports only osregex and pcre2.', d.name);
        if (!o.generated && type === 'pcre2' && W.regex.backtrackRisk(v)) add('warn', `<${role}> repeats a group that itself contains an unbounded quantifier (like (a+)+ or ((?:x|y)+?)+): this can backtrack catastrophically. PCRE2 then hits its match limit and the event is silently not decoded.`, d.name);
        if (!o.generated && role === 'regex' && W.regex.wildcardCount(v) >= 4 && (d.order || []).length >= 3) add('warn', `<regex> chains ${W.regex.wildcardCount(v)} wildcards (.* / .*?) to capture ${(d.order || []).length} fields in a fixed order: one missing or re-ordered field drops the whole event, and failed matches backtrack polynomially. Prefer one sibling decoder per field.`, d.name);
        const c = W.regex.compile(expr, role);
        if (c.error) add('error', `<${role}> does not compile (${type}): ${c.error}`, d.name);
        if (role === 'regex' && !c.error) {
          const groups = c.groupCount || 0;
          const order = d.order || [];
          if (groups === 0) add('error', 'The regex has no capture group, so <order> gets nothing.', d.name);
          else if (order.length < groups) add('warn', `The regex has ${groups} capture group(s) but <order> names ${order.length}; extra captures are discarded.`, d.name);
          else if (order.length > groups) add('warn', `<order> names ${order.length} field(s) but the regex only captures ${groups}.`, d.name);
        }
      }
      if (d.order) {
        totalFields += d.order.length;
        const seen = new Set();
        for (const f of d.order) {
          if (!/^[A-Za-z0-9_.\-@]+$/.test(f)) add('error', `Field name "${f}" is invalid (no spaces or special characters).`, d.name);
          if (seen.has(f)) add('warn', `Field "${f}" appears twice in the same <order>.`, d.name);
          seen.add(f);
        }
      }
      if (d.regex && !d.order) add('error', 'A <regex> without <order> extracts nothing.', d.name);
      if (!d.parent && !d.prematch && !d.programName) add('error', 'This parent has neither <prematch> nor <program_name>: it matches every event that reaches it and hides other decoders.', d.name);
      if (d.plugin && d.regex) add('error', 'A decoder cannot combine <plugin_decoder> with <regex>/<order>.', d.name);
    }
    if (totalFields > MAX_ORDER) add('error', `${totalFields} fields in total: Wazuh's decoder_order_size limit is ${MAX_ORDER} fields per event.`);

    const names = new Map();
    // Anchored regexes (templates) are mutually exclusive: sharing names is fine.
    for (const d of decoders.filter((x) => x.order && !(x.regex && x.regex.value.startsWith('^') && x.regex.value.endsWith('$')))) {
      for (const f of d.order) names.set(f, (names.get(f) || 0) + 1);
    }
    for (const [f, n] of names) if (n > 1) add('info', `Field "${f}" is written by ${n} decoders; the last successful one wins.`);
    return issues;
  }

  /**
   * Verify a generated decoder against the analysed samples.
   * @returns {{issues, results, coverage}}
   */
  function verify(model, analysis, opts) {
    const o = Object.assign({ stripPri: analysis ? analysis.settings.stripPri : true, builtinJson: true }, opts);
    const issues = lintDecoders(model.decoders, { generated: true });
    const lines = analysis.lines.filter((it) => !it.isHeader);
    const sim = W.simulator.simulate(model.decoders, lines.map((it) => it.raw), o);
    for (const e of sim.errors) issues.push({ level: 'error', text: e });

    const expectName = model.builtinJson ? 'json' : model.name;
    let decoded = 0;
    const undecoded = [];
    sim.results.forEach((r, i) => {
      if (r.decoder === expectName) decoded++;
      else if (lines[i].ok) undecoded.push({ line: lines[i].index, by: r.decoder });
    });
    if (undecoded.length) {
      const stolen = undecoded.filter((u) => u.by);
      if (stolen.length) issues.push({ level: 'error', text: `${stolen.length} line(s) are decoded by "${stolen[0].by}" instead of "${expectName}".` });
      const none = undecoded.length - stolen.length;
      if (none) issues.push({ level: 'error', text: `${none} parsable line(s) are not matched by any parent decoder (e.g. line ${undecoded.find((u) => !u.by).line + 1}).` });
    }

    // Field coverage
    const fields = [];
    const selected = analysis.fields.filter((f) => f.selected && f.name && !f.isLabel);
    const jsonPlugin = model.format === 'json' && !model.decoders.some((d) => d.regex);
    for (const f of selected) {
      if (jsonPlugin && f.group === 'envelope') continue;
      const outName = jsonPlugin || model.builtinJson ? W.simulator.JSON_STATIC[f.key] || f.key : W.simulator.STATIC[f.name] || f.name;
      let expected = 0;
      let extracted = 0;
      let mismatched = 0;
      let example = null;
      lines.forEach((it, i) => {
        if (!it.ok) return;
        let want;
        if (f.group === 'template') {
          const c = analysis.template.clusters[f.hint.cluster];
          if (!c.lines.includes(it.index)) return;
          const tIdx = c.lines.indexOf(it.index);
          const p = c.positions[f.hint.pos];
          want = p.role === 'tail' ? W.analyzer.tailText(analysis, c, f.hint.pos, it.index) : W.formats.template.inner({ k: p.k, v: p.values[tIdx] });
        } else {
          const src = f.group === 'envelope' ? it.envelope && it.envelope.fields : it.parsed && it.parsed.fields;
          const pf = src && src.find((x) => x.key === f.key);
          if (!pf) return;
          want = pf.value;
        }
        expected++;
        const got = sim.results[i].fields.find((x) => x.name === outName);
        if (!got) return;
        extracted++;
        if (!sameValue(got.value, want, f)) {
          mismatched++;
          if (!example) example = { line: it.index, want, got: got.value };
        }
      });
      fields.push({ key: f.key, name: f.name, expected, extracted, mismatched, example });
      if (expected && extracted < expected) {
        issues.push({ level: 'warn', text: `"${f.name}" was extracted from ${extracted}/${expected} line(s) that contain "${f.key}".` });
      }
      if (mismatched) {
        issues.push({ level: 'info', text: `"${f.name}" differs from the parsed value on ${mismatched} line(s), e.g. expected "${short(example.want)}", got "${short(example.got)}".` });
      }
    }
    const totalExp = fields.reduce((a, f) => a + f.expected, 0);
    const totalGot = fields.reduce((a, f) => a + f.extracted - f.mismatched, 0);
    const coverage = {
      lines: lines.length,
      parsable: lines.filter((l) => l.ok).length,
      decoded,
      fieldRate: totalExp ? totalGot / totalExp : 1,
      fields,
    };
    const order = { error: 0, warn: 1, info: 2 };
    issues.sort((a, b) => order[a.level] - order[b.level]);
    return { issues, results: sim.results, coverage, loadErrors: sim.errors };
  }

  const short = (s) => W.util.truncate(String(s), 40);

  function sameValue(got, want, f) {
    if (got === want) return true;
    // Parsers unescape CEF/LEEF/JSON escapes; decoders keep the raw text.
    const norm = (s) => String(s).replace(/\\(.)/g, '$1').replace(/""/g, '"').trim();
    return norm(got) === norm(want);
  }

  W.linter = { lintDecoders, verify, BUILTIN_NAMES };
});
