/*
 * Analyzer: raw pasted logs → structured analysis the generator and the UI
 * work from.
 *
 *   1. Wazuh pre-decoding emulation per line (timestamp/hostname/program_name)
 *   2. RFC 5424 envelope detection (Wazuh does not pre-decode 5424)
 *   3. Format detection by per-line vote
 *   4. Parsing + field aggregation (presence, distinct values, type, quoting)
 *   5. Name suggestions (Native Wazuh / WCS v5 / custom mapping)
 */
WDG_MODULE(function (W) {
  'use strict';
  const U = W.util;

  const FORMAT_ORDER = ['json', 'cef', 'leef', 'xml', 'kv', 'csv', 'template'];
  const RFC5424 = /^(?:<\d{1,3}>)?1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]"\\]|\\.|"(?:[^"\\]|\\.)*")*\])+)(?: |$)/;
  const ENVELOPE_KEYS = ['syslog.timestamp', 'syslog.hostname', 'syslog.app_name', 'syslog.procid', 'syslog.msgid'];

  function parseEnvelope(body) {
    const m = RFC5424.exec(body);
    if (!m) return null;
    const fields = ENVELOPE_KEYS.map((k, i) => ({ key: k, value: m[i + 1], group: 'envelope', quoted: false, spaces: false }));
    const sd = m[6];
    if (sd !== '-') {
      const re = /([\w.:@-]+)="((?:[^"\\]|\\.)*)"/g;
      let p;
      while ((p = re.exec(sd))) fields.push({ key: `sd.${p[1]}`, value: p[2], group: 'envelope', quoted: true, spaces: /\s/.test(p[2]), hint: { sdParam: p[1] } });
    }
    return { fields, payload: body.slice(m[0].length), appName: m[3] };
  }

  /**
   * @param {string} text
   * @param {object} [opts]
   * @param {boolean} [opts.stripPri=true]
   * @param {string}  [opts.format='auto']
   * @param {string}  [opts.scheme='wazuh']  wazuh | wcs | custom
   * @param {Object}  [opts.customMap]       key → name, used by the custom scheme
   * @param {string}  [opts.prefix='']
   * @param {number}  [opts.maxLines=5000]
   */
  function analyze(text, opts) {
    const o = Object.assign({ stripPri: true, format: 'auto', scheme: 'wazuh', prefix: '', customMap: {}, maxLines: 5000 }, opts);
    const warnings = [];
    let lines = U.splitLines(text);
    if (lines.length > o.maxLines) {
      warnings.push({ level: 'info', text: `Only the first ${o.maxLines} lines were analysed.` });
      lines = lines.slice(0, o.maxLines);
    }

    // Pretty-printed JSON pasted over several lines → compact it.
    if (lines.length > 1 && /^\s*[{[]/.test(lines[0])) {
      try {
        const v = JSON.parse(lines.join('\n'));
        const arr = Array.isArray(v) ? v : [v];
        if (arr.every((x) => x && typeof x === 'object')) {
          lines = arr.map((x) => JSON.stringify(x));
          warnings.push({ level: 'info', text: `Multi-line JSON was compacted into ${lines.length} single-line event(s): Wazuh reads one event per line.` });
        }
      } catch (e) {
        /* not one JSON document */
      }
    }

    const items = lines.map((raw, index) => {
      const pre = W.predecode(raw, { stripPri: o.stripPri });
      const env = parseEnvelope(pre.log);
      return { index, raw, pre, body: pre.log, envelope: env, payload: env ? env.payload : pre.log };
    });

    // ---- format detection -------------------------------------------------
    const scores = {};
    for (const id of FORMAT_ORDER) scores[id] = 0;
    const votes = [];
    for (const it of items) {
      let best = 'template';
      let bestScore = 0;
      for (const id of FORMAT_ORDER) {
        const s = W.formats[id].detect(it.payload, it.pre);
        scores[id] += s;
        if (s > bestScore) {
          best = id;
          bestScore = s;
        }
      }
      votes.push(best);
    }
    for (const id of FORMAT_ORDER) scores[id] = items.length ? scores[id] / items.length : 0;

    let format = o.format !== 'auto' && W.formats[o.format] ? o.format : U.mode(votes) || 'template';
    const share = votes.filter((v) => v === format).length / Math.max(1, votes.length);
    if (o.format === 'auto' && items.length && share < 0.8) {
      warnings.push({
        level: 'warn',
        text: `Mixed input: only ${Math.round(share * 100)}% of the lines look like ${W.formats[format].label}. Other lines will not be decoded, so consider one decoder per source.`,
      });
    }
    const fmt = W.formats[format];
    const fmtItems = items.map((it) => ({ pre: it.pre, body: it.payload }));
    const options = fmt.configure(fmtItems) || {};

    // ---- parsing ----------------------------------------------------------
    for (const it of items) {
      it.parsed = fmt.parse(it.payload, options, it.pre);
      it.isHeader = !!(it.parsed && it.parsed.meta && it.parsed.meta.isHeader);
      it.ok = !!it.parsed && (format === 'template' || it.parsed.fields.length > 0);
    }
    const dataItems = items.filter((it) => !it.isHeader);
    const okItems = dataItems.filter((it) => it.ok);

    // ---- template mining --------------------------------------------------
    let template = null;
    if (format === 'template') {
      const clusters = W.formats.template.cluster(dataItems.map((it) => it.payload));
      clusters.forEach((c, ci) => {
        c.id = ci;
        c.lines = c.lines.map((li) => dataItems[li].index);
      });
      template = { clusters };
    }

    // ---- aggregation ------------------------------------------------------
    const agg = new Map();
    let order = 0;
    const add = (f) => {
      let a = agg.get(f.key);
      if (!a) {
        a = { key: f.key, group: f.group || 'body', count: 0, values: new Map(), quoted: 0, spaces: false, labels: new Set(), hint: f.hint || null, order: order++ };
        agg.set(f.key, a);
      }
      a.count++;
      a.values.set(f.value, (a.values.get(f.value) || 0) + 1);
      if (f.quoted) a.quoted++;
      if (f.spaces) a.spaces = true;
      if (f.label) a.labels.add(f.label);
    };
    for (const it of okItems) {
      if (it.envelope) it.envelope.fields.forEach(add);
      if (it.parsed) it.parsed.fields.forEach(add);
    }
    if (template) {
      for (const c of template.clusters) {
        c.positions.forEach((p, pi) => {
          if (p.role !== 'var') return;
          const key = `t${c.id}.${pi}`;
          const values = new Map();
          for (const v of p.values) {
            const iv = W.formats.template.inner({ k: p.k, v });
            values.set(iv, (values.get(iv) || 0) + 1);
          }
          agg.set(key, {
            key,
            group: 'template',
            count: c.lines.length,
            values,
            quoted: 0,
            spaces: false,
            labels: new Set(),
            hint: { cluster: c.id, pos: pi },
            order: order++,
            templateName: p.name,
          });
        });
      }
    }

    const denom = Math.max(1, okItems.length);
    const fields = [...agg.values()].map((a) => {
      const samples = [...a.values.keys()];
      const type = W.types.inferType(samples.slice(0, 200));
      const label = a.labels.size === 1 ? [...a.labels][0] : null;
      const total = a.group === 'template' ? a.count : a.count;
      return {
        key: a.key,
        group: a.group,
        count: a.count,
        presence: a.group === 'template' ? 1 : a.count / denom,
        distinct: a.values.size,
        samples: samples.slice(0, 50),
        topValues: [...a.values.entries()].sort((x, y) => y[1] - x[1]).slice(0, 10),
        type,
        quoting: a.quoted === 0 ? 'never' : a.quoted === total ? 'always' : 'mixed',
        spaces: a.spaces || samples.some((s) => /\s/.test(s)),
        label,
        hint: a.hint,
        templateName: a.templateName || null,
      };
    });

    // label companions (cs1Label...) are consumed for naming, not extracted
    const labelKeys = new Set(fields.filter((f) => f.label).map((f) => f.key + 'Label'));
    o.scheme = W.fieldmap.normalizeScheme(o.scheme);
    const names = W.fieldmap.suggestNames(
      fields.map((f) => ({ key: f.key, type: f.type, label: f.label, presence: f.presence })),
      { scheme: o.scheme, prefix: o.prefix, customMap: o.customMap }
    );
    const IGNORE_DEFAULT = new Set(['cef.version', 'cef.vendor', 'cef.product', 'cef.device_version', 'leef.version', 'leef.vendor', 'leef.product', 'leef.product_version', 'syslog.timestamp', 'syslog.procid']);
    for (const f of fields) {
      f.suggested = f.group === 'template' ? templateName(f.templateName, o) : names.get(f.key);
      f.name = f.suggested;
      f.isLabel = labelKeys.has(f.key);
      f.selected = !f.isLabel && !IGNORE_DEFAULT.has(f.key) && f.samples.some((s) => s !== '');
    }

    // ---- root groups (by program_name, the pre-decoder's routing key) -----
    const groupMap = new Map();
    for (const it of okItems) {
      const k = it.pre.program_name;
      groupMap.set(k, (groupMap.get(k) || 0) + 1);
    }
    const groups = [...groupMap.entries()].map(([programName, count]) => ({ programName, count }));

    const failed = dataItems.filter((it) => !it.ok).length;
    if (failed) warnings.push({ level: 'warn', text: `${failed} line(s) could not be parsed as ${fmt.label}.` });
    const withProgram = okItems.filter((it) => it.pre.program_name !== null);
    if (withProgram.length && withProgram.length < okItems.length) {
      warnings.push({
        level: 'info',
        text: `${withProgram.length} line(s) carry a syslog program name ("${U.uniq(withProgram.map((i) => i.pre.program_name)).slice(0, 3).join('", "')}") and ${okItems.length - withProgram.length} don't. Wazuh routes these to different decoder lists, so both a <program_name> parent and a <prematch> parent will be generated.`,
      });
    }
    if (format === 'cef' || format === 'leef') {
      const vendors = U.uniq(okItems.map((it) => `${it.parsed.meta.vendor} ${it.parsed.meta.product}`));
      if (vendors.length > 1) warnings.push({ level: 'warn', text: `Several ${fmt.label} sources detected (${vendors.slice(0, 4).join(', ')}). The parent will match all of them; generate one decoder per product for clean rules.` });
    }
    if (format === 'json' && okItems.some((it) => it.pre.program_name === null && it.parsed.meta.prefix.trim() === '')) {
      warnings.push({ level: 'info', text: 'Plain JSON lines are always decoded by Wazuh\'s built-in "json" decoder (it is loaded before custom decoders). The generator produces rules for them instead of a competing decoder.' });
    }

    return {
      version: W.version,
      format,
      formatLabel: fmt.label,
      formatScores: scores,
      share,
      options,
      lines: items,
      groups,
      fields,
      template,
      envelope: okItems.some((it) => it.envelope),
      stats: { lines: items.length, parsed: okItems.length, failed, headers: items.length - dataItems.length },
      warnings,
      settings: o,
    };
  }

  /** Name of a free-form template variable in the chosen scheme. */
  function templateName(name, o) {
    const scheme = W.fieldmap.normalizeScheme(o.scheme);
    if (scheme === 'custom') return (o.customMap && o.customMap[name]) || name;
    if (scheme === 'wcs') {
      const concept = W.fieldmap.conceptOf(name);
      return concept && W.fieldmap.CONCEPTS[concept] ? W.fieldmap.CONCEPTS[concept][1] : `custom.${name}`;
    }
    return name;
  }

  /**
   * Re-run name suggestions after the scheme, prefix or custom mapping
   * changed. Names the analyst edited by hand are kept.
   */
  function renameAll(analysis, scheme, prefix, customMap) {
    const o = { scheme: W.fieldmap.normalizeScheme(scheme), prefix, customMap: customMap || analysis.settings.customMap };
    const names = W.fieldmap.suggestNames(
      analysis.fields.map((f) => ({ key: f.key, type: f.type, label: f.label, presence: f.presence })),
      o
    );
    for (const f of analysis.fields) {
      const manual = f.name !== f.suggested;
      const next = f.group === 'template' ? templateName(f.templateName, o) : names.get(f.key);
      f.suggested = next;
      if (!manual) f.name = next;
    }
    Object.assign(analysis.settings, o);
    return analysis;
  }

  /**
   * Rebuild the template fields after the analyst toggled tokens between
   * literal / variable / rest-of-line. Keeps names and selections.
   */
  function refreshTemplate(analysis) {
    if (!analysis.template) return analysis;
    const previous = new Map(analysis.fields.filter((f) => f.group === 'template').map((f) => [f.key, f]));
    const others = analysis.fields.filter((f) => f.group !== 'template');
    const out = [];
    for (const c of analysis.template.clusters) {
      const used = new Set();
      const tailAt = c.positions.findIndex((p) => p.role === 'tail');
      c.positions.forEach((p, pi) => {
        if (tailAt >= 0 && pi > tailAt) return; // swallowed by "rest of line"
        if (p.role !== 'var' && p.role !== 'tail') return;
        const key = `t${c.id}.${pi}`;
        const prev = previous.get(key);
        let values;
        if (p.role === 'tail') {
          values = c.lines.map((li) => tailText(analysis, c, pi, li));
        } else values = p.values.map((v) => W.formats.template.inner({ k: p.k, v }));
        const type = W.types.inferType(values.slice(0, 200));
        let name = prev ? prev.name : p.name || (p.role === 'tail' ? 'message' : 'value');
        let n = 2;
        const base = name;
        while (used.has(name)) name = `${base}_${n++}`;
        used.add(name);
        p.name = name;
        const counts = new Map();
        for (const v of values) counts.set(v, (counts.get(v) || 0) + 1);
        out.push({
          key,
          group: 'template',
          count: c.lines.length,
          presence: 1,
          distinct: counts.size,
          samples: [...counts.keys()].slice(0, 50),
          topValues: [...counts.entries()].sort((x, y) => y[1] - x[1]).slice(0, 10),
          type,
          quoting: 'never',
          spaces: values.some((v) => /\s/.test(v)),
          label: null,
          hint: { cluster: c.id, pos: pi },
          templateName: name,
          suggested: prev ? prev.suggested : name,
          name,
          isLabel: false,
          selected: prev ? prev.selected : true,
        });
      });
    }
    analysis.fields = [...others, ...out];
    return analysis;
  }

  /** Text of a line from token `pi` to the end (for "rest of line" tokens). */
  function tailText(analysis, c, pi, lineIndex) {
    const it = analysis.lines[lineIndex];
    const toks = W.formats.template.tokenize(it.payload);
    // approximate: rebuild from the first token at that position
    const first = c.positions[pi].values[c.lines.indexOf(lineIndex)];
    const idx = first === undefined ? -1 : it.payload.indexOf(first);
    return idx >= 0 ? it.payload.slice(idx) : toks.slice(pi).map((t) => t.v).join(' ');
  }

  W.analyze = analyze;
  W.analyzer = { analyze, renameAll, refreshTemplate, tailText, parseEnvelope, FORMAT_ORDER, RFC5424_SOURCE: RFC5424.source };
});
