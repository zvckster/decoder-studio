/*
 * Generator: analysis + user choices → decoder model → Wazuh XML.
 *
 * Design decisions (all verified against analysisd's source):
 *  - Parents are routed like Wazuh routes events: one parent per program_name
 *    seen in the samples (<program_name>, OS_Match), plus one <prematch>
 *    parent for lines without a program name. Parents share the same name,
 *    so the children attach to all of them.
 *  - Fields are extracted by *sibling* children (same name, no prematch):
 *    Wazuh evaluates every sibling, so a missing or re-ordered field only
 *    loses that field instead of the whole event.
 *  - "compact" strategy merges fields that are always present, in a stable
 *    order, into chunked regexes (< 1024 chars, Wazuh's element limit).
 *  - All patterns are PCRE2 (type="pcre2"), never contain a raw '<', and
 *    never use XML entities (Wazuh's XML reader does not decode them).
 */
WDG_MODULE(function (W) {
  'use strict';
  const U = W.util;

  const MAX_REGEX = 1000; // _loadmemory() refuses element contents ≥ 1024 bytes
  const ENV_PREFIX = '^(?:\\x3c\\d{1,3}\\x3e)?1 ';
  const SD = '(?:-|(?:\\[(?:[^\\]"\\\\]|\\\\.|"(?:[^"\\\\]|\\\\.)*")*\\])+)';

  const DEFAULTS = {
    name: '',
    mode: 'robust', // robust | strict
    strategy: 'siblings', // siblings | compact
    jsonMode: 'plugin', // plugin | regex
    comments: true,
  };

  function envelopePattern(items) {
    const apps = U.uniq(items.filter((it) => it.envelope).map((it) => it.envelope.appName));
    const app = apps.length === 1 && apps[0] !== '-' ? U.escapeRegex(apps[0]) : '\\S+';
    return `${ENV_PREFIX}\\S+ \\S+ ${app} \\S+ \\S+ ${SD} ?`;
  }

  const stripCaret = (p) => (p && p.startsWith('^') ? p.slice(1) : p);

  /** Build the parent decoders. */
  function buildRoots(analysis, cfg, name) {
    const fmt = W.formats[analysis.format];
    const okItems = analysis.lines.filter((it) => it.ok && !it.isHeader);
    const view = (it) => ({ pre: it.pre, body: it.payload, parsed: it.parsed, envelope: it.envelope });
    const roots = [];
    const notes = [];
    let childOffset = null;
    const anchored = analysis.format === 'csv' || analysis.format === 'template';

    // --- program_name groups
    const pnGroups = new Map();
    for (const it of okItems) {
      if (it.pre.program_name === null) continue;
      if (!pnGroups.has(it.pre.program_name)) pnGroups.set(it.pre.program_name, []);
      pnGroups.get(it.pre.program_name).push(view(it));
    }
    const pnDefs = [];
    for (const [pname, items] of pnGroups) {
      const pm = fmt.prematch(items, analysis.options, pname, analysis) || {};
      pnDefs.push({ pname, pm, count: items.length });
    }
    // Merge program names that share the same prematch into one parent.
    const byPattern = new Map();
    for (const d of pnDefs) {
      const k = (d.pm.pattern || '') + '|' + (d.pm.strategy || '');
      if (!byPattern.has(k)) byPattern.set(k, []);
      byPattern.get(k).push(d);
    }
    for (const defs of byPattern.values()) {
      const pm = defs[0].pm;
      const names = defs.map((d) => d.pname);
      const root = {
        name,
        programName: { value: names.map((n) => `^${n}$`).join('|'), type: null },
        comment: `Parent · events with a syslog header and program name ${names.map((n) => `"${n}"`).join(', ')} (${defs.reduce((a, d) => a + d.count, 0)} sample line(s))`,
      };
      if (analysis.format === 'json' && cfg.jsonMode !== 'regex') {
        root.prematch = { value: '^\\s*\\{', type: 'pcre2' };
        root.plugin = { name: 'JSON_Decoder', offset: null };
      } else if (pm.pattern) {
        root.prematch = { value: pm.pattern, type: 'pcre2' };
      }
      roots.push(root);
    }

    // --- lines without program name
    const npn = okItems.filter((it) => it.pre.program_name === null).map(view);
    if (npn.length) {
      const withEnv = npn.filter((it) => it.envelope).length > npn.length / 2;
      const pm = fmt.prematch(npn, analysis.options, null, analysis) || {};
      const root = { name, comment: '' };
      if (withEnv) {
        const env = envelopePattern(npn);
        if (analysis.format === 'json') {
          if (cfg.jsonMode === 'regex') root.prematch = { value: env, type: 'pcre2' };
          else {
            root.prematch = { value: env + '(?=\\s*\\{)', type: 'pcre2' };
            root.plugin = { name: 'JSON_Decoder', offset: 'after_prematch' };
          }
        } else if (anchored) {
          root.prematch = { value: pm.pattern ? `${env}(?=${stripCaret(pm.pattern)})` : env, type: 'pcre2' };
          childOffset = 'after_parent';
        } else if (pm.pattern) {
          root.prematch = { value: env + (pm.pattern.startsWith('^') ? stripCaret(pm.pattern) : '.*?' + pm.pattern), type: 'pcre2' };
        } else root.prematch = { value: env, type: 'pcre2' };
        root.comment = `Parent · RFC 5424 syslog events (Wazuh does not pre-decode RFC 5424), ${pm.description || analysis.formatLabel}`;
      } else if (analysis.format === 'json') {
        if (pm.strategy === 'builtin') {
          notes.push({
            level: 'info',
            text: `${npn.length} plain JSON line(s) are decoded by Wazuh's built-in "json" decoder, which is evaluated before custom decoders. Use the generated rules (<decoded_as>json</decoded_as>) for them, since a custom parent would never be reached.`,
          });
        } else if (cfg.jsonMode === 'regex') {
          root.prematch = { value: pm.pattern, type: 'pcre2' };
          root.comment = `Parent · ${pm.description}`;
        } else {
          root.prematch = { value: pm.pattern, type: 'pcre2' };
          root.plugin = { name: 'JSON_Decoder', offset: pm.plugin.offset };
          root.comment = `Parent · ${pm.description}; the JSON_Decoder plugin reads what follows the prematch`;
        }
      } else {
        if (pm.pattern) root.prematch = { value: pm.pattern, type: 'pcre2' };
        root.comment = `Parent · events without a syslog program name: ${pm.description || 'no fingerprint found'}`;
        if (!pm.pattern) {
          notes.push({ level: 'error', text: 'No stable fingerprint was found for the parent decoder: without a <prematch> it would claim every log that reaches it. Add a custom prematch in the settings.' });
        }
      }
      if (root.prematch || root.plugin) roots.push(root);
    }
    return { roots, notes, childOffset };
  }

  /** Keys that keep the same relative order in every line (greedy). */
  function stableOrder(analysis, keys) {
    const lines = analysis.lines.filter((it) => it.ok && it.parsed);
    const pos = (it, k) => it.parsed.fields.findIndex((f) => f.key === k);
    const chosen = [];
    for (const k of keys) {
      const ok = lines.every((it) => chosen.length === 0 || pos(it, chosen[chosen.length - 1]) < pos(it, k));
      if (ok) chosen.push(k);
    }
    return chosen;
  }

  function fieldComment(f) {
    const parts = [`${f.name} ← ${f.key}`];
    parts.push(W.types.info(f.type).label);
    if (f.group !== 'template') parts.push(`${Math.round(f.presence * 100)}% of samples`);
    if (f.label) parts.push(`label "${f.label}"`);
    return parts.join(' · ');
  }

  /** Build the children (siblings) for structured formats. */
  function buildChildren(analysis, cfg, name, childOffset, jsonPlugin) {
    const fmt = W.formats[analysis.format];
    const children = [];
    const notes = [];
    const selected = analysis.fields.filter((f) => f.selected && f.name && !f.isLabel);
    const mk = (regex, order, comment, offset = childOffset) => {
      const d = { name, parent: name, regex: { value: regex, type: 'pcre2', offset }, order, comment };
      children.push(d);
      return d;
    };

    if (analysis.format === 'template') {
      for (const c of analysis.template.clusters) {
        // sync selection / names from the field list
        if (c.manual) {
          for (const s of c.manual.spans) {
            const f = analysis.fields.find((x) => x.key === `t${c.id}.s${s.id}`);
            if (f) {
              s.capture = f.selected;
              s.name = f.name;
            }
          }
        }
        c.positions.forEach((p, pi) => {
          const f = analysis.fields.find((x) => x.key === `t${c.id}.${pi}`);
          if (f) {
            p.selected = f.selected;
            p.name = f.name;
          }
        });
        const { pattern, captures } = W.formats.template.clusterRegex(c, cfg.mode);
        if (!captures.length) continue;
        const sample = analysis.lines[c.lines[0]];
        mk(pattern, captures.map((x) => x.name), `Template #${c.id + 1} · ${c.lines.length} line(s) · e.g. ${U.truncate(sample ? sample.payload : '', 90)}`);
      }
      return { children, notes };
    }

    if (jsonPlugin) {
      if (selected.some((f) => f.group === 'envelope')) notes.push({ level: 'info', text: 'Envelope fields are not extracted in JSON plugin mode (the plugin would be skipped if the parent had children). Hostname and timestamp are still available from the pre-decoder.' });
      return { children, notes };
    }

    // Envelope (RFC 5424) header + structured data
    const env = selected.filter((f) => f.group === 'envelope');
    const envHead = ['syslog.timestamp', 'syslog.hostname', 'syslog.app_name', 'syslog.procid', 'syslog.msgid'];
    const headSel = env.filter((f) => envHead.includes(f.key));
    if (headSel.length) {
      const re = ENV_PREFIX + envHead.map((k) => (headSel.some((f) => f.key === k) ? '(\\S+)' : '\\S+')).join(' ') + ' ';
      const ordered = envHead.filter((k) => headSel.some((f) => f.key === k)).map((k) => headSel.find((f) => f.key === k).name);
      mk(re, ordered, 'RFC 5424 header fields', null);
    }
    for (const f of env.filter((x) => x.hint && x.hint.sdParam)) {
      mk(`${ENV_PREFIX}(?:\\S+ ){5}(?:\\[[^\\]]*\\])*?\\[[^\\]]*?\\b${U.escapeRegex(f.hint.sdParam)}="((?:[^"\\\\]|\\\\.)*)"`, [f.name], fieldComment(f), null);
    }

    // Header cells (CEF / LEEF) in one sibling
    const header = selected.filter((f) => f.group === 'header');
    if (header.length && fmt.headerRegex) {
      const h = fmt.headerRegex(header.map((f) => f.key));
      mk(h.pattern, h.keys.map((k) => header.find((f) => f.key === k).name), `${fmt.label} header: ${h.keys.join(', ')}`);
    }

    // Body fields
    let body = selected.filter((f) => f.group === 'body');
    if (cfg.strategy === 'compact' && analysis.format !== 'csv') {
      const always = body.filter((f) => f.presence === 1).sort((a, b) => analysis.fields.indexOf(a) - analysis.fields.indexOf(b));
      const chain = stableOrder(analysis, always.map((f) => f.key));
      if (chain.length >= 2) {
        let cur = [];
        let curRe = '';
        const flush = () => {
          if (!cur.length) return;
          mk(curRe, cur.map((f) => f.name), `Compact chunk · ${cur.length} always-present fields in fixed order`);
          cur = [];
          curRe = '';
        };
        for (const k of chain) {
          const f = body.find((x) => x.key === k);
          const r = fmt.fieldRegex(f, analysis.options, cfg.mode);
          const next = curRe ? `${curRe}.*?${r}` : r;
          if (next.length > MAX_REGEX && cur.length) {
            flush();
            curRe = r;
            cur = [f];
          } else {
            curRe = next;
            cur.push(f);
          }
        }
        flush();
        body = body.filter((f) => !chain.includes(f.key));
      }
    }
    for (const f of body) {
      mk(fmt.fieldRegex(f, analysis.options, cfg.mode), [f.name], fieldComment(f));
    }
    return { children, notes };
  }

  /**
   * @returns {{decoders:Array, notes:Array, xml:string, name:string}}
   */
  function generate(analysis, config) {
    const cfg = Object.assign({}, DEFAULTS, config);
    const name = U.sanitizeDecoderName(cfg.name) || 'custom-decoder';
    const { roots, notes, childOffset } = buildRoots(analysis, cfg, name);

    if (cfg.customPrematch && cfg.customPrematch.trim()) {
      const pm = cfg.customPrematch.trim();
      const compiled = W.regex.compile({ value: pm, type: 'pcre2' }, 'prematch');
      if (compiled.error) notes.push({ level: 'error', text: `Custom prematch ignored: it does not compile (${compiled.error}).` });
      else if (W.regex.backtrackRisk(pm)) notes.push({ level: 'error', text: 'Custom prematch ignored: it repeats a group that contains an unbounded quantifier, which can backtrack catastrophically. Simplify it.' });
      else for (const r of roots) if (!r.programName) r.prematch = { value: pm, type: 'pcre2' };
    }

    const jsonPlugin = analysis.format === 'json' && cfg.jsonMode !== 'regex';
    let children = [];
    if (roots.length) {
      const b = buildChildren(analysis, cfg, name, childOffset, jsonPlugin);
      children = b.children;
      notes.push(...b.notes);
    }
    if (!children.length && roots.length && !jsonPlugin) {
      notes.push({ level: 'warn', text: 'No field is selected: the decoder will only identify the source.' });
    }

    const decoders = [...roots, ...children];
    const model = { name, format: analysis.format, decoders, notes, builtinJson: analysis.format === 'json' && roots.length === 0 };
    model.xml = serialize(model, analysis, cfg);
    return model;
  }

  // ---------------------------------------------------------------- XML ---
  function serialize(model, analysis, cfg) {
    const out = [];
    const c = (t) => (cfg.comments ? out.push(`<!-- ${U.xmlComment(t)} -->`) : null);
    if (cfg.comments) {
      out.push('<!--');
      out.push(`  Decoder   : ${model.name}`);
      out.push(`  Format    : ${analysis.formatLabel} · ${analysis.stats.parsed}/${analysis.stats.lines} sample line(s) parsed`);
      out.push(`  Generated : Decoder Studio ${W.version} · ${new Date().toISOString().slice(0, 10)}`);
      out.push(`  Requires  : Wazuh 4.1+ (PCRE2 expressions)`);
      out.push(`  Install   : /var/ossec/etc/decoders/${model.name}_decoders.xml`);
      out.push(`              chown wazuh:wazuh the file, then: systemctl restart wazuh-manager`);
      out.push(`  Test      : /var/ossec/bin/wazuh-logtest`);
      out.push('-->');
      out.push('');
    }
    if (!model.decoders.length) {
      c(model.builtinJson ? `No custom decoder is needed: these events are decoded by Wazuh's built-in "json" decoder. Use the generated rules file.` : 'No decoder could be generated: see the warnings.');
      return out.join('\n') + '\n';
    }
    for (const d of model.decoders) {
      if (d.comment) c(d.comment);
      out.push(serializeDecoder(d));
      out.push('');
    }
    return out.join('\n').replace(/\n+$/, '\n');
  }

  function attrs(obj) {
    return Object.entries(obj)
      .filter(([, v]) => v)
      .map(([k, v]) => ` ${k}="${U.xmlAttr(v)}"`)
      .join('');
  }

  function serializeDecoder(d) {
    const lines = [`<decoder name="${U.xmlAttr(d.name)}">`];
    if (d.parent) lines.push(`  <parent>${d.parent}</parent>`);
    if (d.useOwnName) lines.push('  <use_own_name>true</use_own_name>');
    if (d.programName) lines.push(`  <program_name${attrs({ type: d.programName.type })}>${d.programName.value}</program_name>`);
    if (d.prematch) lines.push(`  <prematch${attrs({ type: d.prematch.type, offset: d.prematch.offset })}>${d.prematch.value}</prematch>`);
    if (d.plugin) lines.push(`  <plugin_decoder${attrs({ offset: d.plugin.offset })}>${d.plugin.name}</plugin_decoder>`);
    if (d.regex) lines.push(`  <regex${attrs({ type: d.regex.type, offset: d.regex.offset })}>${d.regex.value}</regex>`);
    if (d.order && d.order.length) lines.push(`  <order>${d.order.join(', ')}</order>`);
    lines.push('</decoder>');
    return lines.join('\n');
  }

  W.generate = generate;
  W.generator = { generate, serialize, serializeDecoder, DEFAULTS, MAX_REGEX };
});
