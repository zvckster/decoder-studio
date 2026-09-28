/*
 * Decoding simulator: a port of analysisd's decoder loading
 * (decoders_list.c: OS_AddOSDecoder) and evaluation (decoder.c: DecodeEvent),
 * so generated or hand-written decoders can be tested in the browser with
 * wazuh-logtest-like output.
 *
 * Emulated faithfully:
 *   - two root lists: with / without <program_name>; an event carrying a
 *     program name is only matched against the first list
 *   - roots are tried in file order; the first match wins
 *   - children attach to every root with the parent's name
 *   - child selection: first child whose prematch matches (or that has no
 *     prematch); sibling chains (get_next) run every regex, a failing
 *     sibling is skipped, a failing non-sibling regex stops decoding
 *   - offsets after_parent / after_prematch / after_regex and the
 *     "pointer after last matched char" arithmetic
 *   - JSON_Decoder offset taken from lf->decoder_info (root or prematch child)
 *   - optional built-in "json" root, loaded before custom decoders
 *   - load-time errors: sibling with prematch, parent not found...
 */
WDG_MODULE(function (W) {
  'use strict';

  const STATIC = { srcuser: 'srcuser', dstuser: 'dstuser', user: 'dstuser', srcip: 'srcip', dstip: 'dstip', srcport: 'srcport', dstport: 'dstport', protocol: 'protocol', action: 'action', id: 'id', url: 'url', data: 'data', extra_data: 'extra_data', status: 'status', system_name: 'system_name' };
  // JSON_Decoder's own static keys (plugins/json_decoder.c fillData): note
  // "systemname" and no "user" alias.
  const JSON_STATIC = { srcip: 'srcip', dstip: 'dstip', srcport: 'srcport', dstport: 'dstport', protocol: 'protocol', action: 'action', srcuser: 'srcuser', dstuser: 'dstuser', id: 'id', status: 'status', url: 'url', data: 'data', extra_data: 'extra_data', systemname: 'system_name' };
  const BUILTIN_JSON = { name: 'json', prematch: { value: '^{\\s*"', type: null }, plugin: { name: 'JSON_Decoder', offset: null }, builtin: true };

  /** Load a decoder model into Wazuh's two root lists. */
  function load(decoders, opts) {
    const o = Object.assign({ builtinJson: true }, opts);
    const errors = [];
    const pn = [];
    const npn = [];
    const all = o.builtinJson ? [BUILTIN_JSON, ...decoders] : decoders.slice();

    for (const d of all) {
      const info = compileDecoder(d, errors);
      if (!d.parent) {
        const node = { d, info, children: [] };
        (d.programName ? pn : npn).push(node);
        continue;
      }
      let added = false;
      for (const root of [...pn, ...npn]) {
        if (root.d.name !== d.parent) continue;
        const list = root.children;
        const child = { d, info, get_next: false };
        let ok = true;
        for (const ex of list) {
          if (ex.d.name !== d.name) continue;
          if (d.prematch) {
            errors.push(`Decoder "${d.name}": siblings (children sharing a name) cannot have a <prematch>, wazuh-analysisd refuses to start.`);
            ok = false;
            break;
          }
          if ((ex.d.regex || ex.d.plugin) && (d.regex || d.plugin)) ex.get_next = true;
          else {
            errors.push(`Decoder "${d.name}": duplicated child without regex/plugin.`);
            ok = false;
            break;
          }
        }
        if (ok && d.regex && d.regex.offset === 'after_regex' && !list.some((ex) => ex.d.name === d.name && (ex.d.regex || ex.d.prematch))) {
          errors.push(`Decoder "${d.name}": offset="after_regex" requires a previous sibling with a regex.`);
          ok = false;
        }
        if (ok) list.push(child);
        added = true;
      }
      if (!added) errors.push(`Decoder "${d.name}": parent "${d.parent}" not found (only one level of parent/child is supported and the parent must be defined first).`);
    }
    return { pn, npn, errors: [...new Set(errors)] };
  }

  function compileDecoder(d, errors) {
    const info = {};
    const comp = (expr, role) => {
      if (!expr) return null;
      const c = W.regex.compile(expr, role);
      if (c.error) errors.push(`Decoder "${d.name}": invalid ${role} ${c.type} expression (${c.error})`);
      return c;
    };
    info.programName = comp(d.programName, 'program_name');
    info.prematch = comp(d.prematch, 'prematch');
    info.regex = comp(d.regex, 'regex');
    if (d.prematch && (d.prematch.type || 'osregex') === 'osmatch') errors.push(`Decoder "${d.name}": <prematch> only supports osregex and pcre2.`);
    return info;
  }

  // Pointer helpers. A pointer is an index into lf->log, null for NULL.
  const sub = (log, p) => (p === null ? null : p < 0 ? '' : log.slice(p));
  // Wazuh returns the last matched char and then advances one → end of match.
  const after = (base, r) => (r.end > 0 || base > 0 ? base + r.end : -1);

  function flattenJson(obj, prefix, out) {
    for (const [k, v] of Object.entries(obj)) {
      const key = prefix ? `${prefix}.${k}` : k;
      if (v !== null && typeof v === 'object' && !Array.isArray(v)) flattenJson(v, key, out);
      else out.push({ name: key, value: v === null ? 'null' : Array.isArray(v) ? JSON.stringify(v) : String(v), static: false });
    }
    return out;
  }

  function runJson(input) {
    if (input === null) return null;
    const t = input.replace(/^\s+/, '');
    let obj;
    try {
      obj = JSON.parse(t);
    } catch (e) {
      const j = t.lastIndexOf('}');
      try {
        obj = JSON.parse(t.slice(0, j + 1));
      } catch (e2) {
        return null;
      }
    }
    if (!obj || typeof obj !== 'object') return null;
    return flattenJson(obj, '', []);
  }

  /** Decode one raw event. */
  function decodeLine(loaded, raw, opts) {
    const o = Object.assign({ stripPri: true }, opts);
    const pre = W.predecode(raw, { stripPri: o.stripPri });
    const log = pre.log;
    const res = { raw, pre, decoder: null, parent: null, fields: [], trace: [], siblings: { ok: 0, failed: 0 }, builtin: false };
    const list = pre.program_name !== null ? loaded.pn : loaded.npn;
    res.list = pre.program_name !== null ? 'program_name' : 'prematch';

    const setField = (name, value, table = STATIC) => {
      const s = table[name];
      const fname = s || name;
      const ex = res.fields.find((f) => f.name === fname);
      if (ex) {
        ex.value = value;
        ex.dup = true;
      } else res.fields.push({ name: fname, value, static: !!s });
    };

    for (const node of list) {
      const d = node.d;
      let pmatch = null;
      if (pre.program_name !== null) {
        if (!node.info.programName || !node.info.programName.exec(pre.program_name)) continue;
        pmatch = 0;
      }
      if (node.info.prematch) {
        const r = node.info.prematch.exec(log);
        if (!r) continue;
        pmatch = after(0, r);
      }
      // (a root without program_name and prematch matches every event, as in Wazuh)

      res.decoder = d.name;
      res.parent = d.name;
      res.builtin = !!d.builtin;
      res.trace.push(`parent "${d.name}" matched${d.programName ? ' (program_name)' : ''}${d.prematch ? ' (prematch)' : ''}`);
      let decoderInfo = d;
      let logAfterParent = null;
      let logAfterPrematch = pmatch;
      let cmatch = null;

      // --- choose the child
      let chain;
      let idx = 0;
      if (!node.children.length) {
        chain = [{ d, info: node.info, get_next: false }];
      } else {
        chain = node.children;
        let found = false;
        while (idx < chain.length) {
          const c = chain[idx];
          if (c.info.prematch) {
            const base = c.d.prematch.offset === 'after_parent' ? pmatch : 0;
            const r = c.info.prematch.exec(sub(log, base) ?? '');
            if (sub(log, base) !== null && r) {
              cmatch = after(base < 0 ? 0 : base, r);
              decoderInfo = c.d;
              logAfterParent = pmatch;
              logAfterPrematch = cmatch;
              found = true;
              res.trace.push(`child "${c.d.name}" selected by its prematch`);
              break;
            }
          } else {
            cmatch = pmatch;
            found = true;
            break;
          }
          if (c.get_next) {
            do idx++;
            while (idx < chain.length && chain[idx].get_next);
            if (idx >= chain.length) return finish(res);
            idx++;
          } else idx++;
        }
        if (!found) {
          res.trace.push('no child decoder matched');
          return finish(res);
        }
      }

      // --- run the regex / plugin chain
      let regexPrev = null;
      while (idx < chain.length) {
        const c = chain[idx];
        const cd = c.d;
        if (cd.plugin) {
          const off = decoderInfo.plugin ? decoderInfo.plugin.offset : null;
          const input = off === 'after_parent' ? sub(log, logAfterParent) : off === 'after_prematch' ? sub(log, logAfterPrematch) : log;
          const out = runJson(cd.plugin.name === 'JSON_Decoder' ? input : null);
          if (cd.plugin.name !== 'JSON_Decoder') res.trace.push(`plugin ${cd.plugin.name} is not simulated`);
          else if (!out) res.trace.push('JSON_Decoder: input is not valid JSON');
          else {
            out.forEach((f) => setField(f.name, f.value, JSON_STATIC));
            res.trace.push(`JSON_Decoder extracted ${out.length} field(s)`);
          }
        } else if (cd.regex) {
          let base = 0;
          const off = cd.regex.offset;
          if (off === 'after_parent') base = pmatch;
          else if (off === 'after_prematch') base = cmatch;
          else if (off === 'after_regex') base = regexPrev === null ? cmatch : regexPrev;
          const text = sub(log, base);
          const r = text === null ? null : c.info.regex.exec(text);
          if (!r) {
            res.siblings.failed++;
            res.trace.push(`regex of "${cd.name}" did not match${cd.order ? ` (${cd.order.join(', ')})` : ''}`);
            if (c.get_next) {
              idx++;
              continue;
            }
            return finish(res);
          }
          res.siblings.ok++;
          regexPrev = after(base < 0 ? 0 : base, r);
          const order = cd.order || [];
          r.groups.forEach((g, gi) => {
            if (order[gi]) setField(order[gi], g);
          });
        } else {
          return finish(res);
        }
        if (c.get_next) idx++;
        else return finish(res);
      }
      return finish(res);
    }
    res.trace.push('No decoder matched.');
    return finish(res);
  }

  function finish(res) {
    return res;
  }

  /** Simulate many lines. */
  function simulate(decoders, lines, opts) {
    const loaded = load(decoders, opts);
    const results = lines.map((raw) => decodeLine(loaded, raw, opts));
    return { errors: loaded.errors, results };
  }

  /** wazuh-logtest-like text for one result. */
  function logtest(res) {
    const out = [];
    out.push('**Phase 1: Completed pre-decoding.');
    out.push(`\tfull event: '${res.raw}'`);
    if (res.pre.timestamp) out.push(`\ttimestamp: '${res.pre.timestamp}'`);
    if (res.pre.hostname) out.push(`\thostname: '${res.pre.hostname}'`);
    if (res.pre.program_name !== null) out.push(`\tprogram_name: '${res.pre.program_name}'`);
    out.push('');
    if (!res.decoder) {
      out.push('**Phase 2: Completed decoding.');
      out.push('\tNo decoder matched.');
      return out.join('\n');
    }
    out.push('**Phase 2: Completed decoding.');
    out.push(`\tname: '${res.decoder}'`);
    if (!res.builtin && res.fields.length) out.push(`\tparent: '${res.parent}'`);
    for (const f of res.fields) out.push(`\t${f.name}: '${f.value}'`);
    return out.join('\n');
  }

  W.simulator = { load, decodeLine, simulate, logtest, STATIC, JSON_STATIC };
});
