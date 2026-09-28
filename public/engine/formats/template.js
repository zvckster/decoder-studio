/*
 * Free-form / unstructured logs (sshd-like messages, Cisco ASA, custom apps,
 * Apache/Nginx access logs...).
 *
 * 1. Tokenize: quoted strings, [bracketed] groups, words (IPs, IP:port, paths
 *    and times stay whole), single punctuation characters, whitespace.
 * 2. Cluster lines into event templates (same token count, ≥50% identical
 *    constant tokens), a lightweight take on the Drain log-parsing algorithm.
 * 3. Positions whose value differs across a cluster are variables; in small
 *    clusters, values that obviously vary (IPs, numbers, hashes, times...)
 *    are promoted to variables too.
 * 4. Variables are named from their context ("from 10.0.0.1" → srcip,
 *    "user admin" → user, "port 22" → srcport/dstport).
 * Every cluster becomes one anchored sibling regex; the analyst can toggle any
 * token between literal / variable / rest-of-line and rename it.
 */
WDG_MODULE(function (W) {
  'use strict';
  const U = W.util;
  const T = W.types;

  const TOKEN = /"(?:[^"\\]|\\.)*"|\[[^\[\]]{0,256}\]|\s+|[A-Za-z0-9_.:@\/\\%+~#$-]+|[^\sA-Za-z0-9]/g;
  const VARIABLE_TYPES = new Set(['ipv4', 'ipv6', 'ipport', 'mac', 'uuid', 'sha256', 'sha1', 'md5', 'hash', 'epoch', 'integer', 'number', 'hex', 'iso8601', 'date', 'time', 'email', 'url', 'unixpath', 'winpath']);
  const NO_SPLIT = new Set(['time', 'ipv6', 'mac', 'iso8601', 'url', 'unixpath', 'winpath', 'date', 'uuid', 'email']);
  const DIRECTION = { from: 'src', to: 'dst', by: 'src', src: 'src', dst: 'dst', source: 'src', destination: 'dst', client: 'src', server: 'dst', remote: 'src', local: 'dst' };
  const KEYWORDS = new Set(['user', 'username', 'account', 'login', 'host', 'hostname', 'file', 'filename', 'path', 'uid', 'gid', 'pid', 'port', 'ip', 'domain', 'group', 'role', 'policy', 'rule', 'client', 'server', 'src', 'dst']);
  const REQUEST_LINE = /^"([A-Z]{3,10}) (\S+) ([A-Z]+\/[\d.]+)"$/;
  const STOP_WORDS = new Set(['the', 'a', 'an', 'of', 'on', 'in', 'at', 'is', 'was', 'for', 'with', 'and', 'or', 'as']);

  function tokenize(body) {
    const toks = [];
    let ws = false;
    TOKEN.lastIndex = 0;
    let m;
    while ((m = TOKEN.exec(body))) {
      const v = m[0];
      if (/^\s+$/.test(v)) {
        ws = true;
        continue;
      }
      let k = 'w';
      if (v[0] === '"' && v.length > 1) k = 'q';
      else if (v[0] === '[' && v.length > 1) k = 'b';
      else if (v.length === 1 && /[^A-Za-z0-9]/.test(v)) k = 'p';
      toks.push({ k, v, ws, start: m.index, end: m.index + v.length });
      ws = false;
    }
    return toks;
  }

  const inner = (tok) => (tok.k === 'q' || tok.k === 'b' ? tok.v.slice(1, -1) : tok.v);

  /** Drain-style masking: values that obviously vary never break a template. */
  const maskable = (tok) => tok.k === 'q' || tok.k === 'b' || (tok.k === 'w' && VARIABLE_TYPES.has(T.classify(tok.v)));

  function similarity(rep, toks) {
    let same = 0;
    for (let i = 0; i < rep.length; i++) {
      if (rep[i].k !== toks[i].k) {
        // a word and a lone punctuation ("alice" vs "-") may share a slot
        if (!/[wp]/.test(rep[i].k) || !/[wp]/.test(toks[i].k)) return 0;
        continue;
      }
      if (!rep[i].isConst || rep[i].v === toks[i].v || (maskable(rep[i]) && maskable(toks[i]))) same++;
    }
    return rep.length ? same / rep.length : 1;
  }

  function cluster(lines) {
    const byLen = new Map();
    lines.forEach((ln, idx) => {
      const toks = tokenize(ln);
      if (!byLen.has(toks.length)) byLen.set(toks.length, []);
      byLen.get(toks.length).push({ idx, toks });
    });
    const clusters = [];
    for (const group of byLen.values()) {
      const local = [];
      for (const { idx, toks } of group) {
        let best = null;
        let bestSim = 0;
        for (const c of local) {
          const s = similarity(c.positions, toks);
          if (s >= 0.6 && s > bestSim) {
            best = c;
            bestSim = s;
          }
        }
        if (!best) {
          best = { lines: [], positions: toks.map((t) => ({ k: t.k, v: t.v, isConst: true, values: [], ws: t.ws })) };
          local.push(best);
        }
        best.lines.push(idx);
        toks.forEach((t, i) => {
          const p = best.positions[i];
          p.values.push(t.v);
          if (p.v !== t.v) p.isConst = false;
          if (p.k !== t.k) p.k = 'w';
          if (p.ws !== t.ws) p.ws = 'mixed';
        });
      }
      clusters.push(...local);
    }
    clusters.sort((a, b) => b.lines.length - a.lines.length);
    return clusters.map(finalize);
  }

  /**
   * HTTP request line ("GET /index.html HTTP/1.1") → quote, method, path,
   * version, quote. Each part becomes its own field.
   */
  function splitRequest(p) {
    const parts = p.values.map((v) => REQUEST_LINE.exec(v));
    const col = (i) => parts.map((m) => m[i]);
    const sub = (k, v, values, ws, role) => ({ k, v, values, ws, isConst: values.every((x) => x === values[0]), sub: role });
    return [
      sub('p', '"', p.values.map(() => '"'), p.ws, null),
      sub('w', col(1)[0], col(1), false, 'method'),
      sub('w', col(2)[0], col(2), true, 'path'),
      sub('w', col(3)[0], col(3), true, 'version'),
      sub('p', '"', p.values.map(() => '"'), false, null),
    ];
  }

  /** Split varying words like "outside:10.0.0.1/443" into sub-positions. */
  function splitWords(positions) {
    const out = [];
    for (const p of positions) {
      if (p.k === 'q' && p.values.every((v) => REQUEST_LINE.test(v))) {
        out.push(...splitRequest(p));
        continue;
      }
      if (p.isConst || p.k !== 'w' || NO_SPLIT.has(T.inferType(p.values))) {
        out.push(p);
        continue;
      }
      const parts = p.values.map((v) => v.split(/([:\/@=])/));
      const n = parts[0].length;
      const sepsSame = parts.every((ps) => ps.length === n && ps.every((x, i) => (i % 2 === 1 ? x === parts[0][i] : true)));
      if (n < 3 || !sepsSame || parts.some((ps) => ps.some((x, i) => i % 2 === 0 && x === ''))) {
        out.push(p);
        continue;
      }
      for (let i = 0; i < n; i++) {
        const vals = parts.map((ps) => ps[i]);
        out.push({ k: i % 2 ? 'p' : 'w', v: vals[0], isConst: vals.every((x) => x === vals[0]), values: vals, ws: i === 0 ? p.ws : false });
      }
    }
    return out;
  }

  function finalize(c) {
    let positions = splitWords(c.positions);
    const small = c.lines.length < 3;
    for (const p of positions) {
      const t = T.inferType(p.values.map((v) => inner({ k: p.k, v })));
      p.type = t;
      if (p.isConst && small && (VARIABLE_TYPES.has(t) || (p.k === 'q' && /\d/.test(p.v)) || (p.k === 'b' && /\d/.test(p.v)))) p.isConst = false;
      if (p.sub) p.isConst = false; // request-line parts are always fields
      p.role = p.isConst ? 'const' : 'var';
      p.selected = p.role === 'var';
    }
    if (c.lines.length === 1) {
      positions.forEach((p, i) => {
        const prev = immediatePrev(positions, i);
        const self = p.v.toLowerCase();
        if (p.role === 'const' && p.k === 'w' && prev && KEYWORDS.has(prev.replace(/[:=]$/, '')) && !KEYWORDS.has(self) && !STOP_WORDS.has(self)) {
          p.isConst = false;
          p.role = 'var';
          p.selected = true;
        }
      });
    }
    nameVariables(positions);
    return { lines: c.lines, positions };
  }

  function prevWord(positions, i) {
    for (let j = i - 1; j >= 0 && j >= i - 3; j--) {
      const p = positions[j];
      if (p.role !== 'const') return null;
      if (p.k === 'p') continue;
      const w = inner(p).toLowerCase().replace(/[:=]+$/, '');
      if (/^[a-z][a-z_-]{0,24}$/.test(w) && !STOP_WORDS.has(w)) return w;
      if (STOP_WORDS.has(w)) continue;
      return null;
    }
    return null;
  }

  function immediatePrev(positions, i) {
    const p = positions[i - 1];
    return p && p.role === 'const' && p.k === 'w' ? p.v.toLowerCase() : null;
  }

  function nameVariables(positions) {
    const used = new Set();
    let dir = null;
    let sawRequest = false;
    let ints = 0;
    positions.forEach((p, i) => {
      if (p.role !== 'var') return;
      const w = prevWord(positions, i);
      const after = immediatePrev(positions, i);
      const d = w && DIRECTION[w];
      if (d) dir = d;
      let name = null;
      const isIp = ['ipv4', 'ipv6', 'ip'].includes(p.type);
      if (isIp && d) name = `${d}ip`;
      else if (isIp && w && /ip|addr|host/.test(w)) name = dir ? `${dir}ip` : 'srcip';
      else if (w === 'port' && p.type === 'integer') name = `${dir || 'dst'}port`;
      else if (w && ['user', 'username', 'account', 'login'].includes(w)) name = dir === 'src' ? 'srcuser' : 'dstuser';
      else if (after === 'for' && !isIp && ['word', 'token', 'email', 'domainuser'].includes(p.type)) name = 'dstuser';
      else if (w && !d) name = W.util.sanitizeFieldName(w);
      if (p.sub) {
        name = { method: 'http_method', path: 'url', version: 'http_version' }[p.sub];
        sawRequest = true;
      } else if (!name && p.type === 'httprequest') {
        name = 'request';
        sawRequest = true;
      } else if (!name && sawRequest && p.type === 'integer') {
        ints++;
        if (ints === 1 && p.values.every((v) => /^[1-5]\d\d$/.test(v))) name = 'http_status';
        else if (ints <= 2) name = 'bytes';
      } else if (!name && sawRequest && p.k === 'q' && ['url', 'empty', 'token'].includes(p.type)) {
        name = 'referrer';
      } else if (!name && sawRequest && ['number', 'integer'].includes(p.type) && p.values.some((v) => v.includes('.'))) {
        name = 'response_time';
      } else if (!name && !sawRequest && p.k !== 'q' && p.k !== 'b') {
        // access-log user column: the token right before the [date]
        const next = positions[i + 1];
        if (next && next.k === 'b' && next.type === 'httpdate' && ['word', 'token', 'empty', 'email', 'domainuser'].includes(p.type)) name = 'srcuser';
      }
      if (!name) {
        const byType = { ipv4: 'ip', ipv6: 'ip', ip: 'ip', ipport: 'endpoint', integer: 'number', number: 'number', iso8601: 'timestamp', syslogtime: 'timestamp', time: 'time', date: 'date', mac: 'mac', email: 'email', url: 'url', unixpath: 'path', winpath: 'path', uuid: 'uuid', md5: 'hash', sha1: 'hash', sha256: 'hash', hash: 'hash', fqdn: 'hostname', httpdate: 'timestamp', useragent: 'user_agent', filename: 'file_name', domainuser: 'user' };
        name = byType[p.type] || (isIp ? 'ip' : 'value');
        if (name === 'ip') name = dir ? `${dir}ip` : used.has('srcip') ? 'dstip' : 'srcip';
      }
      let cand = name;
      let n = 2;
      while (used.has(cand)) cand = `${name}_${n++}`;
      used.add(cand);
      p.name = cand;
    });
  }

  function escapeTokenLiteral(p) {
    return U.escapeRegex(p.v);
  }

  /**
   * Build the anchored regex of one cluster.
   * @returns {{pattern:string, captures:Array<{pos:number,name:string}>}}
   */
  function clusterRegex(cluster, mode) {
    if (cluster.manual) return manualRegex(cluster.manual.line, cluster.manual.spans, mode);
    const pos = cluster.positions;
    let re = '^';
    const captures = [];
    for (let i = 0; i < pos.length; i++) {
      const p = pos[i];
      if (i > 0 && p.ws) re += p.ws === true ? '\\s+' : '\\s*';
      if (p.role === 'tail') {
        re += p.selected ? '(.*)' : '.*';
        if (p.selected) captures.push({ pos: i, name: p.name });
        return { pattern: re, captures };
      }
      if (p.role === 'const') {
        re += escapeTokenLiteral(p);
        continue;
      }
      const next = pos[i + 1];
      let body;
      if (p.k === 'q') body = null;
      else if (p.k === 'b') body = null;
      else if (p.k === 'p') body = '\\S';
      else {
        const typed = mode === 'strict' && W.types.info(p.type).pattern;
        const stop = next && !next.ws && next.role === 'const' ? next.v[0] : null;
        body = typed || (stop ? `[^\\s${U.escapeClassChar(stop)}]+` : '\\S+');
      }
      const wrap = (b) => (p.selected ? `(${b})` : b.startsWith('(?:') ? b : `(?:${b})`);
      if (p.k === 'q') re += '"' + wrap('(?:[^"\\\\]|\\\\.)*') + '"';
      else if (p.k === 'b') re += '\\[' + wrap('[^\\]]*') + '\\]';
      else re += wrap(body);
      if (p.selected) captures.push({ pos: i, name: p.name });
    }
    re += '\\s*$';
    return { pattern: re, captures };
  }

  // ------------------------------------------------------------------
  // Pattern builder: fields as character ranges of a sample line
  // (regex101-style). A span is {start, end, name, capture, type}.
  // capture=false marks a wildcard: the text varies but is not extracted.
  // ------------------------------------------------------------------

  const SEGMENT = /"(?:[^"\\]|\\.)*"|\[[^\[\]]{0,256}\]|\s+|[A-Za-z0-9_.:@\/\\%+~#$-]+|[^\sA-Za-z0-9]/g;

  /** Literal text between two fields: constants stay literal, values that obviously vary become wildcards. */
  function generalize(text) {
    let out = '';
    const pieces = [];
    SEGMENT.lastIndex = 0;
    let m;
    while ((m = SEGMENT.exec(text))) pieces.push(m[0]);
    pieces.forEach((v, i) => {
      if (/^\s+$/.test(v)) {
        out += '\\s+';
        return;
      }
      const next = pieces[i + 1];
      if (v.length > 1 && v[0] === '"' && /\d/.test(v)) out += '"(?:[^"\\\\]|\\\\.)*"';
      else if (v.length > 1 && v[0] === '[' && /\d/.test(v)) out += '\\[[^\\]]*\\]';
      else if ((/^[A-Za-z0-9]/.test(v) && VARIABLE_TYPES.has(T.classify(v))) || (v.length > 1 && (v.match(/\d/g) || []).length >= 2)) {
        const stop = next && !/^\s/.test(next) ? next[0] : null;
        out += stop ? `[^\\s${U.escapeClassChar(stop)}]+` : '\\S+';
      } else out += U.escapeRegex(v);
    });
    return out;
  }

  /** Capture body for one span, chosen from the character that follows it. */
  function spanBody(line, s, mode) {
    const value = line.slice(s.start, s.end);
    const next = line[s.end];
    const typed = mode === 'strict' && s.type && W.types.info(s.type).pattern;
    if (typed) return typed;
    if (next === undefined) return '.*';
    const hasWs = /\s/.test(value);
    if (/\s/.test(next)) return hasWs ? '.+?' : '\\S+';
    if (/[A-Za-z0-9]/.test(next) || hasWs || value.includes(next)) return '.+?';
    return `[^${U.escapeClassChar(next)}]*`;
  }

  /** Regex for a line where fields are character spans. */
  function manualRegex(line, spans, mode) {
    const sorted = spans.slice().sort((a, b) => a.start - b.start);
    let re = '^';
    let cur = 0;
    const captures = [];
    sorted.forEach((s, i) => {
      re += generalize(line.slice(cur, s.start));
      const body = spanBody(line, s, mode);
      if (s.capture) {
        re += `(${body})`;
        captures.push({ span: spans.indexOf(s), name: s.name });
      } else re += body.startsWith('(?:') ? body : `(?:${body})`;
      cur = s.end;
    });
    re += generalize(line.slice(cur));
    return { pattern: re, captures };
  }

  function jsRegex(pattern) {
    const t = W.regex.pcreToJs(pattern);
    return new RegExp(t.source, t.flags + 'd');
  }

  /** Initial spans of a suggested template, located in one of its lines. */
  function spansFromCluster(cluster, line) {
    if (cluster.manual) return cluster.manual.spans.map((s) => Object.assign({}, s));
    const all = { positions: cluster.positions.map((p) => Object.assign({}, p, { selected: p.role === 'var' || p.role === 'tail' })) };
    const { pattern, captures } = clusterRegex(all, 'robust');
    let m;
    try {
      m = jsRegex(pattern).exec(line);
    } catch (e) {
      m = null;
    }
    if (!m || !m.indices) return [];
    return captures
      .map((c, i) => {
        const ix = m.indices[i + 1];
        if (!ix) return null;
        const p = cluster.positions[c.pos];
        return { start: ix[0], end: ix[1], name: p.name, capture: !!p.selected, type: p.type, pos: c.pos };
      })
      .filter((s) => s && s.end >= s.start);
  }

  let spanSeq = 0;
  const newSpanId = () => ++spanSeq;

  /** Switch a template to the character-span model, keeping its fields. */
  function toManual(cluster, line) {
    if (!cluster.manual) {
      cluster.manual = { line, spans: spansFromCluster(cluster, line).map((s) => Object.assign(s, { id: newSpanId() })) };
    }
    return cluster.manual;
  }

  /**
   * Add a span. Spans it overlaps are carved: the parts left over on either
   * side stay as wildcards (they still vary), so selecting "07" inside a
   * timestamp keeps the rest of the timestamp flexible.
   */
  function addSpan(manual, span) {
    if (span.end <= span.start) return manual;
    const out = [];
    for (const s of manual.spans) {
      if (s.end <= span.start || s.start >= span.end) {
        out.push(s);
        continue;
      }
      if (s.start < span.start) out.push({ id: newSpanId(), start: s.start, end: span.start, name: `${s.name}_head`, capture: false, type: null });
      if (s.end > span.end) out.push({ id: newSpanId(), start: span.end, end: s.end, name: `${s.name}_tail`, capture: false, type: null });
    }
    out.push(Object.assign({ id: newSpanId(), capture: true }, span));
    manual.spans = out.sort((a, b) => a.start - b.start);
    return manual;
  }

  function removeSpan(manual, id) {
    manual.spans = manual.spans.filter((s) => s.id !== id);
    return manual;
  }

  /** Value of every span (captured or wildcard) on one line: Map id → value, or null. */
  function spanValues(cluster, line) {
    if (!cluster.manual) return null;
    const spans = cluster.manual.spans.slice().sort((a, b) => a.start - b.start);
    const all = spans.map((s) => Object.assign({}, s, { capture: true }));
    let m;
    try {
      m = jsRegex(manualRegex(cluster.manual.line, all, 'robust').pattern).exec(line);
    } catch (e) {
      return null;
    }
    if (!m) return null;
    const out = new Map();
    spans.forEach((s, i) => out.set(s.id, m[i + 1] === undefined ? '' : m[i + 1]));
    return out;
  }

  /** Values captured by a template (any model) on one line, or null if it does not match. */
  function extract(cluster, line) {
    const { pattern } = clusterRegex(cluster, 'robust');
    let m;
    try {
      m = jsRegex(pattern).exec(line);
    } catch (e) {
      return null;
    }
    return m ? { values: m.slice(1), indices: m.indices.slice(1) } : null;
  }

  /** Suggested name for a new span, from its value and the text before it. */
  function suggestSpanName(line, start, end, used) {
    const value = line.slice(start, end);
    const type = T.classify(value);
    const before = line.slice(Math.max(0, start - 24), start).toLowerCase();
    const word = (/([a-z][a-z_-]{1,20})[\s:=]*["\[(]?$/.exec(before) || [])[1];
    let name = null;
    if (word && DIRECTION[word] && ['ipv4', 'ipv6'].includes(type)) name = `${DIRECTION[word]}ip`;
    else if (word && KEYWORDS.has(word)) name = word === 'port' ? 'dstport' : word;
    else if (REQUEST_LINE.test(`"${value}"`)) name = 'request';
    else {
      const byType = { ipv4: 'srcip', ipv6: 'srcip', ipport: 'endpoint', integer: 'number', number: 'number', iso8601: 'timestamp', syslogtime: 'timestamp', httpdate: 'timestamp', time: 'time', date: 'date', mac: 'mac', email: 'email', url: 'url', unixpath: 'path', winpath: 'path', uuid: 'uuid', md5: 'hash', sha1: 'hash', sha256: 'hash', fqdn: 'hostname', useragent: 'user_agent', filename: 'file_name', httprequest: 'request' };
      name = byType[type] || (word && !STOP_WORDS.has(word) ? word : 'field');
    }
    let cand = name;
    let n = 2;
    while (used && used.has(cand)) cand = `${name}_${n++}`;
    return { name: cand, type };
  }

  const template = {
    id: 'template',
    label: 'Free-form',
    long: 'Unstructured text: automatic template mining, click-to-edit fields',
    tokenize,
    cluster,
    clusterRegex,
    inner,
    manualRegex,
    spansFromCluster,
    toManual,
    newSpanId,
    addSpan,
    removeSpan,
    spanValues,
    jsRegex,
    extract,
    suggestSpanName,

    detect() {
      return 0.2;
    },

    configure() {
      return {};
    },

    parse(body) {
      return { fields: [], meta: {} };
    },

    prematch(items, options, programName, analysis) {
      const bodies = items.map((it) => it.body);
      if (programName && !['CEF', 'LEEF'].includes(programName)) return { pattern: null, description: `program_name ${programName}` };
      const prefix = W.formatsCommon.literalPrefix(bodies);
      if (prefix.replace(/\W/g, '').length >= 3) return { pattern: '^' + U.escapeRegex(prefix), description: `lines starting with "${U.truncate(prefix, 40)}"` };
      // Alternation of each template's leading literal tokens; when a
      // template starts with a variable, use its structural skeleton.
      const clusters = (analysis && analysis.template && analysis.template.clusters) || [];
      const heads = [];
      for (const c of clusters) {
        const h = skeleton(c);
        if (!h) return { pattern: null, description: 'none' };
        heads.push(h);
      }
      const uniq = U.uniq(heads);
      if (!uniq.length || uniq.length > 8) return { pattern: null, description: 'none' };
      return { pattern: uniq.length === 1 ? '^' + uniq[0] : `^(?:${uniq.join('|')})`, description: `${uniq.length} event template(s)` };
    },
  };

  /** Non-capturing regex of a template's first tokens, with ≥ 2 literals. */
  function skeleton(c) {
    if (c.manual) {
      const all = c.manual.spans.map((s) => Object.assign({}, s, { capture: false }));
      return manualRegex(c.manual.line, all, 'robust').pattern.replace(/^\^/, '');
    }
    const copy = { positions: c.positions.map((p) => Object.assign({}, p, { selected: false })) };
    let literals = 0;
    let n = 0;
    while (n < copy.positions.length && (literals < 3 || n < 4) && n < 10) {
      const p = copy.positions[n];
      if (p.role === 'tail') break;
      if (p.role === 'const') literals += p.k === 'p' ? 0.5 : 1;
      else if (p.k === 'q' || p.k === 'b') literals += 0.5; // quotes / brackets are structure
      n++;
    }
    if (literals < 2) return null;
    copy.positions = copy.positions.slice(0, n);
    const re = clusterRegex(copy, 'robust').pattern;
    // drop the leading ^ (added by the caller) and the end-of-line anchor:
    // the skeleton only covers the first tokens of the line.
    const tail = '\\s*$';
    let out = re.replace(/^\^/, '');
    if (out.endsWith(tail)) out = out.slice(0, -tail.length);
    return out;
  }

  W.formats.template = template;
});
