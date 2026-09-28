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
      toks.push({ k, v, ws });
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

  /** Split varying words like "outside:10.0.0.1/443" into sub-positions. */
  function splitWords(positions) {
    const out = [];
    for (const p of positions) {
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
      if (!name && p.type === 'httprequest') {
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

  const template = {
    id: 'template',
    label: 'Free-form',
    long: 'Unstructured text: automatic template mining, click-to-edit fields',
    tokenize,
    cluster,
    clusterRegex,
    inner,

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
