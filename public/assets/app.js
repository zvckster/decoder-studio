/*
 * Decoder Studio for Wazuh: UI controller.
 * Pure DOM, no framework. A four-step flow (paste, review, verify, deploy)
 * with a bottom stepper. Every edit regenerates the decoder and re-runs the
 * Wazuh emulation over all sample lines (a few ms for hundreds of lines).
 */
(function () {
  'use strict';
  const W = window.WDG;
  const U = W.util;
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  const state = {
    analysis: null,
    model: null,
    rules: null,
    verdict: null,
    custom: null, // { decoders, issues, results }
    step: 1,
    line: 0,
    sampleName: '',
    customMap: {},
  };

  // ------------------------------------------------------------ helpers ---
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const pct = (x) => `${Math.round(x * 100)}%`;
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many || one + 's'}`;
  const debounce = (fn, ms) => {
    let t;
    return (...a) => {
      clearTimeout(t);
      t = setTimeout(() => fn(...a), ms);
    };
  };
  const store = {
    get(k, d) {
      try {
        const v = localStorage.getItem(k);
        return v === null ? d : JSON.parse(v);
      } catch (e) {
        return d;
      }
    },
    set(k, v) {
      try {
        localStorage.setItem(k, JSON.stringify(v));
      } catch (e) {
        /* private mode: ignore */
      }
    },
  };

  let toastTimer;
  function toast(msg) {
    const t = $('#toast');
    t.textContent = msg;
    t.classList.add('is-on');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('is-on'), 2200);
  }

  async function copyText(text, btn) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (e) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    if (btn) {
      const old = btn.textContent;
      btn.textContent = 'Copied';
      btn.classList.add('is-ok');
      setTimeout(() => {
        btn.textContent = old;
        btn.classList.remove('is-ok');
      }, 1400);
    }
    toast('Copied to clipboard');
  }

  function download(name, text, type = 'application/xml') {
    const blob = new Blob([text], { type });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    toast(`Saved ${name}`);
  }

  const radio = (name) => ($(`input[name="${name}"]:checked`) || {}).value;
  const setRadio = (name, v) => {
    const el = $(`input[name="${name}"][value="${v}"]`);
    if (el) el.checked = true;
  };

  /** Remove empty and whitespace-only lines. */
  const cleanLogs = (text) =>
    String(text)
      .split(/\r?\n|\r/)
      .filter((l) => l.trim() !== '')
      .join('\n');

  // ----------------------------------------------------------- settings ---
  function settings() {
    return {
      format: $('#formatSelect').value,
      transport: radio('transport') || 'syslog',
      scheme: radio('scheme') || 'wazuh',
      prefix: $('#prefixInput').value.trim(),
      mode: radio('mode'),
      strategy: radio('strategy'),
      jsonMode: radio('jsonMode'),
      prematch: $('#prematchInput').value.trim(),
      ruleId: Number($('#ruleIdInput').value) || 100100,
      ruleLevel: Number($('#ruleLevelSelect').value),
      eventRules: $('#eventRulesChk').checked,
      sevRules: $('#sevRulesChk').checked,
      builtinJson: $('#builtinJsonChk').checked,
    };
  }

  function restoreSettings() {
    state.customMap = store.get('wds.customMap', {}) || {};
    const s = store.get('wds.settings', null);
    if (!s) return;
    ['transport', 'mode', 'strategy', 'jsonMode'].forEach((k) => s[k] && setRadio(k, s[k]));
    if (s.scheme) setRadio('scheme', W.fieldmap.normalizeScheme(s.scheme));
    if (s.prefix) $('#prefixInput').value = s.prefix;
    if (s.ruleId) $('#ruleIdInput').value = s.ruleId;
    if (s.ruleLevel !== undefined) $('#ruleLevelSelect').value = String(s.ruleLevel);
    if (s.eventRules !== undefined) $('#eventRulesChk').checked = s.eventRules;
    if (s.sevRules !== undefined) $('#sevRulesChk').checked = s.sevRules;
    if (s.builtinJson !== undefined) $('#builtinJsonChk').checked = s.builtinJson;
  }

  const saveSettings = () => {
    const s = settings();
    delete s.prematch; // source-specific: never persisted
    delete s.format; // source-specific: never persisted
    store.set('wds.settings', s);
  };

  const stripPri = () => settings().transport === 'syslog';

  const TRANSPORT_HINT = {
    syslog: 'Logs sent to wazuh-remoted over syslog. The leading <PRI> is stripped before decoding.',
    file: 'Logs read by an agent from a file (localfile). Lines reach the decoders exactly as written, <PRI> included.',
    api: 'Logs posted to the Wazuh server API (POST /events). They reach analysisd as sent, usually JSON, with no syslog processing.',
  };
  const SCHEME_HINT = {
    wazuh: 'Native Wazuh 4.x static fields (srcip, dstuser, action, id...). They unlock GeoIP, active response and rule options like <srcip>.',
    wcs: 'Wazuh Common Schema used by Wazuh 5 (ECS-based names like source.ip, user.name). Fields outside the schema go under custom.*',
    custom: 'Your own naming. Every rename you make is remembered and suggested again the next time the same key shows up.',
  };

  function renderSettingsHints() {
    const s = settings();
    $('#transportHint').textContent = TRANSPORT_HINT[s.transport];
    $('#schemeHint').textContent = SCHEME_HINT[s.scheme];
    $('#customMapBox').hidden = s.scheme !== 'custom';
    const n = Object.keys(state.customMap).length;
    $('#customMapCount').textContent = n ? `${plural(n, 'remembered name')} in your mapping` : 'No remembered names yet: rename fields in step 2 to build your mapping.';
  }

  function remember(key, name) {
    if (settings().scheme !== 'custom' || !key || !name) return;
    state.customMap[key] = name;
    store.set('wds.customMap', state.customMap);
    renderSettingsHints();
  }

  // --------------------------------------------------------- naming ---
  function decoderName() {
    const raw = $('#decoderName').value;
    const clean = U.sanitizeDecoderName(raw);
    return clean || suggestName() || 'custom-decoder';
  }

  function suggestName() {
    const a = state.analysis;
    if (state.sampleName) return state.sampleName;
    if (!a) return '';
    const ok = a.lines.find((l) => l.ok && l.parsed && l.parsed.meta);
    if ((a.format === 'cef' || a.format === 'leef') && ok) {
      return U.sanitizeDecoderName(`${ok.parsed.meta.vendor}-${ok.parsed.meta.product}`.toLowerCase());
    }
    const pn = a.groups.find((g) => g.programName && !['CEF', 'LEEF'].includes(g.programName));
    if (pn) return U.sanitizeDecoderName(pn.programName.toLowerCase());
    return '';
  }

  // ---------------------------------------------------------- pipeline ---
  function analyze(opts = {}) {
    const ta = $('#logs');
    const cleaned = cleanLogs(ta.value);
    if (cleaned !== ta.value) ta.value = cleaned;
    updateLineCount();
    if (!cleaned.trim()) {
      if (!opts.quiet) {
        toast('Paste some logs first');
        ta.focus();
      }
      return false;
    }
    const s = settings();
    const t0 = performance.now();
    state.analysis = W.analyze(cleaned, { format: s.format, stripPri: s.transport === 'syslog', scheme: s.scheme, prefix: s.prefix, customMap: state.customMap });
    state.line = 0;
    state.custom = null;
    $('#decoderName').placeholder = suggestName() || 'e.g. trendmicro-apex';
    regenerate();
    $('#analyzeBtn').classList.remove('pulse');
    if (!opts.quiet) {
      const ms = Math.round(performance.now() - t0);
      toast(`${state.analysis.formatLabel} · ${plural(state.analysis.stats.lines, 'line')} analysed in ${ms} ms`);
    }
    render();
    return true;
  }

  function regenerate() {
    const a = state.analysis;
    if (!a) return;
    const s = settings();
    state.model = W.generate(a, { name: decoderName(), mode: s.mode, strategy: s.strategy, jsonMode: s.jsonMode, customPrematch: s.prematch });
    state.rules = W.generateRules(a, state.model, { baseId: s.ruleId, baseLevel: s.ruleLevel, eventRules: s.eventRules, severityRules: s.sevRules });
    state.verdict = W.linter.verify(state.model, a, { stripPri: s.transport === 'syslog', builtinJson: s.builtinJson });
    if (state.custom && radio('testSource') === 'custom') runCustom();
  }

  const regenerateAndRender = () => {
    regenerate();
    render();
  };
  const regenerateSoon = debounce(regenerateAndRender, 160);

  // ------------------------------------------------------------- steps ---
  const STEPS = 4;

  function canGo(n) {
    return n === 1 || !!state.analysis;
  }

  function goStep(n, opts = {}) {
    n = Math.max(1, Math.min(STEPS, n));
    if (!canGo(n)) {
      toast('Analyze some logs first');
      return;
    }
    state.step = n;
    for (let i = 1; i <= STEPS; i++) $(`#step-${i}`).hidden = i !== n;
    renderStepper();
    if (!opts.keepScroll) window.scrollTo(0, 0);
    if (n === 3) renderTest();
  }

  function next() {
    if (state.step === 1) {
      if (analyze()) goStep(2);
      return;
    }
    if (state.step < STEPS) goStep(state.step + 1);
    else if (state.model && state.model.decoders.length) download(`${state.model.name}_decoders.xml`, state.model.xml);
    else if (state.rules) download(`${state.model.name}_rules.xml`, state.rules.xml);
  }

  function renderStepper() {
    const v = state.verdict;
    const verified = v && !v.issues.some((i) => i.level === 'error') && v.coverage.decoded === v.coverage.parsable;
    $$('.steps li').forEach((li) => {
      const btn = $('.step-btn', li);
      const n = Number(btn.dataset.step);
      btn.disabled = !canGo(n);
      li.classList.toggle('is-current', n === state.step);
      li.classList.toggle('is-done', !!state.analysis && n !== state.step && (n < state.step || (n === 3 && verified)));
      btn.setAttribute('aria-current', n === state.step ? 'step' : 'false');
    });
    $('#backBtn').disabled = state.step === 1;
    const nb = $('#nextBtn');
    nb.textContent = state.step === 1 ? 'Analyze and continue' : state.step === STEPS ? (state.model && !state.model.decoders.length ? 'Download rules' : 'Download decoder') : 'Next';

    const chip = $('#healthChip');
    if (!state.analysis) {
      chip.hidden = true;
      return;
    }
    const errors = v.issues.filter((i) => i.level === 'error').length;
    const warns = v.issues.filter((i) => i.level === 'warn').length;
    const c = v.coverage;
    chip.hidden = false;
    chip.textContent = `${c.decoded}/${c.lines} decoded · ${pct(c.fieldRate)} fields${errors ? ` · ${plural(errors, 'error')}` : ''}`;
    chip.className = 'health-chip ' + (errors || c.decoded < c.parsable ? 'is-err' : c.fieldRate >= 0.999 && !warns ? 'is-ok' : 'is-warn');
  }

  // ------------------------------------------------------------ render ---
  function render() {
    renderHealth();
    renderStepper();
    renderOverview();
    renderFields();
    renderDecoder();
    renderRules();
    renderInstall();
    renderTest();
  }

  function renderHealth() {
    const a = state.analysis;
    const v = state.verdict;
    if (!a) return;
    $('#hFormat').textContent = a.formatLabel;
    $('#hFormatSub').textContent = a.settings.format === 'auto' ? `auto-detected · ${pct(a.share)} of lines` : 'set manually';
    $('#hLines').textContent = `${a.stats.parsed} / ${a.stats.lines - a.stats.headers}`;
    const pn = a.groups.filter((g) => g.programName !== null).length;
    $('#hLinesSub').textContent = a.stats.failed ? `${a.stats.failed} unparsed` : pn ? `parsed · ${plural(pn, 'program name')}` : 'all parsed';
    const sel = a.fields.filter((f) => f.selected && !f.isLabel);
    const statics = sel.filter((f) => W.fieldmap.isStatic(f.name)).length;
    $('#hFields').textContent = `${sel.length} / ${a.fields.filter((f) => !f.isLabel).length}`;
    $('#hFieldsSub').textContent = settings().scheme === 'wazuh' ? `selected · ${statics} Wazuh static` : 'selected';
    const errors = v.issues.filter((i) => i.level === 'error').length;
    const warns = v.issues.filter((i) => i.level === 'warn').length;
    const c = v.coverage;
    $('#hHealth').textContent = `${c.decoded} / ${c.lines} decoded`;
    $('#hHealthSub').textContent = errors || warns ? `${pct(c.fieldRate)} fields · ${plural(errors, 'error')} · ${plural(warns, 'warning')}` : `${pct(c.fieldRate)} field coverage · no issues`;
    const tile = $('#hHealthTile');
    tile.classList.remove('is-ok', 'is-warn', 'is-err');
    const perfect = !errors && c.decoded === c.parsable && c.fieldRate >= 0.999;
    tile.classList.add(errors || c.decoded < c.parsable ? 'is-err' : perfect && !warns ? 'is-ok' : 'is-warn');
  }

  function noteHtml(level, text) {
    const icon = { error: '!', warn: '!', info: 'i', ok: '✓' }[level] || 'i';
    const cls = { error: 'is-error', warn: 'is-warn', info: '', ok: 'is-ok' }[level] || '';
    return `<div class="note ${cls}"><span class="note-icon" aria-hidden="true">${icon}</span><div>${esc(text)}</div></div>`;
  }

  // --------------------------------------------- analysis details ---
  function renderOverview() {
    const a = state.analysis;
    const box = $('#overviewContent');
    const notesBox = $('#analysisNotes');
    if (!a) {
      box.innerHTML = '';
      notesBox.innerHTML = '';
      return;
    }
    const notes = [...a.warnings, ...state.model.notes];
    notesBox.innerHTML = notes.length ? `<div class="notes">${notes.map((n) => noteHtml(n.level, n.text)).join('')}</div>` : '';

    const scores = Object.entries(a.formatScores).sort((x, y) => y[1] - x[1]).slice(0, 5);
    const bars = scores
      .map(([id, s]) => `<div class="bar-row ${id === a.format ? 'is-top' : ''}"><span class="name">${esc(W.formats[id].label)}</span><span class="bar"><span style="width:${Math.max(2, Math.round(s * 100))}%"></span></span><span class="pct">${pct(s)}</span></div>`)
      .join('');

    const o = a.options || {};
    const opt = [];
    if (o.delimiter !== undefined) opt.push(['Delimiter', o.delimiter === '\t' ? 'TAB' : o.delimiter === '\\t' ? 'literal \\t' : o.delimiter]);
    if (o.sep !== undefined) opt.push(['Pair separator', o.sep === ' ' ? 'whitespace' : o.sep]);
    if (o.kvd !== undefined) opt.push(['Key/value delimiter', o.kvd]);
    if (o.header) opt.push(['Header row', o.header.join(', ')]);
    if (a.template) opt.push(['Event templates', String(a.template.clusters.length)]);
    if (a.envelope) opt.push(['Envelope', 'RFC 5424 syslog']);

    const lines = a.lines.filter((l) => !l.isHeader);
    const withHeader = lines.filter((l) => l.pre.header !== 'none').length;
    const progs = new Map();
    const hosts = new Map();
    for (const l of lines) {
      if (l.pre.program_name !== null) progs.set(l.pre.program_name, (progs.get(l.pre.program_name) || 0) + 1);
      if (l.pre.hostname) hosts.set(l.pre.hostname, (hosts.get(l.pre.hostname) || 0) + 1);
    }
    const pills = (m) => [...m.entries()].sort((x, y) => y[1] - x[1]).slice(0, 6).map(([k, n]) => `<span class="pill">${esc(k)} <span class="hint">x${n}</span></span>`).join('') || '<span class="hint">none</span>';
    const withProg = lines.filter((l) => l.pre.program_name !== null).length;

    const rows = lines
      .slice(0, 60)
      .map(
        (l) =>
          `<tr><td class="tl-num">${l.index + 1}</td><td>${l.ok ? '<span class="status-dot ok" title="parsed">✓</span>' : '<span class="status-dot fail" title="not parsed">✕</span>'}</td><td class="src-key">${esc(l.pre.timestamp || '-')}</td><td class="src-key">${esc(l.pre.hostname || '-')}</td><td class="src-key">${l.pre.program_name !== null ? esc(l.pre.program_name) : '-'}</td><td><div class="samples one-line" title="${esc(l.pre.log)}">${esc(l.pre.log)}</div></td></tr>`
      )
      .join('');

    box.innerHTML = `
      <div class="ov-grid">
        <div class="ov-card">
          <h3>Format detection</h3>
          <div class="bars">${bars}</div>
          ${opt.length ? `<dl class="kv-list" style="margin-top:14px">${opt.map(([k, v]) => `<dt>${esc(k)}</dt><dd><code>${esc(v)}</code></dd>`).join('')}</dl>` : ''}
        </div>
        <div class="ov-card">
          <h3>Wazuh pre-decoding</h3>
          <dl class="kv-list">
            <dt>Syslog header</dt><dd>${withHeader} / ${lines.length} lines</dd>
            <dt>Program names</dt><dd>${pills(progs)}</dd>
            <dt>Hostnames</dt><dd>${pills(hosts)}</dd>
            <dt>Routing</dt><dd>${withProg} line(s) go to decoders with <code>&lt;program_name&gt;</code><br>${lines.length - withProg} line(s) go to decoders with <code>&lt;prematch&gt;</code></dd>
          </dl>
        </div>
      </div>
      <h3 class="section-title">What the decoders see after pre-decoding</h3>
      <div class="table-wrap"><table class="table">
        <thead><tr><th>#</th><th></th><th>Timestamp</th><th>Hostname</th><th>program_name</th><th>Body passed to decoders</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
      ${lines.length > 60 ? `<p class="hint" style="margin-top:8px">Showing 60 of ${lines.length} lines.</p>` : ''}`;
  }

  // ----------------------------------------------------------- fields ---
  const GROUP_LABEL = { header: 'Header', envelope: 'Syslog envelope (RFC 5424)', body: 'Fields', template: 'Template' };
  const nameOk = (n) => /^[A-Za-z0-9_.\-@]+$/.test(n);

  function renderFields() {
    const a = state.analysis;
    const body = $('#fieldsBody');
    renderTemplateEditor();
    if (!a) {
      body.innerHTML = '<tr><td colspan="7" class="code-empty">Analyze logs to see their fields.</td></tr>';
      return;
    }
    $('#fieldCatalogue').innerHTML = W.fieldmap
      .catalogue(settings().scheme)
      .map((n) => `<option value="${esc(n)}">`)
      .join('');

    const counts = new Map();
    for (const f of a.fields) if (f.selected && !f.isLabel) counts.set(f.name, (counts.get(f.name) || 0) + 1);
    const jsonPlugin = a.format === 'json' && state.model && !state.model.decoders.some((d) => d.regex);
    const scheme = settings().scheme;

    const filter = $('#fieldFilter').value.trim().toLowerCase();
    let html = '';
    let lastGroup = null;
    const visible = a.fields.filter((f) => !f.isLabel && (!filter || f.key.toLowerCase().includes(filter) || String(f.name).toLowerCase().includes(filter)));
    for (const f of visible) {
      const g = f.group === 'template' ? `template-${f.hint.cluster}` : f.group;
      if (g !== lastGroup) {
        lastGroup = g;
        const label = f.group === 'template' ? `Template #${f.hint.cluster + 1}` : GROUP_LABEL[f.group] || f.group;
        html += `<tr class="group-row"><td colspan="7">${esc(label)}</td></tr>`;
      }
      const isStatic = scheme === 'wazuh' && W.fieldmap.isStatic(f.name);
      const dup = f.selected && counts.get(f.name) > 1 && f.group !== 'template';
      const valid = nameOk(f.name || '');
      const samples = f.samples.filter((s) => s !== '');
      const title = f.topValues.map(([v, n]) => `${v}  (x${n})`).join('\n');
      const srcLabel = f.group === 'template' ? `token ${f.hint.pos + 1}` : f.label ? `label "${f.label}"` : f.quoting === 'always' ? 'quoted' : '';
      const shown = samples.slice(0, 6).map((s) => esc(s)).join('<span class="sep">·</span>');
      html += `<tr data-key="${esc(f.key)}" class="${f.selected ? '' : 'is-off'}">
        <td class="col-check"><input type="checkbox" ${f.selected ? 'checked' : ''} aria-label="Extract ${esc(f.key)}"></td>
        <td><span class="src-key">${esc(f.group === 'template' ? f.templateName || f.key : f.key)}</span>${srcLabel ? `<span class="src-label">${esc(srcLabel)}</span>` : ''}</td>
        <td class="col-arrow">→</td>
        <td><div class="name-cell">
          <input class="input mono ${valid ? '' : 'is-invalid'}" value="${esc(jsonPlugin ? f.key : f.name)}" list="fieldCatalogue" aria-label="Field name for ${esc(f.key)}" spellcheck="false" ${jsonPlugin ? 'disabled title="The JSON plugin keeps the JSON key names. Switch JSON extraction to Regex in the settings to rename."' : ''}>
          <span class="tag-slot">${isStatic && !jsonPlugin ? '<span class="tag tag-static" title="Wazuh static field">static</span>' : ''}${dup ? '<span class="tag tag-dup" title="Several fields use this name">dup</span>' : ''}</span>
        </div></td>
        <td><span class="type-chip">${esc(W.types.info(f.type).label)}</span></td>
        <td><div class="presence"><span class="bar"><span style="width:${Math.round(f.presence * 100)}%"></span></span><span class="pct">${pct(f.presence)}</span></div></td>
        <td><div class="samples" title="${esc(title)}">${samples.length ? shown : '<span class="more">empty</span>'}${f.distinct > 6 ? ` <span class="more">+${f.distinct - 6} more</span>` : ''}</div></td>
      </tr>`;
    }
    body.innerHTML = html || '<tr><td colspan="7" class="code-empty">No field matches this filter.</td></tr>';
  }

  function onFieldsChange(e) {
    const tr = e.target.closest('tr[data-key]');
    if (!tr || !state.analysis) return;
    const f = state.analysis.fields.find((x) => x.key === tr.dataset.key);
    if (!f) return;
    if (e.target.type === 'checkbox') {
      f.selected = e.target.checked;
      tr.classList.toggle('is-off', !f.selected);
      syncTemplateSelection(f);
      regenerateAndRender();
    } else if (e.target.classList.contains('input')) {
      const v = U.sanitizeFieldName(e.target.value);
      if (!v) {
        e.target.value = f.name;
        return;
      }
      f.name = v;
      e.target.value = v;
      if (f.group === 'template') {
        remember(f.templateName, v);
        f.templateName = v;
        state.analysis.template.clusters[f.hint.cluster].positions[f.hint.pos].name = v;
      } else remember(f.key, v);
      regenerateAndRender();
    }
  }

  function onFieldsInput(e) {
    if (!e.target.classList.contains('input')) return;
    e.target.classList.toggle('is-invalid', !nameOk(e.target.value.trim().replace(/\s+/g, '_')));
  }

  function syncTemplateSelection(f) {
    if (f.group !== 'template') return;
    state.analysis.template.clusters[f.hint.cluster].positions[f.hint.pos].selected = f.selected;
  }

  // -------------------------------------------------- template editor ---
  function renderTemplateEditor() {
    const box = $('#templateEditor');
    const a = state.analysis;
    if (!a || !a.template) {
      box.innerHTML = '';
      return;
    }
    const clusters = a.template.clusters.slice(0, 40);
    const html = clusters
      .map((c) => {
        const tailAt = c.positions.findIndex((p) => p.role === 'tail');
        const toks = c.positions
          .map((p, pi) => {
            if (tailAt >= 0 && pi > tailAt) return '';
            const cls = ['tok'];
            if (pi > 0 && p.ws) cls.push('ws');
            if (p.role === 'var') cls.push('is-var');
            if (p.role === 'tail') cls.push('is-tail');
            if ((p.role === 'var' || p.role === 'tail') && !p.selected) cls.push('is-off');
            const shownTok = p.role === 'tail' ? `${p.values[0]} …` : p.values[0];
            const label = p.role === 'var' || p.role === 'tail' ? `<span class="tok-name">${esc(p.name || '')}</span>` : '';
            const tip = p.role === 'const' ? 'Literal. Click to make it a field, Shift+click to capture the rest of the line' : `Field "${p.name}" (${W.types.info(p.type).label}). Click to make it literal`;
            return `<button type="button" class="${cls.join(' ')}" data-c="${c.id}" data-p="${pi}" title="${esc(tip)}">${label}<span class="tok-val">${esc(shownTok)}</span></button>`;
          })
          .join('');
        return `<div class="tpl"><div class="tpl-head"><h3>Template #${c.id + 1}</h3><span class="hint">${plural(c.lines.length, 'line')}</span></div><div class="tokens">${toks}</div></div>`;
      })
      .join('');
    box.innerHTML = `<div class="tpl-legend"><span class="l-lit">Literal</span><span class="l-var">Field</span><span class="l-tail">Rest of line</span><span>Click a token to toggle, Shift+click for "rest of line"</span></div>${html}${a.template.clusters.length > 40 ? `<p class="hint">Showing 40 of ${a.template.clusters.length} templates.</p>` : ''}`;
  }

  function onTokenClick(e) {
    const b = e.target.closest('.tok');
    if (!b || !state.analysis) return;
    const c = state.analysis.template.clusters[Number(b.dataset.c)];
    const p = c.positions[Number(b.dataset.p)];
    if (e.shiftKey) {
      if (p.role === 'tail') p.role = p.isConst ? 'const' : 'var';
      else {
        c.positions.forEach((x) => x.role === 'tail' && (x.role = x.isConst ? 'const' : 'var'));
        p.role = 'tail';
        p.selected = true;
        p.name = p.name || 'message';
      }
    } else if (p.role === 'const') {
      p.role = 'var';
      p.selected = true;
      if (!p.name) p.name = U.sanitizeFieldName(W.types.info(p.type).label.toLowerCase().split(' ')[0]) || 'value';
    } else {
      p.role = 'const';
    }
    W.analyzer.refreshTemplate(state.analysis);
    regenerateAndRender();
  }

  // ----------------------------------------------------- deploy step ---
  function highlightXml(xml) {
    const lines = xml.replace(/\n$/, '').split('\n');
    let inComment = false;
    let current = null;
    const out = [];
    const TAG = /^<(\/?)([\w:.-]+)((?:\s+[\w:.-]+="[^"]*")*)\s*(\/?)>/;
    for (const line of lines) {
      let html = '';
      let i = 0;
      while (i < line.length) {
        if (inComment) {
          const j = line.indexOf('-->', i);
          const end = j < 0 ? line.length : j + 3;
          html += `<span class="x-com">${esc(line.slice(i, end))}</span>`;
          i = end;
          if (j >= 0) inComment = false;
          continue;
        }
        if (line.startsWith('<!--', i)) {
          inComment = true;
          continue;
        }
        if (line[i] === '<') {
          const m = TAG.exec(line.slice(i));
          if (m) {
            const attrs = m[3].replace(/([\w:.-]+)="([^"]*)"/g, (s, k, v) => `<span class="x-attr">${esc(k)}</span>=<span class="x-str">"${esc(v)}"</span>`);
            html += `<span class="x-tag">&lt;${m[1]}${esc(m[2])}</span>${attrs}<span class="x-tag">${m[4]}&gt;</span>`;
            current = m[1] || m[4] ? null : m[2];
            i += m[0].length;
            continue;
          }
        }
        let j = line.indexOf('<', i + 1);
        if (j < 0) j = line.length;
        const text = line.slice(i, j);
        const cls = current && /^(regex|prematch|program_name)$/.test(current) ? 'x-re' : current === 'order' || current === 'parent' || current === 'plugin_decoder' ? 'x-ord' : '';
        html += cls ? `<span class="${cls}">${esc(text)}</span>` : esc(text);
        i = j;
      }
      out.push(`<div class="code-line"><span class="src">${html || ' '}</span></div>`);
    }
    return out.join('');
  }

  function renderDecoder() {
    const m = state.model;
    const code = $('#decoderCode');
    const notes = $('#decoderNotes');
    if (!m) {
      code.innerHTML = '<div class="code-empty">The decoder appears here after analysis.</div>';
      notes.innerHTML = '';
      $('#decoderSummary').textContent = '';
      return;
    }
    const parents = m.decoders.filter((d) => !d.parent).length;
    const children = m.decoders.length - parents;
    const longest = Math.max(0, ...m.decoders.map((d) => Math.max(d.regex ? d.regex.value.length : 0, d.prematch ? d.prematch.value.length : 0)));
    $('#decoderSummary').innerHTML = m.decoders.length
      ? `<strong>${plural(parents, 'parent')}</strong> · <strong>${plural(children, 'child', 'children')}</strong> · longest pattern ${longest}/1023 chars · <code>${esc(m.name)}_decoders.xml</code>`
      : '<strong>No decoder needed</strong> (the built-in json decoder handles these logs, see Rules)';
    const issues = state.verdict.issues.filter((i) => i.level !== 'info');
    const list = [...m.notes.filter((n) => n.level !== 'info'), ...issues];
    notes.innerHTML = list.length ? `<div class="notes">${list.map((n) => noteHtml(n.level, n.text)).join('')}</div>` : `<div class="notes">${noteHtml('ok', `Verified against ${plural(state.verdict.coverage.lines, 'sample line')}: every line is decoded and every selected field is extracted.`)}</div>`;
    code.innerHTML = highlightXml(m.xml);
  }

  function renderRules() {
    $('#rulesCode').innerHTML = state.rules ? highlightXml(state.rules.xml) : '<div class="code-empty">Rules appear here after analysis.</div>';
  }

  function renderInstall() {
    const box = $('#installSteps');
    const name = state.model ? state.model.name : 'custom-decoder';
    const withDecoder = !state.model || state.model.decoders.length > 0;
    const cmd = (c) => `<div class="cmd"><code>${esc(c)}</code><button class="btn btn-ghost btn-sm" type="button" data-copy="${esc(c)}">Copy</button></div>`;
    const items = [];
    if (withDecoder) items.push(`Copy the decoder to the manager${cmd(`sudo cp ${name}_decoders.xml /var/ossec/etc/decoders/ && sudo chown wazuh:wazuh /var/ossec/etc/decoders/${name}_decoders.xml`)}`);
    items.push(`${withDecoder ? 'Optionally, copy' : 'Copy'} the rules${cmd(`sudo cp ${name}_rules.xml /var/ossec/etc/rules/ && sudo chown wazuh:wazuh /var/ossec/etc/rules/${name}_rules.xml`)}`);
    items.push(`Restart the manager${cmd('sudo systemctl restart wazuh-manager')}`);
    items.push(`Paste one of your sample lines to confirm${cmd('sudo /var/ossec/bin/wazuh-logtest')}`);
    box.innerHTML = items.map((i) => `<li>${i}</li>`).join('');
  }

  // ------------------------------------------- sandboxed simulation ---
  // Hand-written decoders may contain regexes that backtrack catastrophically.
  // PCRE2 in Wazuh gives up at its match limit; a JS engine would freeze the
  // tab. So user XML is simulated in a Web Worker built from the already
  // loaded engine modules (works from file://) and killed after a timeout.
  let workerUrl = null;
  function workerSource() {
    const mods = (W.__sources || []).map((f) => `WDG_MODULE(${f.toString()});`).join('\n');
    return [
      'self.WDG_MODULE = function (fn) { var W = (self.WDG = self.WDG || {}); fn(W); };',
      mods,
      'self.onmessage = function (e) { var d = e.data; try { self.postMessage({ ok: true, r: self.WDG.simulator.simulate(d.decoders, d.lines, d.opts) }); } catch (err) { self.postMessage({ ok: false, error: String((err && err.message) || err) }); } };',
    ].join('\n');
  }

  function simulateSafe(decoders, lines, opts, timeoutMs = 5000) {
    return new Promise((resolve) => {
      let worker;
      try {
        if (!workerUrl) workerUrl = URL.createObjectURL(new Blob([workerSource()], { type: 'text/javascript' }));
        worker = new Worker(workerUrl);
      } catch (e) {
        resolve(W.simulator.simulate(decoders, lines, opts)); // no worker support: run inline
        return;
      }
      const timer = setTimeout(() => {
        worker.terminate();
        resolve({ timeout: true });
      }, timeoutMs);
      worker.onmessage = (e) => {
        clearTimeout(timer);
        worker.terminate();
        resolve(e.data.ok ? e.data.r : { error: e.data.error });
      };
      worker.onerror = (e) => {
        clearTimeout(timer);
        worker.terminate();
        resolve({ error: e.message || 'simulation failed' });
      };
      worker.postMessage({ decoders, lines, opts });
    });
  }

  function testLines() {
    return state.analysis ? state.analysis.lines.filter((l) => !l.isHeader) : [];
  }

  let customRun = 0;
  async function runCustom() {
    const xml = $('#customXml').value;
    const lines = testLines();
    if (!xml.trim() || !lines.length) {
      state.custom = null;
      renderTest();
      return;
    }
    const run = ++customRun;
    const parsed = W.xmlreader.readDecoders(xml);
    const s = settings();
    const btn = $('#runCustomBtn');
    btn.textContent = 'Running…';
    const sim = await simulateSafe(parsed.decoders, lines.map((l) => l.raw), { stripPri: s.transport === 'syslog', builtinJson: s.builtinJson });
    btn.textContent = 'Run test';
    if (run !== customRun) return; // a newer run superseded this one
    const issues = [
      ...parsed.errors.map((t) => ({ level: 'error', text: `XML: ${t}` })),
      ...W.linter.lintDecoders(parsed.decoders, { generated: false }),
      ...parsed.warnings.map((t) => ({ level: 'info', text: t })),
    ];
    let results = [];
    if (sim.timeout) {
      issues.unshift({ level: 'error', text: 'The test was stopped after 5 s: a regex backtracks catastrophically on these logs. In Wazuh, PCRE2 would hit its match limit and the events would silently not be decoded. Avoid repeating groups that contain * or + (e.g. (a+)+ or ((?:x|y)+?)+).' });
    } else if (sim.error) {
      issues.unshift({ level: 'error', text: `Simulation failed: ${sim.error}` });
    } else {
      results = sim.results;
      issues.unshift(...sim.errors.map((t) => ({ level: 'error', text: t })));
    }
    const order = { error: 0, warn: 1, info: 2 };
    issues.sort((x, y) => order[x.level] - order[y.level]);
    state.custom = { decoders: parsed.decoders, issues, results };
    renderTest();
  }

  function lineStatus(r, i) {
    const custom = radio('testSource') === 'custom';
    if (!r.decoder) return { cls: 'fail', icon: '✕', text: 'not decoded' };
    if (custom) return r.fields.length ? { cls: 'ok', icon: '✓', text: `decoded by ${r.decoder}` } : { cls: 'partial', icon: '!', text: `${r.decoder}, no fields` };
    const m = state.model;
    const expected = m.builtinJson ? 'json' : m.name;
    if (r.decoder !== expected) return { cls: 'other', icon: '?', text: `taken by ${r.decoder}` };
    const lineIdx = testLines()[i].index;
    const missing = state.verdict.coverage.fields.filter((f) => f.missingLines && f.missingLines.includes(lineIdx));
    return missing.length ? { cls: 'partial', icon: '!', text: 'some fields missing' } : { cls: 'ok', icon: '✓', text: 'decoded' };
  }

  /** Attach, per field, the lines where it was expected but not extracted. */
  function markMissing() {
    const a = state.analysis;
    const v = state.verdict;
    if (!a || !v || v._marked) return;
    const lines = testLines();
    const jsonPlugin = state.model.format === 'json' && !state.model.decoders.some((d) => d.regex);
    for (const cf of v.coverage.fields) {
      const f = a.fields.find((x) => x.key === cf.key);
      cf.missingLines = [];
      if (!f) continue;
      const outName = jsonPlugin || state.model.builtinJson ? W.simulator.JSON_STATIC[f.key] || f.key : W.simulator.STATIC[f.name] || f.name;
      lines.forEach((l, i) => {
        if (!l.ok) return;
        let present;
        if (f.group === 'template') present = a.template.clusters[f.hint.cluster].lines.includes(l.index);
        else {
          const src = f.group === 'envelope' ? l.envelope && l.envelope.fields : l.parsed && l.parsed.fields;
          present = !!(src && src.find((x) => x.key === f.key));
        }
        if (present && !v.results[i].fields.some((x) => x.name === outName)) cf.missingLines.push(l.index);
      });
    }
    v._marked = true;
  }

  function renderTest() {
    const custom = radio('testSource') === 'custom';
    $('#customXmlBox').hidden = !custom;
    const listEl = $('#testLines');
    const detail = $('#testDetail');
    const issuesEl = $('#testIssues');
    const covEl = $('#coverage');
    const lines = testLines();
    if (!state.analysis) {
      listEl.innerHTML = '<div class="code-empty">No logs yet.</div>';
      detail.innerHTML = '<p class="hint">Analyze logs to test the decoder against them.</p>';
      issuesEl.innerHTML = '';
      covEl.innerHTML = '';
      return;
    }
    let results;
    let issues;
    if (custom) {
      if (!state.custom) {
        listEl.innerHTML = '<div class="code-empty">Paste decoder XML above and press "Run test".</div>';
        detail.innerHTML = '';
        issuesEl.innerHTML = '';
        covEl.innerHTML = '';
        return;
      }
      results = state.custom.results;
      issues = state.custom.issues;
    } else {
      results = state.verdict.results;
      issues = state.verdict.issues;
      markMissing();
    }

    issuesEl.innerHTML = issues.length ? `<div class="notes">${issues.slice(0, 12).map((n) => noteHtml(n.level, n.text)).join('')}${issues.length > 12 ? `<p class="hint">+${issues.length - 12} more</p>` : ''}</div>` : `<div class="notes">${noteHtml('ok', 'No issue found.')}</div>`;

    if (state.line >= results.length) state.line = 0;
    listEl.innerHTML = results.length ? '' : '<div class="code-empty">No result.</div>';
    listEl.innerHTML += results
      .map((r, i) => {
        const st = lineStatus(r, i);
        return `<button type="button" role="option" class="tl ${i === state.line ? 'is-active' : ''}" data-i="${i}" aria-selected="${i === state.line}" title="${esc(st.text)}"><span class="status-dot ${st.cls}">${st.icon}</span><span class="tl-num">${lines[i].index + 1}</span><span class="tl-text">${esc(lines[i].raw)}</span></button>`;
      })
      .join('');

    const r = results[state.line];
    detail.innerHTML = '';
    if (r) {
      const st = lineStatus(r, state.line);
      const fieldsRows = r.fields.map((f) => `<tr><td>${esc(f.name)}${f.static ? ' <span class="tag tag-static">static</span>' : ''}</td><td>${esc(f.value)}</td></tr>`).join('');
      detail.innerHTML = `
        <h3>Line ${lines[state.line].index + 1} <span class="status-dot ${st.cls}">${st.icon}</span> <span class="hint">${esc(st.text)} · ${plural(r.fields.length, 'field')}</span></h3>
        <pre class="logtest">${esc(W.simulator.logtest(r))}</pre>
        ${r.fields.length ? `<div class="table-wrap" style="max-height:30vh;margin-bottom:12px"><table class="table fields-out"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>${fieldsRows}</tbody></table></div>` : ''}
        <h3>Decoding trace</h3>
        <ol class="trace">${r.trace.map((t) => `<li>${esc(t)}</li>`).join('')}</ol>`;
    }

    if (!custom) {
      const cov = state.verdict.coverage.fields.filter((f) => f.expected > 0);
      covEl.innerHTML = cov.length
        ? cov
            .map((f) => {
              const good = f.extracted - f.mismatched;
              const ratio = good / f.expected;
              const cls = ratio >= 0.999 ? '' : ratio === 0 ? 'is-zero' : 'is-partial';
              const tip = f.example ? `e.g. line ${f.example.line + 1}: expected "${f.example.want}", got "${f.example.got}"` : '';
              return `<div class="cov-row ${cls}" title="${esc(tip)}"><span class="cov-name">${esc(f.name)}</span><span class="bar"><span style="width:${Math.round(ratio * 100)}%"></span></span><span class="cov-val">${good} / ${f.expected}</span></div>`;
            })
            .join('')
        : '<p class="hint">No selected field.</p>';
    } else {
      const counts = new Map();
      for (const res of results) for (const f of res.fields) counts.set(f.name, (counts.get(f.name) || 0) + 1);
      covEl.innerHTML = counts.size
        ? [...counts.entries()]
            .map(([n, c]) => `<div class="cov-row ${c === results.length ? '' : 'is-partial'}"><span class="cov-name">${esc(n)}</span><span class="bar"><span style="width:${Math.round((c / results.length) * 100)}%"></span></span><span class="cov-val">${c} / ${results.length} lines</span></div>`)
            .join('')
        : '<p class="hint">No field was extracted.</p>';
    }
  }

  // ------------------------------------------------------------- input ---
  function updateLineCount() {
    const n = U.splitLines($('#logs').value).length;
    $('#lineCount').textContent = plural(n, 'line');
  }

  function loadText(text, name, opts = {}) {
    $('#logs').value = cleanLogs(text);
    updateLineCount();
    if (name !== undefined) state.sampleName = name;
    analyze({ quiet: opts.quiet });
  }

  function readFile(file) {
    if (!file) return;
    if (file.size > 10 * 1024 * 1024) toast('File is larger than 10 MB, only the beginning is used');
    const reader = new FileReader();
    reader.onload = () => {
      state.sampleName = U.sanitizeDecoderName(file.name.replace(/\.[^.]+$/, '').toLowerCase());
      loadText(String(reader.result));
    };
    reader.readAsText(file.size > 10 * 1024 * 1024 ? file.slice(0, 10 * 1024 * 1024) : file);
  }

  // --------------------------------------------------------------- init ---
  function init() {
    restoreSettings();
    renderSettingsHints();

    // samples
    const sel = $('#sampleSelect');
    for (const s of W.samples) sel.add(new Option(s.label, s.id));
    sel.addEventListener('change', () => {
      const s = W.samples.find((x) => x.id === sel.value);
      sel.value = '';
      if (!s) return;
      $('#decoderName').value = s.source;
      $('#prematchInput').value = '';
      $('#formatSelect').value = 'auto';
      loadText(s.text, s.source);
    });

    // logs: empty lines are removed on paste, on blur and before analysis
    const logs = $('#logs');
    logs.addEventListener('input', () => {
      updateLineCount();
      if (state.analysis) $('#analyzeBtn').classList.add('pulse');
    });
    logs.addEventListener('paste', (e) => {
      const text = e.clipboardData && e.clipboardData.getData('text');
      if (typeof text !== 'string') return;
      e.preventDefault();
      const cleaned = cleanLogs(text);
      const { selectionStart: a, selectionEnd: b, value } = logs;
      const before = value.slice(0, a);
      const glue = before && !before.endsWith('\n') && cleaned ? '\n' : '';
      logs.setRangeText(glue + cleaned, a, b, 'end');
      logs.value = cleanLogs(logs.value);
      state.sampleName = '';
      updateLineCount();
      analyze({ quiet: true });
    });
    logs.addEventListener('blur', () => {
      const c = cleanLogs(logs.value);
      if (c !== logs.value) {
        logs.value = c;
        updateLineCount();
      }
    });
    $('#analyzeBtn').addEventListener('click', () => {
      if (analyze()) goStep(2);
    });
    $('#clearBtn').addEventListener('click', () => {
      logs.value = '';
      state.sampleName = '';
      updateLineCount();
      logs.focus();
    });
    $('#fileInput').addEventListener('change', (e) => readFile(e.target.files[0]));

    const dz = $('#dropzone');
    ['dragenter', 'dragover'].forEach((ev) =>
      dz.addEventListener(ev, (e) => {
        e.preventDefault();
        dz.classList.add('is-over');
      })
    );
    ['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, () => dz.classList.remove('is-over')));
    dz.addEventListener('drop', (e) => {
      e.preventDefault();
      readFile(e.dataTransfer.files[0]);
    });

    // decoder name + format
    $('#decoderName').addEventListener('input', (e) => {
      const raw = e.target.value;
      const clean = U.sanitizeDecoderName(raw);
      const hint = $('#decoderNameHint');
      const bad = raw && clean !== raw.trim();
      e.target.classList.toggle('is-invalid', !!bad);
      hint.classList.toggle('is-error', !!bad);
      hint.innerHTML = bad ? `Will be used as <code>${esc(clean || 'custom-decoder')}</code>. Only letters, digits, <code>-</code> <code>_</code> <code>.</code> are allowed.` : 'Letters, digits, <code>-</code> <code>_</code> <code>.</code> are allowed. Used for the parent, children, file names and rules.';
      if (state.analysis) regenerateSoon();
    });
    $('#formatSelect').addEventListener('change', () => state.analysis && analyze({ quiet: true }));

    // settings dialog
    const dlg = $('#settingsDialog');
    $('#settingsBtn').addEventListener('click', () => {
      renderSettingsHints();
      dlg.showModal();
    });
    const reanalyze = () => {
      saveSettings();
      renderSettingsHints();
      if (state.analysis) analyze({ quiet: true });
    };
    $$('input[name="transport"]').forEach((el) => el.addEventListener('change', reanalyze));
    const rename = () => {
      saveSettings();
      renderSettingsHints();
      if (!state.analysis) return;
      const s = settings();
      W.analyzer.renameAll(state.analysis, s.scheme, s.prefix, state.customMap);
      regenerateAndRender();
    };
    $$('input[name="scheme"]').forEach((el) => el.addEventListener('change', rename));
    $('#prefixInput').addEventListener('input', debounce(rename, 250));
    const regen = () => {
      saveSettings();
      if (state.analysis) regenerateAndRender();
    };
    ['mode', 'strategy', 'jsonMode'].forEach((n) => $$(`input[name="${n}"]`).forEach((el) => el.addEventListener('change', regen)));
    $('#prematchInput').addEventListener('input', debounce(regen, 300));
    ['#ruleIdInput', '#ruleLevelSelect', '#eventRulesChk', '#sevRulesChk', '#builtinJsonChk'].forEach((id) => $(id).addEventListener('change', regen));

    // custom mapping export / import / clear
    $('#exportMapBtn').addEventListener('click', () => download('decoder-studio-mapping.json', JSON.stringify(state.customMap, null, 2) + '\n', 'application/json'));
    $('#importMapInput').addEventListener('change', (e) => {
      const f = e.target.files[0];
      if (!f) return;
      const r = new FileReader();
      r.onload = () => {
        try {
          const obj = JSON.parse(String(r.result));
          if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new Error('not an object');
          for (const [k, v] of Object.entries(obj)) if (typeof v === 'string' && v) state.customMap[k] = U.sanitizeFieldName(v);
          store.set('wds.customMap', state.customMap);
          renderSettingsHints();
          rename();
          toast('Mapping imported');
        } catch (err) {
          toast('This file is not a valid mapping (expected a JSON object of key: name)');
        }
        e.target.value = '';
      };
      r.readAsText(f);
    });
    $('#clearMapBtn').addEventListener('click', () => {
      state.customMap = {};
      store.set('wds.customMap', {});
      renderSettingsHints();
      toast('Custom mapping cleared');
    });

    // fields
    const fb = $('#fieldsBody');
    fb.addEventListener('change', onFieldsChange);
    fb.addEventListener('input', onFieldsInput);
    fb.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && e.target.classList.contains('input')) e.target.blur();
    });
    $('#fieldFilter').addEventListener('input', debounce(renderFields, 120));
    $$('[data-select]').forEach((b) =>
      b.addEventListener('click', () => {
        const a = state.analysis;
        if (!a) return;
        const mode = b.dataset.select;
        const filter = $('#fieldFilter').value.trim().toLowerCase();
        for (const f of a.fields) {
          if (f.isLabel) continue;
          if (filter && !f.key.toLowerCase().includes(filter) && !String(f.name).toLowerCase().includes(filter)) continue;
          if (mode === 'all') f.selected = true;
          else if (mode === 'none') f.selected = false;
          else {
            f.name = f.suggested;
            f.selected = f.samples.some((s) => s !== '') && !/^(cef\.(version|vendor|product|device_version)|leef\.(version|vendor|product|product_version)|syslog\.(timestamp|procid))$/.test(f.key);
          }
          syncTemplateSelection(f);
        }
        regenerateAndRender();
      })
    );
    $('#templateEditor').addEventListener('click', onTokenClick);

    // deploy
    $$('input[name="deployView"]').forEach((el) =>
      el.addEventListener('change', () => {
        const rules = radio('deployView') === 'rules';
        $('#deployDecoder').hidden = rules;
        $('#deployRules').hidden = !rules;
      })
    );
    $('#copyDecoderBtn').addEventListener('click', (e) => state.model && copyText(state.model.xml, e.currentTarget));
    $('#downloadDecoderBtn').addEventListener('click', () => state.model && download(`${state.model.name}_decoders.xml`, state.model.xml));
    $('#copyRulesBtn').addEventListener('click', (e) => state.rules && copyText(state.rules.xml, e.currentTarget));
    $('#downloadRulesBtn').addEventListener('click', () => state.rules && download(`${state.model.name}_rules.xml`, state.rules.xml));
    $('#installSteps').addEventListener('click', (e) => {
      const b = e.target.closest('[data-copy]');
      if (b) copyText(b.dataset.copy, b);
    });
    $('#editDecoderBtn').addEventListener('click', () => {
      if (!state.model) return;
      $('#customXml').value = state.model.xml;
      setRadio('testSource', 'custom');
      goStep(3);
      runCustom();
    });

    // verify
    $$('input[name="testSource"]').forEach((el) =>
      el.addEventListener('change', () => {
        if (radio('testSource') === 'custom' && !$('#customXml').value.trim() && state.model) $('#customXml').value = state.model.xml;
        state.line = 0;
        if (radio('testSource') === 'custom') runCustom();
        else renderTest();
      })
    );
    $('#runCustomBtn').addEventListener('click', () => {
      if (!state.analysis) {
        toast('Analyze some logs first, they are the test input');
        return;
      }
      runCustom().then(() => toast('Test complete'));
    });
    $('#customXml').addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        e.stopPropagation();
        runCustom();
      }
    });
    $('#testLines').addEventListener('click', (e) => {
      const b = e.target.closest('.tl');
      if (!b) return;
      state.line = Number(b.dataset.i);
      renderTest();
      const again = $(`.tl[data-i="${state.line}"]`);
      if (again) again.focus();
    });
    $('#testLines').addEventListener('keydown', (e) => {
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
      e.preventDefault();
      const n = $$('.tl').length;
      state.line = Math.max(0, Math.min(n - 1, state.line + (e.key === 'ArrowDown' ? 1 : -1)));
      renderTest();
      const b = $(`.tl[data-i="${state.line}"]`);
      if (b) {
        b.focus();
        b.scrollIntoView({ block: 'nearest' });
      }
    });

    // stepper
    $$('.step-btn').forEach((b) => b.addEventListener('click', () => goStep(Number(b.dataset.step))));
    $('#backBtn').addEventListener('click', () => goStep(state.step - 1));
    $('#nextBtn').addEventListener('click', next);

    // global shortcuts
    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && document.activeElement !== $('#customXml')) {
        e.preventDefault();
        if (analyze() && state.step === 1) goStep(2);
      } else if (e.altKey && /^[1-4]$/.test(e.key)) {
        e.preventDefault();
        goStep(Number(e.key));
      }
    });

    // theme + help
    $('#themeBtn').addEventListener('click', () => {
      const root = document.documentElement;
      const cur = root.getAttribute('data-theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
      const nextTheme = cur === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', nextTheme);
      try {
        localStorage.setItem('wds.theme', nextTheme);
      } catch (e) {
        /* ignore */
      }
    });
    $('#helpBtn').addEventListener('click', () => $('#helpDialog').showModal());

    updateLineCount();
    render();
    goStep(1, { keepScroll: true });

    // Deep links for demos: ?sample=<id>&step=<1-4>&theme=<light|dark>
    const q = new URLSearchParams(location.search);
    if (q.get('theme') === 'dark' || q.get('theme') === 'light') document.documentElement.setAttribute('data-theme', q.get('theme'));
    const sample = W.samples.find((x) => x.id === q.get('sample'));
    if (sample) {
      $('#decoderName').value = sample.source;
      loadText(sample.text, sample.source, { quiet: true });
    }
    const legacyTab = { overview: 2, fields: 2, test: 3, decoder: 4, rules: 4 }[q.get('tab')];
    const step = Number(q.get('step')) || legacyTab;
    if (step && state.analysis) goStep(step, { keepScroll: true });
    if (q.get('tab') === 'rules') {
      setRadio('deployView', 'rules');
      $('#deployDecoder').hidden = true;
      $('#deployRules').hidden = false;
    }
    if (q.get('settings')) $('#settingsBtn').click();
  }

  document.addEventListener('DOMContentLoaded', init);
})();
