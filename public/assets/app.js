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
      uiScale: radio('uiScale') || '1.1',
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
    ['transport', 'mode', 'strategy', 'jsonMode', 'uiScale'].forEach((k) => s[k] && setRadio(k, s[k]));
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
    $('#nextBtn').classList.remove('pulse');
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
    $('#backBtn').hidden = state.step === 1;
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
    if (!a) {
      for (const id of ['hFormat', 'hLines', 'hFields', 'hHealth']) $(`#${id}`).textContent = '-';
      for (const id of ['hFormatSub', 'hLinesSub', 'hFieldsSub', 'hHealthSub']) $(`#${id}`).innerHTML = '&nbsp;';
      $('#hHealthTile').classList.remove('is-ok', 'is-warn', 'is-err');
      return;
    }
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
          <input class="input mono ${valid ? '' : 'is-invalid'}" value="${esc(jsonPlugin ? f.key : f.name)}" autocomplete="off" role="combobox" aria-autocomplete="list" aria-expanded="false" aria-label="Field name for ${esc(f.key)}" spellcheck="false" ${jsonPlugin ? 'disabled title="The JSON plugin keeps the JSON key names. Switch JSON extraction to Regex in the settings to rename."' : ''}>
          <span class="tag-slot">${isStatic && !jsonPlugin ? '<span class="tag tag-static" title="Wazuh static field">static</span>' : ''}${scheme === 'wcs' && !jsonPlugin && !String(f.name).startsWith('custom.') && !W.fieldmap.isKnownName('wcs', f.name) ? '<span class="tag tag-custom" title="Not a WCS field: kept as a custom field">custom</span>' : ''}${dup ? '<span class="tag tag-dup" title="Several fields use this name">dup</span>' : ''}</span>
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
        const c = state.analysis.template.clusters[f.hint.cluster];
        if (f.hint.manual) {
          const s = c.manual.spans.find((x) => x.id === f.hint.span);
          if (s) s.name = v;
        } else c.positions[f.hint.pos].name = v;
      } else remember(f.key, v);
      regenerateAndRender();
    }
  }

  function onFieldsInput(e) {
    if (!e.target.classList.contains('input')) return;
    e.target.classList.toggle('is-invalid', !nameOk(e.target.value.trim().replace(/\s+/g, '_')));
  }

  // ------------------------------------------------------- field picker ---
  // Dropdown on every field-name input: fields matching the value's type
  // first, narrowed as the analyst types; any custom name stays allowed.
  let comboEl = null;
  let combo = null; // { input, field, typed, active, items }
  const SCHEME_LABEL = { wazuh: 'Native Wazuh', wcs: 'WCS', custom: 'the catalogue' };

  function openCombo(input) {
    const tr = input.closest('tr[data-key]');
    const f = tr && state.analysis && state.analysis.fields.find((x) => x.key === tr.dataset.key);
    if (!f || input.disabled) return;
    if (!comboEl) {
      comboEl = document.createElement('div');
      comboEl.className = 'combo-list';
      comboEl.setAttribute('role', 'listbox');
      comboEl.hidden = true;
      document.body.appendChild(comboEl);
      // mousedown + preventDefault: pick before the input loses focus
      comboEl.addEventListener('mousedown', (e) => {
        e.preventDefault();
        const it = e.target.closest('.combo-item');
        if (it) pickCombo(it.dataset.name);
      });
    }
    combo = { input, field: f, typed: false, active: -1, items: [] };
    input.setAttribute('aria-expanded', 'true');
    renderCombo();
  }

  function closeCombo() {
    if (combo) combo.input.setAttribute('aria-expanded', 'false');
    combo = null;
    if (comboEl) comboEl.hidden = true;
  }

  function markQuery(name, q) {
    if (!q) return esc(name);
    const i = name.toLowerCase().indexOf(q.toLowerCase());
    if (i < 0) return esc(name);
    return `${esc(name.slice(0, i))}<mark>${esc(name.slice(i, i + q.length))}</mark>${esc(name.slice(i + q.length))}`;
  }

  function renderCombo() {
    if (!combo || !comboEl) return;
    const { input, field } = combo;
    const scheme = settings().scheme;
    const q = combo.typed ? input.value.trim() : '';
    const opts = W.fieldmap.pickerOptions(scheme, { type: field.type, key: field.key, query: q });
    const sugg = opts.suggested.slice(0, 40);
    const others = opts.others.slice(0, q ? 60 : 40);
    combo.items = [...sugg, ...others].map((x) => x.name);
    if (combo.active >= combo.items.length) combo.active = combo.items.length - 1;
    let i = 0;
    const row = (x) => `<div class="combo-item${i === combo.active ? ' is-active' : ''}" role="option" data-idx="${i++}" data-name="${esc(x.name)}"><span class="mono">${markQuery(x.name, q)}</span><span class="combo-desc">${esc(x.desc)}</span></div>`;
    let html = '';
    if (sugg.length) html += `<div class="combo-group">Suggested for ${esc(W.types.info(field.type).label)}</div>${sugg.map(row).join('')}`;
    if (others.length) html += `<div class="combo-group">${q ? 'Other matches' : 'All fields'}</div>${others.map(row).join('')}`;
    const custom = q && !opts.known && !(scheme === 'wcs' && q.startsWith('custom.'));
    const foot = custom
      ? `<div class="combo-foot is-custom">"${esc(q)}" is a custom field, not part of ${SCHEME_LABEL[scheme] || 'the catalogue'}. Press Enter to keep it.</div>`
      : `<div class="combo-foot">Type to filter, or enter any custom name.</div>`;
    comboEl.innerHTML = html + foot;
    comboEl.hidden = false;
    const r = input.getBoundingClientRect();
    const width = Math.max(r.width, Math.min(380, window.innerWidth - 24));
    comboEl.style.width = `${width}px`;
    comboEl.style.left = `${Math.max(12, Math.min(r.left, window.innerWidth - width - 12))}px`;
    const h = comboEl.offsetHeight;
    comboEl.style.top = `${r.bottom + 4 + h > window.innerHeight - 8 && r.top - h - 4 > 8 ? r.top - h - 4 : r.bottom + 4}px`;
    const act = $('.combo-item.is-active', comboEl);
    if (act) act.scrollIntoView({ block: 'nearest' });
  }

  function pickCombo(name) {
    if (!combo) return;
    const input = combo.input;
    input.value = name;
    closeCombo();
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function onComboKey(e) {
    if (!combo || e.target !== combo.input) return;
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const n = combo.items.length;
      if (!n) return;
      combo.active = e.key === 'ArrowDown' ? (combo.active + 1) % n : (combo.active - 1 + n) % n;
      renderCombo();
    } else if (e.key === 'Enter') {
      if (combo.active >= 0 && combo.items[combo.active]) {
        e.preventDefault();
        e.stopPropagation();
        pickCombo(combo.items[combo.active]);
      } else closeCombo();
    } else if (e.key === 'Escape') {
      closeCombo();
    }
  }

  function syncTemplateSelection(f) {
    if (f.group !== 'template') return;
    const c = state.analysis.template.clusters[f.hint.cluster];
    if (f.hint.manual) {
      const s = c.manual.spans.find((x) => x.id === f.hint.span);
      if (s) s.capture = f.selected;
    } else c.positions[f.hint.pos].selected = f.selected;
  }

  // --------------------------------------------------- pattern builder ---
  // regex101-style editor for free-form templates: select text in the sample
  // line to create a field; every field keeps one color in the sample, in the
  // regular expression, in the match table and in the test lines.
  const GROUP_COLORS = 8;
  const TPL = () => W.formats.template;

  function sampleOf(c) {
    return c.manual ? c.manual.line : state.analysis.lines[c.lines[0]].payload;
  }

  /** Spans shown for a template: its builder spans, or the ones implied by the suggestion. */
  function displaySpans(c) {
    const spans = TPL().spansFromCluster(c, sampleOf(c));
    return spans.sort((a, b) => a.start - b.start);
  }

  /** HTML of a text with non-overlapping highlighted ranges. */
  function paint(text, ranges) {
    let html = '';
    let cur = 0;
    for (const r of ranges.slice().sort((a, b) => a.start - b.start)) {
      if (r.start < cur) continue;
      html += esc(text.slice(cur, r.start));
      html += `<span class="${r.cls}"${r.attrs || ''}${r.title ? ` title="${esc(r.title)}"` : ''}>${esc(text.slice(r.start, r.end)) || '&#8203;'}</span>`;
      cur = r.end;
    }
    return html + esc(text.slice(cur));
  }

  /** Color index of each captured span, in capture order. */
  function colorMap(spans) {
    const m = new Map();
    let i = 0;
    for (const s of spans) if (s.capture) m.set(s, i++ % GROUP_COLORS);
    return m;
  }

  /** Syntax-highlighted PCRE2, capture groups tinted with their field color. */
  function highlightRegex(re) {
    let out = '';
    let group = 0;
    const stack = [];
    for (let i = 0; i < re.length; i++) {
      const ch = re[i];
      if (ch === '\\') {
        const tok = re.slice(i, re[i + 1] === 'x' ? i + 4 : i + 2);
        out += `<span class="${/^\\[dDsSwWhH]$/.test(tok) ? 're-class' : 're-esc'}">${esc(tok)}</span>`;
        i += tok.length - 1;
      } else if (ch === '[') {
        let j = i + 1;
        if (re[j] === '^') j++;
        if (re[j] === ']') j++;
        while (j < re.length && re[j] !== ']') j += re[j] === '\\' ? 2 : 1;
        out += `<span class="re-set">${esc(re.slice(i, j + 1))}</span>`;
        i = j;
      } else if (ch === '(') {
        if (re[i + 1] === '?') {
          const m = /^\(\?(?:[:=!|>]|<[=!])/.exec(re.slice(i));
          const tok = m ? m[0] : '(?';
          out += `<span class="re-nc">${esc(tok)}`;
          stack.push('nc');
          i += tok.length - 1;
        } else {
          out += `<span class="re-grp g${group++ % GROUP_COLORS}">(`;
          stack.push('cap');
        }
      } else if (ch === ')') {
        out += ')</span>';
        stack.pop();
      } else if ('+*?'.includes(ch)) out += `<span class="re-q">${ch}</span>`;
      else if (ch === '{' && /^\{\d+(?:,\d*)?\}/.test(re.slice(i))) {
        const q = /^\{\d+(?:,\d*)?\}/.exec(re.slice(i))[0];
        out += `<span class="re-q">${q}</span>`;
        i += q.length - 1;
      } else if (ch === '^' || ch === '$') out += `<span class="re-anchor">${ch}</span>`;
      else if (ch === '|') out += '<span class="re-alt">|</span>';
      else out += esc(ch);
    }
    while (stack.length) {
      out += '</span>';
      stack.pop();
    }
    return out;
  }

  function renderTemplateEditor() {
    const box = $('#templateEditor');
    const a = state.analysis;
    if (!a || !a.template) {
      box.innerHTML = '';
      return;
    }
    const mode = settings().mode;
    const clusters = a.template.clusters.slice(0, 20);
    box.innerHTML = clusters
      .map((c) => {
        const line = sampleOf(c);
        const spans = displaySpans(c);
        const colors = colorMap(spans);
        const fieldByKey = (s) => a.fields.find((f) => f.group === 'template' && f.hint.cluster === c.id && (c.manual ? f.hint.span === s.id : f.hint.pos === s.pos));
        const nameOf = (s) => {
          const f = fieldByKey(s);
          return f ? f.name : s.name;
        };
        const ranges = spans.map((s) => ({
          start: s.start,
          end: s.end,
          cls: s.capture ? `bl-hl g${colors.get(s)}` : 'bl-hl is-wild',
          attrs: ` data-start="${s.start}" data-end="${s.end}"${s.id ? ` data-id="${s.id}"` : ''}`,
          title: `${nameOf(s)}${s.capture ? '' : ' (wildcard, not extracted)'}. Click to edit`,
        }));
        const { pattern } = TPL().clusterRegex(c, mode);
        const info = spans
          .filter((s) => s.capture)
          .map((s) => `<tr><td><span class="swatch g${colors.get(s)}"></span></td><td class="mono">${esc(nameOf(s))}</td><td class="mono bl-val">${esc(line.slice(s.start, s.end))}</td></tr>`)
          .join('');
        const wild = spans.filter((s) => !s.capture).length;
        const tests = c.lines.slice(0, 30).map((li) => {
          const text = a.lines[li].payload;
          const r = TPL().extract(c, text);
          if (!r) return `<div class="bl-test is-miss"><span class="bl-tag">no match</span>${esc(text)}</div>`;
          const tr = r.indices
            .map((ix, i) => (ix ? { start: ix[0], end: ix[1], cls: `bl-hl g${i % GROUP_COLORS}` } : null))
            .filter(Boolean);
          return `<div class="bl-test">${paint(text, tr)}</div>`;
        });
        return `<div class="card builder" data-c="${c.id}">
          <div class="bl-head">
            <h3>Template #${c.id + 1} <span class="hint">${plural(c.lines.length, 'line')}${c.manual ? ' · edited' : ' · suggested'}</span></h3>
            <div class="btn-group">
              ${c.manual ? `<button class="btn btn-ghost btn-sm" type="button" data-act="reset" data-c="${c.id}">Reset to suggestion</button>` : ''}
              <button class="btn btn-ghost btn-sm" type="button" data-act="clear" data-c="${c.id}">Clear fields</button>
            </div>
          </div>
          <p class="hint">Select any part of the log to turn it into a field. Click a highlighted field to rename it, make it a wildcard or remove it.</p>
          <div class="bl-sample mono" data-c="${c.id}">${paint(line, ranges)}</div>
          <div class="bl-grid">
            <div>
              <div class="bl-label"><span>Regular expression</span><button class="btn btn-ghost btn-sm" type="button" data-act="copy-re" data-c="${c.id}">Copy</button></div>
              <div class="bl-regex mono">${highlightRegex(pattern)}</div>
            </div>
            <div>
              <div class="bl-label"><span>Match information</span>${wild ? `<span class="hint">${plural(wild, 'wildcard')}</span>` : ''}</div>
              ${info ? `<table class="bl-info">${info}</table>` : '<p class="hint">No field yet: select text in the sample.</p>'}
            </div>
          </div>
          <div class="bl-label"><span>Test lines</span><span class="hint">${c.lines.length > 30 ? `first 30 of ${c.lines.length}` : plural(c.lines.length, 'line')}</span></div>
          <div class="bl-tests mono">${tests.join('')}</div>
        </div>`;
      })
      .join('');
    if (a.template.clusters.length > 20) box.innerHTML += `<p class="hint">Showing 20 of ${a.template.clusters.length} templates.</p>`;
  }

  // ---- popover
  let pop = null;
  function closePop() {
    if (pop) pop.hidden = true;
  }

  function openPop(rect, html, onAction) {
    if (!pop) {
      pop = document.createElement('div');
      pop.className = 'span-pop';
      pop.setAttribute('role', 'dialog');
      document.body.appendChild(pop);
    }
    pop.innerHTML = html;
    pop.hidden = false;
    const w = Math.min(340, window.innerWidth - 24);
    pop.style.width = `${w}px`;
    pop.style.left = `${Math.max(12, Math.min(rect.left, window.innerWidth - w - 12))}px`;
    const below = rect.bottom + 8;
    pop.style.top = `${below + 200 > window.innerHeight ? Math.max(12, rect.top - 8 - pop.offsetHeight) : below}px`;
    const input = $('input.input', pop);
    if (input) {
      input.focus();
      input.select();
    }
    pop.onclick = (e) => {
      const b = e.target.closest('[data-act]');
      if (b) onAction(b.dataset.act, input ? input.value : '', pop);
    };
    pop.onkeydown = (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        onAction('primary', input ? input.value : '', pop);
      } else if (e.key === 'Escape') closePop();
    };
  }

  /** Character offset of a DOM point inside the sample element. */
  function offsetIn(root, node, offset) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let pos = 0;
    let n;
    while ((n = walker.nextNode())) {
      if (n === node) return pos + offset;
      pos += n.textContent.length;
    }
    // node is an element: count the text before its offset-th child
    if (node.nodeType === 1) {
      let p = 0;
      for (let i = 0; i < offset && i < node.childNodes.length; i++) p += node.childNodes[i].textContent.length;
      const r = document.createRange();
      r.setStart(root, 0);
      r.setEnd(node, 0);
      return r.toString().length + p;
    }
    return pos;
  }

  function usedNames() {
    return new Set(state.analysis.fields.filter((f) => f.selected).map((f) => f.name));
  }

  function afterBuilderChange() {
    W.analyzer.refreshTemplate(state.analysis);
    regenerateAndRender();
  }

  /** Switch a template to builder mode, carrying over the current field names. */
  function manualOf(c) {
    const fresh = !c.manual;
    const man = TPL().toManual(c, sampleOf(c));
    if (fresh) {
      for (const s of man.spans) {
        const f = state.analysis.fields.find((x) => x.group === 'template' && x.hint.cluster === c.id && x.hint.pos === s.pos);
        if (f) {
          s.name = f.name;
          s.capture = f.selected;
        }
      }
    }
    return man;
  }

  function onSampleMouseUp(e) {
    const el = e.target.closest('.bl-sample');
    if (!el || !state.analysis) return;
    const sel = window.getSelection();
    const c = state.analysis.template.clusters[Number(el.dataset.c)];
    if (sel && !sel.isCollapsed && el.contains(sel.anchorNode) && el.contains(sel.focusNode)) {
      const range = sel.getRangeAt(0);
      let start = offsetIn(el, range.startContainer, range.startOffset);
      let end = offsetIn(el, range.endContainer, range.endOffset);
      const line = sampleOf(c);
      // trim surrounding whitespace from the selection
      while (start < end && /\s/.test(line[start])) start++;
      while (end > start && /\s/.test(line[end - 1])) end--;
      if (end <= start) return;
      const value = line.slice(start, end);
      const guess = TPL().suggestSpanName(line, start, end, usedNames());
      openPop(
        range.getBoundingClientRect(),
        `<div class="pop-title">New field</div>
         <div class="pop-value mono">${esc(U.truncate(value, 120))}</div>
         <label class="pop-label">Field name <span class="hint">${esc(W.types.info(guess.type).label)}</span></label>
         <input class="input mono" value="${esc(guess.name)}" spellcheck="false">
         <div class="pop-actions">
           <button class="btn btn-primary btn-sm" type="button" data-act="primary">Add field</button>
           <button class="btn btn-ghost btn-sm" type="button" data-act="wild" title="The text varies but is not extracted">Wildcard</button>
           <span class="spacer"></span>
           <button class="btn btn-ghost btn-sm" type="button" data-act="cancel">Cancel</button>
         </div>`,
        (act, name) => {
          if (act === 'cancel') return closePop();
          const clean = U.sanitizeFieldName(name) || guess.name;
          const man = manualOf(c);
          TPL().addSpan(man, { start, end, name: clean, capture: act !== 'wild', type: guess.type });
          sel.removeAllRanges();
          closePop();
          afterBuilderChange();
        }
      );
      return;
    }
    // plain click on a highlighted field: edit it
    const hl = e.target.closest('.bl-hl');
    if (!hl) return;
    const start = Number(hl.dataset.start);
    const end = Number(hl.dataset.end);
    const man0 = c.manual;
    const shown = displaySpans(c).find((s) => s.start === start && s.end === end);
    if (!shown) return;
    const f = state.analysis.fields.find((x) => x.group === 'template' && x.hint.cluster === c.id && (man0 ? x.hint.span === shown.id : x.hint.pos === shown.pos));
    const currentName = f ? f.name : shown.name;
    openPop(
      hl.getBoundingClientRect(),
      `<div class="pop-title">Field</div>
       <div class="pop-value mono">${esc(U.truncate(sampleOf(c).slice(start, end), 120))}</div>
       <label class="pop-label">Field name</label>
       <input class="input mono" value="${esc(currentName)}" spellcheck="false">
       <label class="check"><input type="checkbox" data-role="capture" ${shown.capture ? 'checked' : ''}> Extract this value (unticked: wildcard)</label>
       <div class="pop-actions">
         <button class="btn btn-primary btn-sm" type="button" data-act="primary">Save</button>
         <button class="btn btn-ghost btn-sm" type="button" data-act="remove" title="Treat this text as a literal again">Remove</button>
         <span class="spacer"></span>
         <button class="btn btn-ghost btn-sm" type="button" data-act="cancel">Cancel</button>
       </div>`,
      (act, name, p) => {
        if (act === 'cancel') return closePop();
        const man = manualOf(c);
        const s = man.spans.find((x) => x.start === start && x.end === end);
        if (!s) return closePop();
        if (act === 'remove') TPL().removeSpan(man, s.id);
        else {
          s.name = U.sanitizeFieldName(name) || s.name;
          s.capture = $('input[data-role="capture"]', p).checked;
        }
        closePop();
        afterBuilderChange();
      }
    );
  }

  function onBuilderClick(e) {
    const b = e.target.closest('[data-act]');
    if (!b || !state.analysis || !b.closest('.bl-head, .bl-label')) return;
    const c = state.analysis.template.clusters[Number(b.dataset.c)];
    if (b.dataset.act === 'reset') {
      delete c.manual;
      afterBuilderChange();
    } else if (b.dataset.act === 'clear') {
      manualOf(c).spans = [];
      afterBuilderChange();
    } else if (b.dataset.act === 'copy-re') {
      copyText(TPL().clusterRegex(c, settings().mode).pattern, b);
    }
  }

  function initBuilder() {
    const box = $('#templateEditor');
    box.addEventListener('mouseup', (e) => setTimeout(() => onSampleMouseUp(e), 0));
    box.addEventListener('click', onBuilderClick);
    document.addEventListener('mousedown', (e) => {
      if (pop && !pop.hidden && !pop.contains(e.target)) closePop();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closePop();
    });
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

  function resetSession() {
    closeCombo();
    Object.assign(state, { analysis: null, model: null, rules: null, verdict: null, custom: null, line: 0, sampleName: '' });
    $('#logs').value = '';
    $('#decoderName').value = '';
    $('#decoderName').placeholder = 'e.g. trendmicro-apex';
    $('#decoderName').classList.remove('is-invalid');
    $('#prematchInput').value = '';
    $('#formatSelect').value = 'auto';
    $('#customXml').value = '';
    $('#fieldFilter').value = '';
    setRadio('testSource', 'generated');
    setRadio('deployView', 'decoder');
    $('#deployDecoder').hidden = false;
    $('#deployRules').hidden = true;
    $('#nextBtn').classList.remove('pulse');
    if (location.search) history.replaceState(null, '', location.pathname);
    updateLineCount();
    render();
    goStep(1);
    $('#logs').focus();
    toast('Fresh session');
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
      if (state.analysis) $('#nextBtn').classList.add('pulse');
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
    fb.addEventListener('input', (e) => {
      onFieldsInput(e);
      if (combo && e.target === combo.input) {
        combo.typed = true;
        combo.active = -1;
        renderCombo();
      }
    });
    fb.addEventListener('focusin', (e) => {
      if (e.target.matches('.name-cell input.input')) openCombo(e.target);
    });
    fb.addEventListener('click', (e) => {
      if (e.target.matches('.name-cell input.input') && (!combo || combo.input !== e.target)) openCombo(e.target);
    });
    fb.addEventListener('focusout', (e) => {
      if (combo && e.target === combo.input) closeCombo();
    });
    fb.addEventListener('keydown', onComboKey, true);
    window.addEventListener('scroll', () => combo && renderCombo(), true);
    window.addEventListener('resize', () => combo && renderCombo());
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
    initBuilder();

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

    // display size
    $$('input[name="uiScale"]').forEach((el) =>
      el.addEventListener('change', () => {
        document.documentElement.style.setProperty('--ui-scale', radio('uiScale'));
        saveSettings();
      })
    );

    // home: start a fresh session (settings and custom mapping are kept)
    const confirmDlg = $('#confirmDialog');
    $('#homeBtn').addEventListener('click', () => {
      if (!state.analysis && !$('#logs').value.trim()) {
        resetSession();
        return;
      }
      confirmDlg.returnValue = '';
      confirmDlg.showModal();
    });
    confirmDlg.addEventListener('close', () => {
      if (confirmDlg.returnValue === 'ok') resetSession();
    });

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
