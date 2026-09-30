/*
 * Value type inference. Every sample value is classified into the most
 * specific type; a field's type is the most specific type that covers all of
 * its non-empty samples (walking up the lattice below when they disagree).
 *
 * Each type carries a strict PCRE2 capture body used in "strict" capture mode,
 * and a hint used for naming / static-field suggestions / lint checks.
 */
WDG_MODULE(function (W) {
  'use strict';

  const IPV4 = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  const IPV6 = /^(?=.*:)(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9A-Fa-f]{0,4}|(?:\d{1,3}\.){3}\d{1,3})(?:%\w+)?$/;

  // Ordered: first match wins. `parent` defines the generalisation lattice.
  const TYPES = [
    { id: 'empty', label: 'Empty', test: (v) => v === '' || v === '-', pattern: null, parent: null },
    { id: 'ipv4', label: 'IPv4', test: (v) => IPV4.test(v), pattern: '\\d{1,3}(?:\\.\\d{1,3}){3}', parent: 'ip' },
    { id: 'ipv6', label: 'IPv6', test: (v) => (v.includes('::') || (v.match(/:/g) || []).length === 7) && IPV6.test(v), pattern: '[0-9A-Fa-f:.%]*:[0-9A-Fa-f:.%]*', parent: 'ip' },
    { id: 'ip', label: 'IP address', test: () => false, pattern: '[0-9A-Fa-f:.%]+', parent: 'token' },
    { id: 'ipport', label: 'IP:port', test: (v) => /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/.test(v), pattern: '\\d{1,3}(?:\\.\\d{1,3}){3}:\\d{1,5}', parent: 'token' },
    { id: 'mac', label: 'MAC address', test: (v) => /^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$|^(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$/.test(v), pattern: '[0-9A-Fa-f]{2}(?:[:.-]?[0-9A-Fa-f]{2}){5}', parent: 'token' },
    { id: 'uuid', label: 'UUID', test: (v) => /^\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?$/.test(v), pattern: '\\{?[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\\}?', parent: 'token' },
    { id: 'sha256', label: 'SHA-256', test: (v) => /^[0-9A-Fa-f]{64}$/.test(v), pattern: '[0-9A-Fa-f]{64}', parent: 'hash' },
    { id: 'sha1', label: 'SHA-1', test: (v) => /^[0-9A-Fa-f]{40}$/.test(v), pattern: '[0-9A-Fa-f]{40}', parent: 'hash' },
    { id: 'md5', label: 'MD5', test: (v) => /^[0-9A-Fa-f]{32}$/.test(v), pattern: '[0-9A-Fa-f]{32}', parent: 'hash' },
    { id: 'hash', label: 'Hash', test: () => false, pattern: '[0-9A-Fa-f]{32,128}', parent: 'token' },
    { id: 'epoch', label: 'Epoch time', test: (v) => /^1\d{9}(?:\d{3}|\.\d{1,6})?$/.test(v), pattern: '\\d{10}(?:\\d{3}|\\.\\d{1,6})?', parent: 'number' },
    { id: 'integer', label: 'Integer', test: (v) => /^[-+]?\d{1,18}$/.test(v), pattern: '[-+]?\\d+', parent: 'number' },
    { id: 'number', label: 'Number', test: (v) => /^[-+]?(?:\d+\.\d*|\.\d+|\d+)(?:[eE][-+]?\d+)?$/.test(v), pattern: '[-+]?\\d*\\.?\\d+(?:[eE][-+]?\\d+)?', parent: 'token' },
    { id: 'hex', label: 'Hex', test: (v) => /^0x[0-9A-Fa-f]+$/.test(v), pattern: '0x[0-9A-Fa-f]+', parent: 'token' },
    { id: 'bool', label: 'Boolean', test: (v) => /^(?:true|false|yes|no|on|off)$/i.test(v), pattern: '[A-Za-z]+', parent: 'token' },
    { id: 'iso8601', label: 'ISO-8601 time', test: (v) => /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?$/.test(v), pattern: '\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}(?::\\d{2}(?:[.,]\\d+)?)?(?:Z|[+-]\\d{2}:?\\d{2})?', parent: 'timestamp' },
    { id: 'syslogtime', label: 'Syslog time', test: (v) => /^[A-Z][a-z]{2} {1,2}\d{1,2}(?: \d{4})? \d{2}:\d{2}:\d{2}/.test(v), pattern: '[A-Z][a-z]{2} {1,2}\\d{1,2}(?: \\d{4})? \\d{2}:\\d{2}:\\d{2}', parent: 'timestamp' },
    { id: 'date', label: 'Date', test: (v) => /^\d{4}[-/]\d{1,2}[-/]\d{1,2}$|^\d{1,2}[-/]\d{1,2}[-/]\d{2,4}$/.test(v), pattern: '\\d{1,4}[-/]\\d{1,2}[-/]\\d{1,4}', parent: 'token' },
    { id: 'time', label: 'Time', test: (v) => /^\d{1,2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?$/.test(v), pattern: '\\d{1,2}:\\d{2}(?::\\d{2}(?:[.,]\\d+)?)?', parent: 'token' },
    { id: 'ctime', label: 'Timestamp (ctime)', test: (v) => /^[A-Z][a-z]{2} [A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4}$/.test(v), pattern: null, parent: 'timestamp' },
    { id: 'httpdate', label: 'HTTP date', test: (v) => /^\d{2}\/[A-Z][a-z]{2}\/\d{4}:\d{2}:\d{2}:\d{2}(?: [+-]\d{4})?$/.test(v), pattern: null, parent: 'timestamp' },
    { id: 'timestamp', label: 'Timestamp', test: () => false, pattern: null, parent: 'text' },
    { id: 'email', label: 'E-mail', test: (v) => /^[^\s@]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(v), pattern: '[^\\s@]+@[A-Za-z0-9.-]+', parent: 'token' },
    { id: 'url', label: 'URL', test: (v) => /^[A-Za-z][A-Za-z0-9+.-]{1,15}:\/\/\S+$/.test(v), pattern: '[A-Za-z][A-Za-z0-9+.-]*://\\S+', parent: 'token' },
    { id: 'winpath', label: 'Windows path', test: (v) => /^(?:[A-Za-z]:\\|\\\\)[^\n]*$/.test(v), pattern: null, parent: 'text' },
    { id: 'unixpath', label: 'Unix path', test: (v) => /^\/[^\s]*$/.test(v) && v.length > 1, pattern: '/\\S*', parent: 'token' },
    { id: 'domainuser', label: 'DOMAIN\\user', test: (v) => /^[\w.-]+\\[\w.$-]+$/.test(v), pattern: '[\\w.-]+\\\\[\\w.$-]+', parent: 'token' },
    { id: 'useragent', label: 'User agent', test: (v) => /^(?:Mozilla|curl|Wget|python-requests|Go-http-client|okhttp|Java|Apache-HttpClient|PostmanRuntime|Opera|Dalvik)\//.test(v), pattern: null, parent: 'text' },
    { id: 'filename', label: 'File name', test: (v) => /^[^\\/\s:*?"<>|]+\.(?:exe|dll|sys|bat|cmd|ps1|psm1|vbs|js|jar|msi|scr|inf|lnk|hta|py|sh|pl|rb|php|aspx?|jsp|html?|xml|json|ya?ml|csv|txt|log|ini|cfg|conf|tmp|bak|zip|rar|7z|gz|tgz|tar|iso|img|docx?|xlsx?|xlsm|pptx?|pdf|rtf|odt|png|jpe?g|gif|bmp|svg|mp[34]|avi|mov|xmr|dat|db|sql|key|pem|crt|cer)$/i.test(v), pattern: '[^\\s/\\\\]+', parent: 'token' },
    { id: 'fqdn', label: 'Hostname / FQDN', test: (v) => /^(?=.*[A-Za-z])[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}\.)+[A-Za-z]{2,63}\.?$/.test(v), pattern: '[A-Za-z0-9.-]+', parent: 'token' },
    { id: 'word', label: 'Word', test: (v) => /^[A-Za-z_][\w.-]*$/.test(v), pattern: '[\\w.-]+', parent: 'token' },
    { id: 'token', label: 'Token (no spaces)', test: (v) => !/\s/.test(v), pattern: '\\S+', parent: 'text' },
    { id: 'httprequest', label: 'HTTP request line', test: (v) => /^[A-Z]{3,10} \S+ HTTP\/[\d.]+$/.test(v), pattern: null, parent: 'text' },
    { id: 'text', label: 'Free text', test: () => true, pattern: null, parent: null },
  ];

  const BY_ID = Object.fromEntries(TYPES.map((t) => [t.id, t]));

  function classify(value) {
    const v = String(value);
    for (const t of TYPES) {
      if (t.test(v)) return t.id;
    }
    return 'text';
  }

  function ancestors(id) {
    const out = [];
    let cur = id;
    while (cur) {
      out.push(cur);
      cur = BY_ID[cur] ? BY_ID[cur].parent : null;
    }
    return out;
  }

  /** Lowest common ancestor of two type ids in the lattice. */
  function join(a, b) {
    if (a === b) return a;
    if (a === 'empty') return b;
    if (b === 'empty') return a;
    const aa = ancestors(a);
    for (const x of ancestors(b)) {
      if (aa.includes(x)) return x;
    }
    return 'text';
  }

  /** Infer a field's type from its sample values. */
  function inferType(samples) {
    let t = 'empty';
    for (const s of samples) t = join(t, classify(s));
    return t;
  }

  function info(id) {
    return BY_ID[id] || BY_ID.text;
  }

  /** True when the type can never contain whitespace. */
  function isToken(id) {
    return ancestors(id).includes('token');
  }

  W.types = { TYPES, classify, inferType, join, info, isToken, ancestors };
});
