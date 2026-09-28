/*
 * Faithful emulation of Wazuh's pre-decoding phase (analysisd/cleanevent.c,
 * OS_CleanMSG, v4.x).
 *
 * Why this matters: when the pre-decoder extracts a program_name, Wazuh only
 * evaluates decoders that declare <program_name>; decoders that rely on a
 * <prematch> alone are never tried. And the body the decoders see (lf->log)
 * starts *after* the program name. A classic trap:
 *
 *   "Aug 23 11:30:15 host CEF:0|Vendor|Product|..."
 *     → program_name = "CEF", log = "0|Vendor|Product|..."
 *
 * so a decoder with <prematch>CEF:0</prematch> silently never matches.
 */
WDG_MODULE(function (W) {
  'use strict';

  // hostname_map from os_regex/os_regex_maps.c (isValidChar() == 1)
  const isValidChar = (c) => c !== undefined && /[A-Za-z0-9()\-./@_]/.test(c);
  const isDigit = (c) => c !== undefined && c >= '0' && c <= '9';
  const isAlnum = (c) => c !== undefined && /[A-Za-z0-9]/.test(c);
  const isLower = (c) => c !== undefined && c >= 'a' && c <= 'z';

  /** Offset of the syslog-style timestamp, or -1 (mirrors the big if-chain). */
  function syslogTimestampOffset(p) {
    const loglen = p.length + 1;
    const at = (i) => p[i];

    // "Dec 29 10:00:01 "
    if (loglen > 17 && at(3) === ' ' && at(6) === ' ' && at(9) === ':' && at(12) === ':' && at(15) === ' ') return 16;
    // "2015-04-16 21:51:02,805 "
    if (loglen > 24 && at(4) === '-' && at(7) === '-' && at(10) === ' ' && at(13) === ':' && at(16) === ':' && at(19) === ',') return 24;
    // ISO 8601 with 'T'
    if (loglen > 33 && at(4) === '-' && at(7) === '-' && at(10) === 'T' && at(13) === ':' && at(16) === ':') {
      if (at(22) === ':' && at(25) === ' ') return 26;
      if (at(19) === '.') {
        if (at(26) === ':') return 30;
        if (at(29) === ':') return 33;
        return 32;
      }
    }
    // "2015 Dec 29 10:00:01 "
    if (loglen > 21 && isDigit(at(0)) && at(4) === ' ' && at(8) === ' ' && at(11) === ' ' && at(14) === ':' && at(17) === ':' && at(20) === ' ') return 21;
    // macOS ULS "2021-04-21 10:16:09.404756-0700 "
    if (
      loglen > 33 && isDigit(at(0)) && at(4) === '-' && at(7) === '-' && at(10) === ' ' && at(13) === ':' &&
      at(16) === ':' && at(19) === '.' && (at(26) === '-' || at(26) === '+') && at(31) === ' '
    ) return 32;
    return -1;
  }

  /**
   * @param {string} raw        the log line as received
   * @param {object} [opts]
   * @param {boolean} [opts.stripPri=true]  remove a leading "<PRI>" (wazuh-remoted
   *        strips it for logs received over syslog; logs read from a file keep it)
   */
  function predecode(raw, opts) {
    const o = Object.assign({ stripPri: true }, opts);
    const res = {
      raw,
      pri: null,
      timestamp: null,
      hostname: null,
      program_name: null,
      log: raw,
      header: 'none', // none | syslog | syslog-no-program | xferlog | snort | suricata | apache | squid
    };

    let p = raw;
    if (o.stripPri) {
      const m = /^<(\d{1,3})>/.exec(p);
      if (m) {
        res.pri = Number(m[1]);
        p = p.slice(m[0].length);
      }
    }
    res.log = p;

    const off = syslogTimestampOffset(p);
    if (off > 0) {
      res.header = 'syslog';
      res.timestamp = p.slice(0, off - 1);
      let log = p.slice(off);
      if (log[0] === ' ') log = log.slice(1);
      res.log = log;

      let i = 0;
      while (isValidChar(log[i])) i++;

      if (log[i] === ':' && log[i + 1] === ' ') {
        // Solaris-style: no hostname, "program: msg"
        res.program_name = log.slice(0, i);
        res.log = log.slice(i + 2);
        return res;
      }
      if (log[i] !== ' ') {
        // invalid hostname: log stays right after the timestamp
        res.header = 'syslog-no-program';
        return res;
      }

      res.hostname = log.slice(0, i);
      const rest = log.slice(i + 1);
      res.log = rest;

      let j = 0;
      while (isValidChar(rest[j])) j++;
      let k = -1;
      let pname = null;

      if (rest[j] === ':') {
        pname = rest.slice(0, j);
        k = j + 1;
        if (rest[k] === ' ') k++;
      } else if (rest[j] === '[' && isDigit(rest[j + 1])) {
        let q = j + 2;
        while (isDigit(rest[q])) q++;
        if (rest[q] === ']' && rest[q + 1] === ':') {
          pname = rest.slice(0, j);
          k = q + 2;
          if (rest[k] === ' ') k++;
        } else if (rest[q] === ']' && rest[q + 1] === ' ') {
          pname = rest.slice(0, j);
          k = q + 2;
        }
      } else if (rest[j] === '|' && isLower(rest[j + 1])) {
        // AIX: "auth|security:info p_name: msg"
        let q = j + 2;
        while (isAlnum(rest[q])) q++;
        if (rest[q] === ':') {
          q++;
          while (isAlnum(rest[q])) q++;
          if (rest[q] === ' ') {
            q++;
            const start = q;
            while (isValidChar(rest[q])) q++;
            if (rest[q] === ':' && rest[q + 1] === ' ') {
              pname = rest.slice(start, q);
              k = q + 2;
            } else if (rest[q] === '[' && isDigit(rest[q + 1])) {
              const nameEnd = q;
              q += 2;
              while (isDigit(rest[q])) q++;
              if (rest[q] === ']' && rest[q + 1] === ':' && rest[q + 2] === ' ') {
                pname = rest.slice(start, nameEnd);
                k = q + 3;
              }
            }
          }
        }
      }

      if (pname === null || k < 0) {
        res.header = 'syslog-no-program';
        return res;
      }

      res.program_name = pname;
      let body = rest.slice(k);
      // Remove "[ID xx facility.severity] "
      if (body.startsWith('[ID ')) {
        const close = body.indexOf(']', 4);
        if (close >= 0) body = body.slice(close + 2);
      }
      res.log = body;
      return res;
    }

    const loglen = p.length + 1;
    const at = (i) => p[i];

    // xferlog: "Mon Apr 17 18:27:14 2006 1 64.160.42.130"
    if (loglen > 28 && at(3) === ' ' && at(7) === ' ' && at(10) === ' ' && at(13) === ':' && at(16) === ':' && at(19) === ' ' && at(24) === ' ' && at(26) === ' ') {
      res.header = 'xferlog';
      res.timestamp = p.slice(0, 24);
      res.log = p.slice(25);
      return res;
    }
    // snort: "01/28-09:13:16.240702  [**]"
    if (loglen > 24 && at(2) === '/' && at(5) === '-' && at(8) === ':' && at(11) === ':' && at(14) === '.' && at(21) === ' ') {
      res.header = 'snort';
      res.timestamp = p.slice(0, 21);
      res.log = p.slice(23);
      return res;
    }
    // suricata: "01/28/1979-09:13:16.240702  [**]"
    if (loglen > 26 && at(2) === '/' && at(5) === '/' && at(10) === '-' && at(13) === ':' && at(16) === ':' && at(19) === '.' && at(26) === ' ') {
      res.header = 'suricata';
      res.timestamp = p.slice(0, 26);
      res.log = p.slice(28);
      return res;
    }
    // apache: "[Fri Feb 11 18:06:35 2004] [warn]"
    if (loglen > 27 && at(0) === '[' && at(4) === ' ' && at(8) === ' ' && at(11) === ' ' && at(14) === ':' && at(17) === ':' && at(20) === ' ' && at(25) === ']') {
      res.header = 'apache';
      res.timestamp = p.slice(1, 25);
      res.log = p.slice(27);
      return res;
    }
    // squid: "1140804070.368  11623"
    if (
      loglen > 32 && at(0) === '1' && isDigit(at(1)) && isDigit(at(2)) && isDigit(at(3)) && at(10) === '.' &&
      isDigit(at(13)) && at(14) === ' ' && (at(21) === ' ' || at(22) === ' ')
    ) {
      res.header = 'squid';
      res.timestamp = p.slice(0, 14);
      let log = p.slice(14);
      log = log.replace(/^ +/, '');
      res.log = log;
      return res;
    }
    return res;
  }

  W.predecode = predecode;
  W.predecoder = { predecode, isValidChar };
});
