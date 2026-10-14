'use strict';

/* ============================================================================
 * Phishing Email Analyser — analysis engine
 * ----------------------------------------------------------------------------
 * Everything in this file runs inside the visitor's browser.
 * NO network requests, no storage, no analytics, no external services.
 * The email text you paste never leaves your device.
 * ==========================================================================*/

/* ---------- small helpers ------------------------------------------------ */

// Find matching phrases in the text so we can show the user exactly which
// words triggered a rule (this is what makes the score explainable).
function matchPhrases(text, patterns) {
  const hits = [];
  for (const pattern of patterns) {
    const all = text.match(pattern);
    if (all) {
      for (const hit of all) {
        const clean = String(hit).trim();
        if (clean && !hits.some(h => h.toLowerCase() === clean.toLowerCase())) {
          hits.push(clean);
        }
      }
    }
  }
  return hits.slice(0, 3);
}

/* ---------- URL helpers -------------------------------------------------- */

const URL_REGEX = /https?:\/\/[^\s<>"'“”‘’)\]]+/gi;
const WWW_REGEX = /\bwww\.[a-z0-9-]+(?:\.[a-z0-9-]+)+\b/gi;

function cleanUrl(url) {
  return url.replace(/[.,;:!?]+$/, '');
}

function hostOf(url) {
  try {
    return new URL(url.startsWith('http') ? url : 'http://' + url).hostname.toLowerCase();
  } catch (e) {
    return '';
  }
}

// Naive "last two labels" rule — good enough for an educational tool.
function baseDomain(host) {
  const labels = String(host).split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  return labels.slice(-2).join('.');
}

function extractUrls(text) {
  const found = [];
  const seen = new Set();
  const spans = [];
  for (const m of text.matchAll(URL_REGEX)) {
    const raw = cleanUrl(m[0]);
    const key = raw.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      found.push({ raw, index: m.index, host: hostOf(raw) });
    }
    spans.push([m.index, m.index + m[0].length]);
  }
  for (const m of text.matchAll(WWW_REGEX)) {
    const inOtherUrl = spans.some(([a, b]) => m.index >= a && m.index < b);
    if (inOtherUrl) continue;
    const raw = cleanUrl(m[0]);
    const key = raw.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      found.push({ raw, index: m.index, host: hostOf(raw) });
    }
  }
  return found;
}

/* ---------- email header helpers ------------------------------------------ */

const ADDRESS_REGEX = /[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/;

function extractHeaderValue(headersBlock, name) {
  const re = new RegExp('^' + name + ':\\s*(.+)$', 'im');
  const m = headersBlock.match(re);
  return m ? m[1].trim() : null;
}

function parseAddress(value) {
  if (!value) return null;
  const angle = value.match(/<([^>]+)>/);
  const bare = value.match(ADDRESS_REGEX);
  const addr = angle ? angle[1] : (bare ? bare[0] : null);
  if (!addr) return null;
  const parts = addr.split('@');
  const domain = parts[1] ? parts[1].toLowerCase() : '';
  const displayMatch = value.match(/^\s*"?([^"<]+?)"?\s*(?:<|$)/);
  const display = displayMatch ? displayMatch[1].trim() : '';
  return { addr: addr.toLowerCase(), domain, display };
}

function parseHeaders(text) {
  const lines = text.split(/\r?\n/);
  const raw = [];
  for (const line of lines) {
    if (raw.length === 0 && line.trim() === '') continue;  // skip leading blanks
    if (line.trim() === '') break;                          // blank line ends headers
    if (/^[A-Za-z][A-Za-z0-9-]*:\s?/.test(line)) { raw.push(line); continue; }
    if (raw.length && /^\s/.test(line)) { raw.push(line); continue; } // folded line
    break;
  }
  if (raw.length < 2) return null; // needs at least a couple of header lines

  // Re-assemble folded header lines (continuations start with whitespace).
  let joined = '';
  for (const l of raw) {
    if (/^\s/.test(l) && joined) joined += ' ' + l.trim();
    else { if (joined) joined += '\n'; joined += l; }
  }

  const from = parseAddress(extractHeaderValue(joined, 'From'));
  const replyTo = parseAddress(extractHeaderValue(joined, 'Reply-To'));

  const auth = {};
  for (const mech of ['spf', 'dkim', 'dmarc']) {
    const re = new RegExp(mech + '=(pass|fail|none|softfail|neutral|temperror|permerror)', 'i');
    const m = joined.match(re);
    auth[mech] = m ? m[1].toLowerCase() : null;
  }
  // Some mail systems report SPF in a separate "Received-SPF:" header instead.
  if (!auth.spf) {
    const m = joined.match(/^Received-SPF:\s*(\w+)/im);
    if (m) auth.spf = m[1].toLowerCase();
  }

  return { from, replyTo, auth, block: joined };
}

/* ---------- well-known brands abused by phishers -------------------------- */

const BRANDS = [
  { name: 'Microsoft 365', keys: ['microsoft', 'office', 'm365', 'o365'], re: /\b(?:microsoft|office\s*365|m365|o365)\b/i },
  { name: 'PayPal', keys: ['paypal'], re: /\bpaypal\b/i },
  { name: 'Apple / iCloud', keys: ['apple', 'icloud'], re: /\b(?:apple|icloud)\b/i },
  { name: 'Google / Gmail', keys: ['google', 'gmail'], re: /\b(?:google|gmail)\b/i },
  { name: 'Amazon', keys: ['amazon'], re: /\bamazon\b/i },
  { name: 'Netflix', keys: ['netflix'], re: /\bnetflix\b/i },
  { name: 'DHL', keys: ['dhl'], re: /\bdhl\b/i },
  { name: 'FedEx', keys: ['fedex'], re: /\bfedex\b/i },
  { name: 'UPS', keys: ['ups'], re: /\bUPS\b/ },
  { name: 'DocuSign', keys: ['docusign'], re: /\bdocusign\b/i },
  { name: 'Dropbox', keys: ['dropbox'], re: /\bdropbox\b/i },
  { name: 'HMRC', keys: ['hmrc'], re: /\bhmrc\b/i },
  { name: 'IRS', keys: ['irs'], re: /\birs\b/i },
  { name: 'Barclays', keys: ['barclays'], re: /\bbarclays\b/i },
  { name: 'Chase Bank', keys: ['chase'], re: /\bchase\s+bank\b/i },
  { name: 'Santander', keys: ['santander'], re: /\bsantander\b/i },
  { name: 'NatWest', keys: ['natwest'], re: /\bnatwest\b/i },
  { name: 'LinkedIn', keys: ['linkedin'], re: /\blinkedin\b/i },
  { name: 'WhatsApp', keys: ['whatsapp'], re: /\bwhatsapp\b/i },
  { name: 'Coinbase', keys: ['coinbase'], re: /\bcoinbase\b/i }
];

/* ---------- detection rules (the heart of the analyser) -------------------
 * Each rule has:
 *   name      – shown to the user
 *   category  – language | links | attachments | headers
 *   points    – fixed amount added to the score when it fires
 *   why       – plain-English explanation of why this matters
 *   test()    – returns evidence strings, or [] if nothing matched
 *---------------------------------------------------------------------- */

const INDICATORS = [
  {
    id: 'urgency',
    name: 'Urgency and pressure language',
    category: 'language',
    points: 12,
    why: 'Pressure tactics push you to act before you can think clearly or verify the request. Legitimate organisations normally give you reasonable time.',
    test: (text) => matchPhrases(text, [
      /\bact now\b/i,
      /\bimmediately\b/i,
      /\burgently?\b/i,
      /within\s+\d+\s+hours?\b/i,
      /within\s+\d+\s+days?\b/i,
      /\bexpires?\b/i,
      /\bexpir(?:ation|y)\b/i,
      /limited[-\s]?time\b/i,
      /\bhurry\b/i,
      /do(?:n't| not)\s+delay\b/i,
      /\bfinal notice\b/i,
      /\blast warning\b/i,
      /time[-\s]?sensitive\b/i,
      /as soon as possible\b/i,
      /\bimmediate attention\b/i,
      /\baction required\b/i
    ])
  },
  {
    id: 'threats',
    name: 'Threats of suspension, closure or penalties',
    category: 'language',
    points: 15,
    why: 'Fear of losing access, money or standing is one of the oldest phishing tricks. Real banks rarely threaten you by email first.',
    test: (text) => matchPhrases(text, [
      /(?:account|access|mailbox)[^.!?\n]{0,50}\b(?:will be|shall be)?\s*(?:suspend\w*|deactivat\w*|block\w*|lock\w*|disab\w*|clos\w*|terminat\w*|restrict\w*)/i,
      /\b(?:suspend\w*|deactivat\w*|clos\w*|terminat\w*|delet\w*)\b[^.!?\n]{0,40}\b(?:account|mailbox|access)\b/i,
      /\blegal action\b/i,
      /\bunauthori[sz]ed\b[^.!?\n]{0,30}\b(?:activit|access|log[-\s]?in|transaction)/i,
      /failure to (?:comply|respond|verify|confirm|act|reply)\b/i,
      /\b(?:penalt|fine)s?\b[^.!?\n]{0,40}\b(?:apply|applied|imposed|legal|prosecut)/i,
      /\bprosecution\b/i,
      /\bcollections?\s+(?:action|department|agency|process)\b/i,
      /permanent(?:ly)?\s+(?:clos\w*|block\w*|suspend\w*|delet\w*)/i
    ])
  },
  {
    id: 'password_request',
    name: 'Request for your password',
    category: 'language',
    points: 20,
    why: 'Genuine organisations do not ask you to send or confirm your password by email. This is a direct attempt to steal your login.',
    test: (text) => matchPhrases(text, [
      /\b(?:your|the)\s+password\b/i,
      /confirm\s+(?:your|the)\s+password\b/i,
      /enter\s+(?:your|the)\s+password\b/i,
      /provide\s+(?:your|the)\s+password\b/i,
      /password\s*:/i,
      /\blog[-\s]?in\s+(?:credentials|details)\b/i,
      /\bsign[-\s]?in\s+credentials\b/i,
      /\baccount credentials\b/i,
      /\busername and password\b/i,
      /\bemail (?:address and )?password\b/i,
      /update\s+(?:your|the)\s+password\b/i
    ])
  },
  {
    id: 'mfa_code_request',
    name: 'Request for an MFA / verification code',
    category: 'language',
    points: 20,
    why: 'Your one-time codes are the last line of defence on your accounts. Sharing one lets an attacker complete a login they have already started.',
    test: (text) => matchPhrases(text, [
      /verifi?cation\s+code\b/i,
      /\bsecurity\s+code\b/i,
      /one[-\s]?time\s+(?:code|password|passcode|pin)\b/i,
      /\botp\b/i,
      /\b(?:mfa|2fa|two[-\s]?factor)\s+code\b/i,
      /\bauthentication\s+code\b/i,
      /\blogin\s+code\b/i,
      /confirm\s+(?:the|this|your)\s+code\b/i,
      /enter\s+the\s+code\b/i,
      /code\s+we\s+(?:sent|texted)\b/i,
      /\bsms\s+code\b/i
    ])
  },

  {
    id: 'payment_request',
    name: 'Payment, gift-card or money request',
    category: 'language',
    points: 15,
    why: 'Asking for wire transfers, gift cards or crypto is a common end-goal of scams. Gift cards in particular are a favourite of fraudsters because they are hard to trace.',
    test: (text) => matchPhrases(text, [
      /gift\s?cards?\b/i,
      /\bitunes\b/i,
      /amazon\s+(?:voucher|gift)/i,
      /google\s+play\s+(?:card|credit)/i,
      /steam\s+(?:card|wallet)/i,
      /\bwire\s+transfer\b/i,
      /\bbank\s+transfer\b/i,
      /\bwestern\s+union\b/i,
      /\bbitcoin\b/i,
      /\bbtc\b/i,
      /\bcrypto(?:currency)?\b/i,
      /\bethereum\b/i,
      /\bprepaid\s+cards?\b/i,
      /make\s+(?:a|the|this)?\s*payment\b/i,
      /process\s+(?:the|this|a)?\s*payment\b/i,
      /pay\s+(?:now|online|immediately|within)\b/i,
      /\bcustoms\s+(?:fee|charge|payment)\b/i,
      /\bdelivery\s+(?:fee|charge)\b/i,
      /outstanding\s+(?:fee|balance|amount|payment)\b/i,
      /payment\s+(?:is\s+)?(?:now\s+)?(?:due|overdue|required|pending)\b/i,
      /settle\s+(?:the|this|an)?\s*invoice\b/i
    ])
  },
  {
    id: 'bank_change',
    name: 'Request to change bank / payment details',
    category: 'language',
    points: 18,
    why: 'Fraudsters redirect payments by swapping in their own bank details. Genuine companies announce bank changes through official channels, not a surprise email.',
    test: (text) => matchPhrases(text, [
      /\bbank\s+details\b/i,
      /\bbank\s+account\s+details\b/i,
      /\bnew\s+(?:bank|payment)\s+details\b/i,
      /\bupdated\s+bank\s+details\b/i,
      /change\s+of\s+(?:bank|payment)\s+details\b/i,
      /\baccount\s+number\b/i,
      /\bsort\s+code\b/i,
      /\biban\b/i,
      /\brouting\s+number\b/i,
      /\baccount\s+name\s*:/i,
      /\bpayment\s+instructions\b/i
    ])
  },
  {
    id: 'impersonation',
    name: 'Impersonation of a well-known organisation',
    category: 'language',
    points: 8,
    why: 'Phishing emails borrow the trust of famous brands. Seeing a brand name is not proof of fraud, but it does mean you should double-check the sender carefully.',
    test: (text) => {
      const hits = [];
      for (const brand of BRANDS) {
        if (brand.re.test(text) && !hits.includes(brand.name)) hits.push(brand.name);
      }
      return hits.slice(0, 3);
    }
  },
  {
    id: 'credential_harvesting',
    name: 'Credential-harvesting language',
    category: 'language',
    points: 12,
    why: 'Phrases like "verify your account" invent a fake reason to collect your login details. Attackers use them because they sound official and routine.',
    test: (text) => matchPhrases(text, [
      /verify\s+(?:your|the)\s+(?:account|identity|email|mailbox|information|details)\b/i,
      /confirm\s+(?:your|the)\s+(?:account|identity|details|information)\b/i,
      /validate\s+(?:your|the)\s+account\b/i,
      /update\s+(?:your|the)\s+(?:account|information|details|profile)\b/i,
      /reactivate\s+(?:your|the)\s+account\b/i,
      /restore\s+(?:your|the)\s+account\b/i,
      /unlock\s+(?:your|the)\s+account\b/i,
      /\bun?usual\s+(?:activit\w*|sign[-\s]?in|log[-\s]?in)\b/i,
      /\bsuspicious\s+activit\w*\b/i,
      /\bwe\s+detected\b/i,
      /review\s+(?:your\s+)?recent\s+(?:activit\w*|sign[-\s]?in)\b/i,
      /confirm\s+your\s+mailbox\b/i
    ])
  },
  {
    id: 'invoice_language',
    name: 'Unexpected invoice or payment notice',
    category: 'language',
    points: 10,
    why: 'Unexpected invoices pressure accounts teams into paying quickly. Attackers attach fake invoices hoping nobody checks the supplier details.',
    test: (text) => matchPhrases(text, [
      /\binvoice\b/i,
      /\bpurchase\s+order\b/i,
      /\bpo\s+number\b/i,
      /\boutstanding\s+balance\b/i,
      /\bamount\s+due\b/i,
      /\bpayment\s+due\b/i,
      /\breceipt\b/i,
      /\boverdue\b/i,
      /unpaid\s+(?:invoice|balance|amount)\b/i,
      /\bbilling\s+(?:statement|notice)\b/i,
      /\bstatement\s+of\s+account\b/i
    ])
  },
  {
    id: 'macro_request',
    name: 'Request to enable macros / editing',
    category: 'language',
    points: 15,
    why: 'Enabling macros lets hidden code run on your computer. Real invoices do not normally need you to disable security features just to view them.',
    test: (text) => matchPhrases(text, [
      /enable\s+(?:all\s+)?macros?\b/i,
      /enable\s+content\b/i,
      /enable\s+editing\b/i,
      /macros?\s+(?:are|is)\s+disabled\b/i,
      /click\s+['"]?enable\b/i,
      /turn\s+on\s+macros?\b/i
    ])
  },

  /* ----- link rules ------------------------------------------------------- */
  {
    id: 'url_shortener',
    name: 'Shortened or masked link',
    category: 'links',
    points: 15,
    why: 'Short links hide the real destination. Attackers use them so you cannot see where a click will actually take you.',
    test: (text, ctx) => {
      const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'buff.ly', 'cutt.ly', 'rebrand.ly', 'shorturl.at', 'tiny.cc', 'lnkd.in', 'rb.gy', 's.id', 'v.gd', 'trib.al', 'soo.gd'];
      const hits = [];
      for (const u of ctx.urls) {
        if (SHORTENERS.some(s => u.host === s || u.host.endsWith('.' + s))) hits.push(u.raw);
      }
      return hits.slice(0, 3);
    }
  },
  {
    id: 'url_ip',
    name: 'Link using a raw IP address',
    category: 'links',
    points: 20,
    why: 'Real organisations use named domains, not bare IP addresses. An IP link usually means a throwaway server with no reputation to protect.',
    test: (text, ctx) => {
      const hits = [];
      for (const u of ctx.urls) {
        if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(u.host)) hits.push(u.raw);
      }
      return hits.slice(0, 3);
    }
  },
  {
    id: 'url_suspicious_tld',
    name: 'Link with a suspicious domain ending',
    category: 'links',
    points: 10,
    why: 'Certain domain endings (.xyz, .top, .click …) are cheap to register and disproportionately common in disposable phishing kits.',
    test: (text, ctx) => {
      const TLDS = ['xyz', 'top', 'click', 'link', 'loan', 'work', 'gq', 'cf', 'ml', 'tk', 'zip', 'mov'];
      const hits = [];
      for (const u of ctx.urls) {
        for (const t of TLDS) {
          if (u.host.endsWith('.' + t)) { hits.push(u.host); break; }
        }
      }
      return hits.slice(0, 3);
    }
  },
  {
    id: 'url_insecure',
    name: 'Unencrypted http:// link',
    category: 'links',
    points: 5,
    why: 'Legitimate login pages almost always use https. Plain http means anything you type on that page could be read in transit.',
    test: (text, ctx) => {
      const hits = [];
      for (const u of ctx.urls) {
        if (/^http:\/\//i.test(u.raw)) hits.push(u.raw);
      }
      return hits.slice(0, 3);
    }
  },
  {
    id: 'url_misleading',
    name: 'Misleading link text',
    category: 'links',
    points: 18,
    why: 'The visible text points somewhere different from the real destination — a classic trick to make a dangerous link look official.',
    test: (text, ctx) => {
      const hits = [];
      const labelRegex = /(?:https?:\/\/)?((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})/i;
      // Markdown style: [looks safe](http://actual-destination)
      for (const m of text.matchAll(/\[([^\]\n]{3,120})\]\((https?:\/\/[^)\s]+)\)/g)) {
        const label = m[1];
        const labelDomain = (label.match(labelRegex) || [])[1];
        const targetHost = hostOf(m[2]);
        if (labelDomain && targetHost && baseDomain(labelDomain.toLowerCase()) !== baseDomain(targetHost)) {
          hits.push('Link text shows "' + label + '" but actually points to ' + targetHost);
        }
      }
      // HTML style: <a href="actual">looks safe</a>
      for (const m of text.matchAll(/<a\s[^>]*href=["'](https?:\/\/[^"']+)["'][^>]*>([^<]{3,120})<\/a>/gi)) {
        const label = m[2].trim();
        const labelDomain = (label.match(labelRegex) || [])[1];
        const targetHost = hostOf(m[1]);
        if (labelDomain && targetHost && baseDomain(labelDomain.toLowerCase()) !== baseDomain(targetHost)) {
          hits.push('Link text shows "' + label + '" but actually points to ' + targetHost);
        }
      }
      // "@ trick": http://trusted.example@evil.example
      for (const u of ctx.urls) {
        if (/^https?:\/\/[^/@\s]+@/i.test(u.raw)) {
          hits.push('Link hides its real destination behind an @ sign: ' + u.raw);
        }
      }
      return hits.slice(0, 3);
    }
  },

  /* ----- attachment rules -------------------------------------------------- */
  {
    id: 'attachment_exec',
    name: 'Executable attachment type',
    category: 'attachments',
    points: 20,
    why: 'Programs and scripts (.exe, .scr, .js, .iso …) run code on your computer. Email security teams block them for a reason — never open one you were not expecting.',
    test: (text) => {
      const re = /\b[A-Za-z0-9_-]{2,60}\.(?:exe|scr|bat|cmd|pif|vbs|vbe|js|jse|wsf|wsh|msi|jar|ps1|psm1|lnk|iso|img|apk|hta|cpl|reg)\b/gi;
      const hits = new Set();
      for (const m of text.matchAll(re)) hits.add(m[0].toLowerCase());
      return [...hits].slice(0, 3);
    }
  },
  {
    id: 'attachment_double_extension',
    name: 'Deceptive double-extension filename',
    category: 'attachments',
    points: 10,
    why: 'Names like "invoice.pdf.exe" try to look like a harmless document. The real file type is the last extension.',
    test: (text) => {
      const re = /\b[A-Za-z0-9_-]{2,60}\.(?:pdf|docx?|xlsx?|pptx?|txt|csv|jpe?g|png|gif|zip|html?|rtf|odt)\.(?:exe|scr|bat|cmd|pif|vbs|js|jar|iso|lnk|msi|com)\b/gi;
      const hits = new Set();
      for (const m of text.matchAll(re)) hits.add(m[0].toLowerCase());
      return [...hits].slice(0, 3);
    }
  },
  {
    id: 'attachment_macro_doc',
    name: 'Macro-enabled Office document',
    category: 'attachments',
    points: 15,
    why: 'Files ending .docm, .xlsm or .pptm can carry hidden macros. Combined with a request to "enable content", that is a well-known malware route.',
    test: (text) => {
      const re = /\b[A-Za-z0-9_-]{2,60}\.(?:docm|dotm|xlsm|xltm|pptm|ppsm|potm|xlsb)\b/gi;
      const hits = new Set();
      for (const m of text.matchAll(re)) hits.add(m[0].toLowerCase());
      return [...hits].slice(0, 3);
    }
  },

  /* ----- email header rules ------------------------------------------------ */
  {
    id: 'header_replyto_mismatch',
    name: 'Sender and Reply-To addresses do not match',
    category: 'headers',
    points: 18,
    why: 'If the From address and the Reply-To address use different domains, replies would go somewhere other than the apparent sender — a strong sign of forgery.',
    test: (text, ctx) => {
      const h = ctx.headers;
      if (!h || !h.from || !h.replyTo) return [];
      const fromBase = baseDomain(h.from.domain);
      const replyBase = baseDomain(h.replyTo.domain);
      if (fromBase && replyBase && fromBase !== replyBase) {
        return ['From: ' + h.from.addr + '  vs  Reply-To: ' + h.replyTo.addr];
      }
      return [];
    }
  },
  {
    id: 'header_spf_fail',
    name: 'SPF check failed',
    category: 'headers',
    points: 15,
    why: 'SPF lists the servers allowed to send mail for a domain. "fail" means this email came from a server that domain does not authorise.',
    test: (text, ctx) => (ctx.headers && ctx.headers.auth && ctx.headers.auth.spf === 'fail') ? ['Authentication-Results: spf=fail'] : []
  },
  {
    id: 'header_dkim_fail',
    name: 'DKIM check failed',
    category: 'headers',
    points: 15,
    why: 'DKIM is a cryptographic signature the real sender\'s mail server applies. A failure means the signature does not match — the email was altered or forged.',
    test: (text, ctx) => (ctx.headers && ctx.headers.auth && ctx.headers.auth.dkim === 'fail') ? ['Authentication-Results: dkim=fail'] : []
  },
  {
    id: 'header_dmarc_fail',
    name: 'DMARC check failed',
    category: 'headers',
    points: 15,
    why: 'DMARC combines SPF and DKIM and tells the receiving mail system what to do when neither passes. A fail strongly suggests the email is not legitimate.',
    test: (text, ctx) => (ctx.headers && ctx.headers.auth && ctx.headers.auth.dmarc === 'fail') ? ['Authentication-Results: dmarc=fail'] : []
  },
  {
    id: 'header_display_name_mismatch',
    name: 'Trusted name in the From label, unrelated address inside',
    category: 'headers',
    points: 12,
    why: 'The friendly name (what your mail app shows first) mentions a trusted organisation, but the actual email address belongs to an unrelated domain.',
    test: (text, ctx) => {
      const h = ctx.headers;
      if (!h || !h.from || !h.from.display || !h.from.domain) return [];
      for (const brand of BRANDS) {
        if (brand.re.test(h.from.display)) {
          if (!brand.keys.some(k => h.from.domain.includes(k))) {
            return ['Display name "' + h.from.display + '" but address domain ' + h.from.domain];
          }
        }
      }
      return [];
    }
  }
];

/* ==========================================================================
 * Core engine — pure functions (testable without a browser)
 * ========================================================================*/

function classify(score) {
  if (score >= 70) {
    return {
      key: 'high', label: 'High Risk',
      hint: 'This email contains many strong warning signs of phishing or fraud. Do not click links, open attachments or reply until the message has been verified another way.'
    };
  }
  if (score >= 30) {
    return {
      key: 'medium', label: 'Suspicious',
      hint: 'Some warning signs are present. Treat this message with caution and verify it independently before acting on it.'
    };
  }
  return {
    key: 'low', label: 'Low Risk',
    hint: 'Few or no known warning signs were found — but that is not the same as "safe". Stay alert and verify anything unexpected.'
  };
}

function buildRecommendations(findings, headersPresent) {
  const ids = new Set(findings.map(f => f.id));
  const recs = [];
  const push = (t) => { if (!recs.includes(t)) recs.push(t); };

  if (ids.has('password_request') || ids.has('mfa_code_request') || ids.has('credential_harvesting')) {
    push('Never enter your password or a one-time code on a page you reached by clicking an email link. Legitimate companies will not ask you to.');
  }
  if ([...ids].some(id => id.startsWith('url_'))) {
    push('Do not click the links in this email. On a computer you can usually hover over a link to preview its real address first.');
    push("Instead, open the organisation's website yourself by typing the address, using a bookmark, or using their official app.");
  }
  if ([...ids].some(id => id.startsWith('attachment_')) || ids.has('macro_request')) {
    push('Do not open the attachment, and do not enable macros or "enable content" if prompted. If you were expecting a document, confirm with the sender by phone first.');
  }
  if (ids.has('payment_request') || ids.has('bank_change') || ids.has('invoice_language')) {
    push('Before paying anything or changing bank details, verify the request by calling the organisation on a number from its official website — never a number given in the email.');
  }
  if (ids.has('impersonation') || ids.has('header_display_name_mismatch')) {
    push("Check the sender's full email address, not just the friendly name. The name is easy to fake; the domain is the real clue.");
  }
  if (ids.has('header_replyto_mismatch')) {
    push('A From / Reply-To mismatch means a reply would reach someone other than the apparent sender — treat the message as forged until proven otherwise.');
  }
  if (ids.has('header_spf_fail') || ids.has('header_dkim_fail') || ids.has('header_dmarc_fail')) {
    push('The email failed one or more authentication checks (SPF/DKIM/DMARC), which usually means it did not come from the organisation\u2019s real mail system.');
  }
  if (ids.has('urgency') || ids.has('threats')) {
    push('Slow down. Pressure and threats are designed to stop you thinking. Take a breath and verify through an independent channel.');
  }
  if (!headersPresent) {
    push('You pasted the email body only. If you can copy the full headers too (From, Reply-To, Authentication-Results), this tool can run extra authenticity checks.');
  }
  if (findings.length === 0) {
    push('This message does not match the specific patterns this tool looks for, but no automated check can prove an email is safe. Keep applying the same healthy scepticism.');
  }
  push('If the email reached a work account, report it to your IT or security team using your normal reporting process.');
  push('If you think you already clicked a link or replied with your details, change your password from a device you trust and tell your security team immediately.');
  return recs;
}

function analyseEmail(text) {
  const trimmed = (text || '').trim();
  if (!trimmed) {
    return {
      empty: true, score: 0, rawScore: 0, capped: false,
      band: classify(0), findings: [], passedChecks: [],
      recommendations: [], headersPresent: false, urlCount: 0
    };
  }

  const headers = parseHeaders(trimmed);
  const urls = extractUrls(trimmed);
  const ctx = { urls, headers };

  const findings = [];
  for (const rule of INDICATORS) {
    let evidence = [];
    try {
      evidence = rule.test(trimmed, ctx) || [];
    } catch (err) {
      evidence = []; // a broken rule should never break the whole analysis
    }
    if (evidence.length > 0) {
      findings.push({
        id: rule.id,
        name: rule.name,
        category: rule.category,
        points: rule.points,
        why: rule.why,
        evidence: evidence.slice(0, 3)
      });
    }
  }

  const rawScore = findings.reduce((sum, f) => sum + f.points, 0);
  const score = Math.min(100, rawScore);

  // Neutral "good news" signals shown alongside the warnings.
  const passedChecks = [];
  if (headers && headers.auth) {
    const labels = { spf: 'SPF passed', dkim: 'DKIM passed', dmarc: 'DMARC passed' };
    for (const mech of Object.keys(labels)) {
      if (headers.auth[mech] === 'pass') passedChecks.push(labels[mech]);
    }
  }
  if (headers && headers.from && headers.replyTo && headers.from.domain && headers.replyTo.domain &&
      baseDomain(headers.from.domain) === baseDomain(headers.replyTo.domain)) {
    passedChecks.push('From and Reply-To domains match');
  }

  return {
    empty: false,
    score: score,
    rawScore: rawScore,
    capped: rawScore > 100,
    band: classify(score),
    findings: findings,
    passedChecks: passedChecks,
    recommendations: buildRecommendations(findings, !!headers),
    headersPresent: !!headers,
    urlCount: urls.length
  };
}

/* ==========================================================================
 * Demonstration emails — 100% fictional.
 * All domains use the reserved ".example" suffix and all IP addresses come
 * from the documentation-only ranges (192.0.2.x, 198.51.100.x, 203.0.113.x),
 * so no link here leads anywhere real.
 * ========================================================================*/

const DEMO_EMAILS = [
  {
    id: 'obvious',
    title: 'Obvious phishing',
    blurb: 'Shouting capital letters, threats, a password request and a raw IP link — the classic amateur scam.',
    text: `From: "Account Security Department" <alerts@secure-bank-verify.example>
To: you@example.com
Subject: FINAL NOTICE!!! Your bank account will be SUSPENDED in 24 hours

Dear Customer,

This is your FINAL NOTICE. Due to suspicious activity, your bank account will be suspended within 24 hours unless you act now.

Please verify your account immediately using the secure link below:
http://192.0.2.44/account/verify
(backup link: http://bit.ly/bank-verify-demo-01)

You must enter your username and password, plus the one-time verification code we sent to your mobile phone, to confirm your identity.

Failure to respond will result in permanent account closure and possible legal action.

Regards,
The Security Team`
  },
  {
    id: 'sophisticated',
    title: 'Sophisticated phishing',
    blurb: 'Calm, professional tone with a disguised link and a dangerous attachment — harder to spot at a glance.',
    text: `From: DocuSign Service <documents@e-sign-delivery.example>
To: accounts.payable@example.com
Subject: Invoice ready for your signature — INV-2026-4471

Hello Amelia,

A document has been shared with you for review and signature. Please find attached a copy for your records.

You can also view the document online:
[https://secure-docusign-review.example/envelope/2f8a](http://198.51.100.77/envelope/2f8a)

For your security, you will be asked to verify your identity before the document can be opened. This link expires in 5 days.

Attachment: Scan_INV-2026-4471.pdf.exe

Kind regards,
Electronic Documents Department`
  },
  {
    id: 'm365',
    title: 'Fake Microsoft 365 warning',
    blurb: 'Includes pasted email headers so you can see the SPF/DKIM/DMARC and Reply-To checks at work.',
    text: `From: "Microsoft 365 Team" <security-alert@account-verification-center.example>
Reply-To: account-helpdesk@outlook-secure-assist.example
To: user@example.com
Subject: Action required: unusual sign-in activity detected
Authentication-Results: spf=fail (account-verification-center.example); dkim=fail; dmarc=fail

Unusual sign-in activity has been detected on your Microsoft 365 account.

If this was you, please confirm your identity by entering the verification code we sent to your phone. If you do not respond within 48 hours, your account will be deactivated and your mailbox will be suspended.

[Sign in to Microsoft](http://203.0.113.20/microsoft-365/login)

Microsoft will never ask you to share your sign-in details by email. Please verify your account using the secure link above.

Thank you,
The Microsoft Account Team`
  },

  {
    id: 'parcel',
    title: 'Fake parcel-delivery message',
    blurb: 'A small "customs fee" scam — friendly tone, tiny amount, shortened link. Very common in text-message and email scams.',
    text: `From: DHL Express Delivery <delivery@dhl-parcel-tracking.example>
To: recipient@example.com
Subject: Your parcel #DH-8842019 is on hold — action required

Dear Customer,

Your parcel #DH-8842019 could not be delivered because an outstanding customs fee of £2.99 has not been paid.

Please pay the delivery fee online within 24 hours to release the parcel.

Pay the customs charge here: http://bit.ly/dhl-parcel-demo-01

You will also need to confirm your address and phone number before the next delivery attempt.

DHL Customer Support`
  },
  {
    id: 'bec',
    title: 'Fake invoice / BEC-style email',
    blurb: 'Business Email Compromise: no shouting at all, just an "overdue invoice", new bank details and a macro document.',
    text: `From: Nathan Garrison <accounts@northgate-supply.example>
Reply-To: n.garrison@nathan-garrison-mail.example
To: accounts.payable@example.com
Subject: Invoice INV-8842 — updated bank details

Hi Sarah,

Hope you're well. Please find attached our latest invoice, INV-8842 for £1,240.00, which is now overdue.

Please note that we have recently changed banks, so our payment details have been updated. Please change your records to the new account below and process payment this week:

Account name: Northgate Office Solutions Ltd
Sort code: 12-34-56
Account number: 12345678
IBAN: GB00FICT00001234567890 (demo numbers only)

Attachment: INV-8842.xlsm

Let me know once payment has been scheduled so I can update the invoice status.

Many thanks,
Nathan Garrison
Accounts Department, Northgate Office Supplies`
  },
  {
    id: 'legit',
    title: 'Legitimate email',
    blurb: 'A normal message from a colleague. It should score very low — useful for comparison.',
    text: `From: Jamie Chen <jamie.chen@company.example>
To: you@company.example
Subject: Notes from today's project meeting

Hi,

Thanks for meeting this afternoon. As promised, here are the action items from our discussion:

- You offered to draft the revised project timeline. There's no rush at all — whenever you have time over the next two weeks is fine.
- I'll book the larger meeting room for the 20th.
- We agreed to move the demo to after the holiday period.

The meeting notes are on our internal wiki if you want to refer back: http://wiki.company.example/notes/2026-10-10

No attachments on this one. Let me know if I've missed anything!

Best regards,
Jamie`
  }
];

/* ==========================================================================
 * User interface — only runs inside a browser
 * ========================================================================*/

const CATEGORY_LABELS = {
  language: 'Language',
  links: 'Links',
  attachments: 'Attachments',
  headers: 'Headers'
};

function initUI() {
  const input = document.getElementById('emailInput');
  const analyseBtn = document.getElementById('analyseBtn');
  const clearBtn = document.getElementById('clearBtn');
  const charCount = document.getElementById('charCount');
  const inputError = document.getElementById('inputError');
  const results = document.getElementById('results');
  const demoGrid = document.getElementById('demoGrid');
  const gauge = document.getElementById('gauge');
  const scoreValue = document.getElementById('scoreValue');
  const riskBadge = document.getElementById('riskBadge');
  const riskHint = document.getElementById('riskHint');
  const scoreMath = document.getElementById('scoreMath');
  const findingsList = document.getElementById('findingsList');
  const noFindings = document.getElementById('noFindings');
  const recList = document.getElementById('recList');
  const passedChecks = document.getElementById('passedChecks');

  if (!input || !analyseBtn || !clearBtn || !results) return;

  /* ----- character counter ------------------------------------------------ */
  function updateCount() {
    const n = input.value.length;
    charCount.textContent = n.toLocaleString('en-GB') + (n === 1 ? ' character' : ' characters');
  }
  input.addEventListener('input', updateCount);
  updateCount();

  /* ----- demo cards -------------------------------------------------------- */
  DEMO_EMAILS.forEach((demo) => {
    const card = document.createElement('button');
    card.type = 'button';
    card.className = 'demo-card';

    const tag = document.createElement('span');
    const demoBand = classify(analyseEmail(demo.text).score);
    tag.className = 'demo-tag band-' + demoBand.key;
    tag.textContent = 'Scores ' + demoBand.label;

    const title = document.createElement('h4');
    title.textContent = demo.title;

    const blurb = document.createElement('p');
    blurb.className = 'demo-blurb';
    blurb.textContent = demo.blurb;

    const load = document.createElement('span');
    load.className = 'demo-load';
    load.textContent = 'Load this example →';

    card.appendChild(tag);
    card.appendChild(title);
    card.appendChild(blurb);
    card.appendChild(load);
    card.addEventListener('click', () => {
      input.value = demo.text;
      updateCount();
      inputError.hidden = true;
      if (runAnalysis()) {
        results.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
    demoGrid.appendChild(card);
  });

  /* ----- analysis ---------------------------------------------------------- */
  function runAnalysis() {
    if (!input.value.trim()) {
      inputError.textContent = 'Paste an email (or load one of the demo examples) first.';
      inputError.hidden = false;
      results.hidden = true;
      return false;
    }
    inputError.hidden = true;
    let result;
    try {
      result = analyseEmail(input.value);
    } catch (err) {
      inputError.textContent = 'Something went wrong while analysing this text. Please try again.';
      inputError.hidden = false;
      return false;
    }
    renderResults(result);
    return true;
  }

  /* ----- rendering the results --------------------------------------------- */
  function renderResults(result) {
    gauge.style.setProperty('--pct', String(result.score));
    gauge.className = 'gauge band-' + result.band.key;
    gauge.setAttribute('aria-label', 'Risk score ' + result.score + ' out of 100 — ' + result.band.label);
    scoreValue.textContent = String(result.score);
    riskBadge.textContent = result.band.label;
    riskBadge.className = 'risk-badge band-' + result.band.key;
    riskHint.textContent = result.band.hint;

    // the explainable maths behind the number
    if (result.findings.length) {
      const parts = result.findings.map(f => String(f.points));
      scoreMath.textContent = parts.join(' + ') + ' = ' + result.rawScore +
        (result.capped ? ' points (capped at 100)' : ' points');
    } else {
      scoreMath.textContent = 'No indicators matched = 0 points';
    }

    // warning signs
    findingsList.textContent = '';
    result.findings.forEach(f => findingsList.appendChild(renderFinding(f)));
    noFindings.hidden = result.findings.length > 0;
    if (!result.findings.length) {
      noFindings.textContent = result.headersPresent
        ? 'No known warning signs were detected in this email. That does not prove it is safe — phishing tactics change constantly.'
        : 'No known warning signs were detected in this email. That does not prove it is safe — and no headers were present, so sender-authenticity checks (SPF/DKIM/DMARC) were skipped.';
    }

    // neutral "good news" chips
    passedChecks.textContent = '';
    result.passedChecks.forEach(c => {
      const chip = document.createElement('span');
      chip.className = 'passed-chip';
      chip.textContent = c;
      passedChecks.appendChild(chip);
    });
    if (!result.headersPresent) {
      const chip = document.createElement('span');
      chip.className = 'passed-chip is-muted';
      chip.textContent = 'Header checks skipped — no headers pasted';
      passedChecks.appendChild(chip);
    }

    // recommendations
    recList.textContent = '';
    result.recommendations.forEach(r => {
      const li = document.createElement('li');
      li.textContent = r;
      recList.appendChild(li);
    });

    results.hidden = false;
  }

  function renderFinding(f) {
    const li = document.createElement('li');
    li.className = 'finding cat-' + f.category;

    const head = document.createElement('div');
    head.className = 'finding-head';

    const name = document.createElement('span');
    name.className = 'finding-name';
    name.textContent = f.name;

    const meta = document.createElement('div');
    meta.className = 'finding-meta';

    const cat = document.createElement('span');
    cat.className = 'cat-pill';
    cat.textContent = CATEGORY_LABELS[f.category] || f.category;

    const pts = document.createElement('span');
    pts.className = 'pts';
    pts.textContent = '+' + f.points;

    meta.appendChild(cat);
    meta.appendChild(pts);
    head.appendChild(name);
    head.appendChild(meta);

    const why = document.createElement('p');
    why.className = 'finding-why';
    why.textContent = f.why;

    li.appendChild(head);
    li.appendChild(why);

    if (f.evidence && f.evidence.length) {
      const evWrap = document.createElement('div');
      evWrap.className = 'evidence';
      f.evidence.forEach(ev => {
        const chip = document.createElement('span');
        chip.className = 'ev-chip';
        chip.textContent = '“' + ev + '”';
        evWrap.appendChild(chip);
      });
      li.appendChild(evWrap);
    }
    return li;
  }

  /* ----- buttons & keyboard shortcut ---------------------------------------- */
  analyseBtn.addEventListener('click', () => {
    if (runAnalysis()) results.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });

  clearBtn.addEventListener('click', () => {
    input.value = '';
    updateCount();
    results.hidden = true;
    inputError.hidden = true;
    input.focus();
  });

  input.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      if (runAnalysis()) results.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
}

/* ----- start the UI once the page is ready -------------------------------- */
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initUI);
  } else {
    initUI();
  }
}

/* Allow the engine to be tested outside the browser (e.g. with Node.js). */
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    analyseEmail: analyseEmail,
    classify: classify,
    INDICATORS: INDICATORS,
    DEMO_EMAILS: DEMO_EMAILS,
    parseHeaders: parseHeaders,
    extractUrls: extractUrls
  };
}











