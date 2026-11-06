// Web proxy locked to one site, for Vercel. Save this file as api/index.js in your GitHub repository.
// KEEP THE REPOSITORY PRIVATE: this file contains your password and master code.
// Keep the backtick quotes on the text settings, so they can contain ' and ". Don't use a backtick or ${ inside them.
// Optional: instead of editing the lines below, you can set PROXY_PASSWORD, PROXY_QUESTION, PROXY_MASTER_CODE and PROXY_SITE
// as environment variables in your Vercel project's settings. When they are set, they replace the values here.
const env = (k) => process.env[k];
const PASSWORD = env('PROXY_PASSWORD') || `Iskender`;
// The one site this proxy opens. There is no way to change it from the browser.
const SITE = env('PROXY_SITE') || 'https://krillion.io';
// The sign-in page shows this question; the password above is the answer to it.
const QUESTION = env('PROXY_QUESTION') || `Same as previous but replace a with e`;
// Optional master code. Typing it at the sign-in page signs you in even during a lockout, and clears the lockout.
// Use something long and private. Leave it empty (two backticks with nothing between) to turn it off.
const MASTER_CODE = env('PROXY_MASTER_CODE') ?? `mastercode`;

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const shell = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title>
<style>
:root{--bg:#f6f7f4;--ink:#1d2a2a;--muted:#5d6b6b;--line:#c9d1ce;--accent:#0f6b63}
@media(prefers-color-scheme:dark){:root{--bg:#101716;--ink:#e4ecea;--muted:#8fa09d;--line:#2b3a38;--accent:#4fc3b5}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,sans-serif}
main{width:100%;max-width:560px}h1{font-size:1.9rem;margin:0 0 .4rem}p{color:var(--muted);margin:0 0 1.4rem}a{color:var(--accent)}
form{display:flex;gap:8px}
input{flex:1;min-width:0;padding:12px 14px;font:inherit;color:var(--ink);background:transparent;border:1px solid var(--line);border-radius:8px}
button{padding:12px 18px;font:inherit;font-weight:600;color:var(--bg);background:var(--accent);border:0;border-radius:8px;cursor:pointer}
</style></head><body><main>${body}</main>
<script>document.cookie='__l=; Max-Age=0; Path=/; Secure; SameSite=Lax'</script></body></html>`;

const login = (next, note = '') => shell('Sign in', `<h1>Sign in</h1><p>${esc(QUESTION)}</p>${note ? `<p>${esc(note)}</p>` : ''}
<form action="/__login" method="post"><input type="hidden" name="next" value="${esc(next)}"><input name="password" type="password" autofocus required aria-label="Password"><button>Enter</button></form>`);

// Builds headers; a value can be a list (used to send several cookies at once).
const mk = (o) => { const h = new Headers(); for (const [k, v] of Object.entries(o)) for (const x of [].concat(v)) h.append(k, x); return h; };
const html = (body, status = 200, extra = {}) => new Response(body, { status, headers: mk({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', ...extra }) });
const redirect = (location, status = 302, extra = {}) => new Response(null, { status, headers: mk({ location, 'cache-control': 'no-store', ...extra }) });

// Wrong-answer lockout: after MAX_TRIES wrong answers in a row, sign-in is refused for LOCK_SECONDS, even for the right answer
// (only the master code gets in). It is remembered in two places: per visitor address (this function's memory, which Vercel may reset at any time) and in a signed cookie in the browser, so re-entering the address can't skip it.
const MAX_TRIES = 5;
const LOCK_SECONDS = 15 * 60;
const ZERO = { n: 0, m: 0, until: 0, exp: 0 };
const memory = new Map();
const getTries = async (ip) => {
  const v = memory.get(ip);
  return v && v.exp > Date.now() ? v : ZERO;
};
const setTries = async (ip, v) => {
  if (memory.size > 500) for (const [k, x] of memory) if (x.exp < Date.now()) memory.delete(k);
  memory.set(ip, v);
};
const clearTries = async (ip) => memory.delete(ip);
const failCookie = async (st) => {
  const body = [st.n, st.m, st.until, st.exp].join('.');
  return `__f=${body}.${await sign('f' + body)}${COOKIE}; Max-Age=${LOCK_SECONDS}`;
};
const readFail = async (v) => {
  const p = (v || '').split('.');
  if (p.length !== 5 || p.slice(0, 4).some((x) => !/^\d+$/.test(x))) return ZERO;
  const [n, m, until, exp] = p.slice(0, 4).map(Number);
  if (p[4] !== (await sign('f' + p.slice(0, 4).join('.'))) || exp <= Date.now()) return ZERO;
  return { n, m, until, exp };
};
const loadState = async (ip, cookie) => {
  const a = await getTries(ip);
  const b = await readFail(cookie);
  return { n: Math.max(a.n, b.n), m: Math.max(a.m, b.m), until: Math.max(a.until, b.until), exp: Math.max(a.exp, b.exp) };
};
const pausedNote = (ms) => `Too many wrong answers. Sign-in is paused for about ${Math.ceil(ms / 60000)} minute${Math.ceil(ms / 60000) === 1 ? '' : 's'}.`;
const pausedPage = (next, ms, cookie) => html(login(next, pausedNote(ms)), 429, { 'retry-after': String(Math.ceil(ms / 1000)), 'set-cookie': cookie });
// The visitor's address. Vercel sets x-vercel-forwarded-for itself, so a visitor can't fake it.
const ipOf = (request) => {
  const h = request.headers;
  const xff = (h.get('x-forwarded-for') || '').split(',').map((x) => x.trim()).filter(Boolean);
  return h.get('x-vercel-forwarded-for') || h.get('x-real-ip') || xff[xff.length - 1] || 'unknown';
};

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const hmacKey = () => crypto.subtle.importKey('raw', new TextEncoder().encode('proxy:' + PASSWORD), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
const sign = async (ts) => hex(await crypto.subtle.sign('HMAC', await hmacKey(), new TextEncoder().encode(String(ts))));
// The sign-in cookie is "<time you signed in>.<signature>", so the start time can't be changed or extended.
const makeToken = async () => { const ts = Date.now(); return ts + '.' + (await sign(ts)); };
const validToken = async (t) => {
  const [ts, sig] = (t || '').split('.');
  const age = Date.now() - Number(ts);
  return !!sig && age > -60000 && age < LIMIT_SECONDS * 1000 && sig === (await sign(ts));
};
const safeNext = (n) => (/^\/(?!\/)/.test(n) && !/^\/__(login|ping)/.test(n) ? n : '/');
const parseCookies = (h) => Object.fromEntries(h.split(/;\s*/).filter(Boolean).map((c) => { const i = c.indexOf('='); return [c.slice(0, i), c.slice(i + 1)]; }));
const COOKIE = '; Path=/; HttpOnly; Secure; SameSite=Lax';
// Sign-in lasts this many seconds after the last open page stops checking in (about 30s apart).
const SESSION_SECONDS = 120;
// Total time you can stay signed in, even if you keep using the proxy.
const LIMIT_SECONDS = 20 * 60;
// After the last page is closed, reopening within this many seconds still counts as the same visit.
const LEAVE_GRACE_SECONDS = 10;
const signIn = (token) => `__a=${token}${COOKIE}; Max-Age=${SESSION_SECONDS}`;
const CLEAR_A = `__a=; Max-Age=0${COOKIE}`;
const CLEAR_L = '__l=; Max-Age=0; Path=/; Secure; SameSite=Lax';
const CLEAR_F = `__f=; Max-Age=0${COOKIE}`;

const SKIP_REQ = /^(host|cookie|referer|origin|accept-encoding|connection|keep-alive|upgrade|te|content-length|transfer-encoding|forwarded|via|x-real-ip|x-request-id|true-client-ip|cdn-loop|cf-.*|fly-.*|render-.*|x-render-.*|x-forwarded-.*)$/i;
const DROP_RES = ['content-security-policy', 'content-security-policy-report-only', 'x-frame-options', 'strict-transport-security',
  'cross-origin-embedder-policy', 'cross-origin-opener-policy', 'cross-origin-resource-policy', 'content-encoding', 'content-length',
  'set-cookie', 'link', 'report-to', 'nel', 'transfer-encoding', 'connection', 'keep-alive'];

// The site you opened (the "target") lives at this server's root, so its own paths keep working.
// Anything on other hosts (CDNs, APIs) goes through /__x/<scheme>/<host>/<path>.
function toProxy(a, nav, T) {
  if (a.origin === T) return a.pathname + a.search + a.hash;
  if (nav) return a.href;
  return '/__x/' + a.protocol.slice(0, -1) + '/' + a.host + a.pathname + a.search + a.hash;
}

function rewriteUrl(v, base, nav, T) {
  v = (v || '').trim();
  if (!v || /^(#|data:|javascript:|mailto:|tel:|blob:|about:)/i.test(v)) return null;
  try {
    const a = new URL(v, base);
    return /^https?:$/.test(a.protocol) ? toProxy(a, nav, T) : null;
  } catch { return null; }
}

const rewriteCss = (css, base, T) => css
  .replace(/url\(\s*(["']?)([^"')]*)\1\s*\)/gi, (m, q, v) => { const o = rewriteUrl(v, base, false, T); return o ? `url(${q}${o}${q})` : m; })
  .replace(/@import\s+(["'])([^"']*)\1/gi, (m, q, v) => { const o = rewriteUrl(v, base, false, T); return o ? `@import ${q}${o}${q}` : m; });

const rewriteHls = (text, base, T) => text.split('\n').map((line) => {
  const t = line.trim();
  if (!t) return line;
  if (t.startsWith('#')) return line.replace(/URI="([^"]*)"/g, (m, v) => { const o = rewriteUrl(v, base, false, T); return o ? `URI="${o}"` : m; });
  return rewriteUrl(t, base, false, T) || line;
}).join('\n');

// Runs inside every page: sends fetch/XHR and dynamically added scripts/images through the proxy.
const clientScript = (T) => `<script>(()=>{
var T=${JSON.stringify(T)};
function fix(u,nav){try{var a=new URL(u,location.href);
if(a.origin===location.origin||!/^https?:$/.test(a.protocol))return u;
if(a.origin===T)return a.pathname+a.search+a.hash;
if(nav)return a.href;
return '/__x/'+a.protocol.slice(0,-1)+'/'+a.host+a.pathname+a.search+a.hash;}catch(e){return u}}
var f=window.fetch;
window.fetch=function(i,o){if(i instanceof Request)i=new Request(fix(i.url),i);else i=fix(String(i));return f.call(this,i,o)};
var xo=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){arguments[1]=fix(String(u));return xo.apply(this,arguments)};
var sa=Element.prototype.setAttribute;
Element.prototype.setAttribute=function(n,v){if(/^(src|href|action|poster)$/i.test(n)&&typeof v==='string')v=fix(v,this.tagName==='A'||this.tagName==='FORM');return sa.call(this,n,v)};
[[HTMLScriptElement,'src'],[HTMLImageElement,'src'],[HTMLIFrameElement,'src'],[HTMLLinkElement,'href'],[HTMLMediaElement,'src'],[HTMLSourceElement,'src']].forEach(function(p){
var d=Object.getOwnPropertyDescriptor(p[0].prototype,p[1]);if(!d||!d.set)return;
Object.defineProperty(p[0].prototype,p[1],{get:d.get,set:function(v){d.set.call(this,fix(String(v)))},configurable:true,enumerable:d.enumerable})});
if(navigator.serviceWorker)navigator.serviceWorker.register=function(){return Promise.reject(new Error('blocked by proxy'))};
function ping(){if(window!==top)return;f.call(window,'/__ping',{credentials:'same-origin'}).then(function(r){if(r.status===401)location.reload()}).catch(function(){})}
setInterval(ping,30000);
document.addEventListener('visibilitychange',function(){if(!document.hidden)ping()});
var off=${Date.now()}-Date.now(),CK='; Path=/; Secure; SameSite=Lax';
function unmark(){document.cookie='__l=; Max-Age=0'+CK}
unmark();
var bc=window.BroadcastChannel&&new BroadcastChannel('proxy-session');
if(bc)bc.onmessage=unmark;
addEventListener('pagehide',function(){if(window!==top)return;document.cookie='__l='+(Date.now()+off)+'; Max-Age=300'+CK;if(bc)bc.postMessage(1)});
addEventListener('pageshow',function(e){if(e.persisted){unmark();ping()}});
})()</script>`;

// Page rewriting. Links, scripts, pictures and frames are pointed at the proxy; inline scripts and comments are left alone.
const ATTR = { a: 'href', area: 'href', form: 'action', link: 'href', script: 'src', img: 'src', iframe: 'src', source: 'src', audio: 'src', embed: 'src', video: 'src' };
const NAV = new Set(['a', 'area', 'form']);
const BLOCK_RE = /<!--[\s\S]*?-->|<(script)\b((?:"[^"]*"|'[^']*'|[^'">])*)>([\s\S]*?)<\/script\s*>|<(style)\b((?:"[^"]*"|'[^']*'|[^'">])*)>([\s\S]*?)<\/style\s*>|<(a|area|form|link|img|iframe|source|video|audio|embed|base|meta)\b((?:"[^"]*"|'[^']*'|[^'">])*)>/gi;

function rewriteAttrs(tag, attrs, base, T) {
  const nav = NAV.has(tag);
  if (tag === 'link' || tag === 'script') attrs = attrs.replace(/\s+integrity\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '');
  for (const name of tag === 'video' ? ['src', 'poster'] : [ATTR[tag]]) {
    attrs = attrs.replace(new RegExp('(\\s' + name + '\\s*=\\s*)(?:"([^"]*)"|\'([^\']*)\'|([^\\s>]+))', 'i'), (m, pre, a, b, c) => {
      const raw = (a ?? b ?? c ?? '').replace(/&amp;/gi, '&').replace(/&quot;/gi, '"').replace(/&#0*39;/g, "'");
      const out = rewriteUrl(raw, base, nav, T);
      return out ? pre + '"' + out.replace(/&/g, '&amp;').replace(/"/g, '&quot;') + '"' : m;
    });
  }
  return attrs;
}

function rewriteHtml(text, base, T) {
  const out = text.replace(BLOCK_RE, (m, sTag, sAttrs, sBody, cTag, cAttrs, cBody, tag, attrs) => {
    if (sTag) return '<script' + rewriteAttrs('script', sAttrs, base, T) + '>' + sBody + '</script>';
    if (cTag) return '<style' + cAttrs + '>' + rewriteCss(cBody, base, T) + '</style>';
    if (!tag) return m; // a comment
    tag = tag.toLowerCase();
    if (tag === 'base') return '';
    if (tag === 'meta') return /http-equiv\s*=\s*["']?content-security-policy/i.test(attrs) ? '' : m;
    return '<' + tag + rewriteAttrs(tag, attrs, base, T) + '>';
  });
  const inject = clientScript(T);
  if (/<head\b[^>]*>/i.test(out)) return out.replace(/<head\b[^>]*>/i, (h) => h + inject);
  if (/<html\b[^>]*>/i.test(out)) return out.replace(/<html\b[^>]*>/i, (h) => h + inject);
  const d = out.match(/^\s*<!doctype[^>]*>/i);
  return d ? d[0] + inject + out.slice(d[0].length) : inject + out;
}

async function handler(request) {
  const u = new URL(request.url);
  if (PASSWORD === 'change-me') {
    return html(shell('Set a password', '<h1>Set a password first</h1><p>Edit the PASSWORD line at the top of the code, then deploy again.</p>'), 500);
  }

  const cookies = parseCookies(request.headers.get('cookie') || '');
  const ip = ipOf(request);

  if (u.pathname === '/__login' && request.method === 'POST') {
    const now = Date.now();
    const st = await loadState(ip, cookies.__f);
    const locked = st.until > now;
    const form = await request.formData();
    const next = safeNext(String(form.get('next') || '/'));
    const given = String(form.get('password') || '');
    // Too many wrong entries during a lockout: nothing is accepted, not even the master code, until it ends.
    if (locked && st.m >= MAX_TRIES) return pausedPage(next, st.until - now, await failCookie(st));
    // The master code works even during a lockout. The normal answer only works when not locked.
    if ((MASTER_CODE && given === MASTER_CODE) || (!locked && given === PASSWORD)) {
      await clearTries(ip);
      return redirect(next, 303, { 'set-cookie': [signIn(await makeToken()), CLEAR_L, CLEAR_F] });
    }
    let nx;
    if (locked) {
      // Wrong entries during a lockout are counted too, so the master code can't be guessed freely.
      const m = st.m + 1;
      nx = m >= MAX_TRIES ? { n: st.n, m, until: now + LOCK_SECONDS * 1000, exp: now + LOCK_SECONDS * 1000 } : { ...st, m };
    } else {
      const n = st.n + 1;
      const until = n >= MAX_TRIES ? now + LOCK_SECONDS * 1000 : 0;
      nx = { n, m: 0, until, exp: now + LOCK_SECONDS * 1000 };
    }
    await setTries(ip, nx);
    const fc = await failCookie(nx);
    if (nx.until > now) return pausedPage(next, nx.until - now, fc);
    const left = MAX_TRIES - nx.n;
    return html(login(next, `Wrong answer. ${left} ${left === 1 ? 'try' : 'tries'} left.`), 401, { 'set-cookie': fc });
  }
  // Signed out if the sign-in is missing or expired, or if the last open page was closed a few seconds ago.
  const dest = request.headers.get('sec-fetch-dest');
  const left = Number(cookies.__l) || 0;
  const closed = (!dest || dest === 'document') && left > 0 && Date.now() - left > LEAVE_GRACE_SECONDS * 1000;
  if (closed || !(await validToken(cookies.__a))) {
    const st = await loadState(ip, cookies.__f);
    const wait = st.until - Date.now();
    return html(login(safeNext(u.pathname + u.search), wait > 0 ? pausedNote(wait) : ''), wait > 0 ? 429 : 401, { 'set-cookie': [CLEAR_A, CLEAR_L] });
  }
  if (u.pathname === '/__ping') return new Response(null, { status: 204, headers: mk({ 'set-cookie': [signIn(cookies.__a), CLEAR_L] }) });
  if (request.headers.get('upgrade')) return new Response('WebSockets are not supported by this proxy.', { status: 501 });

  const T = new URL(SITE).origin;
  let real;
  try {
    if (u.pathname.startsWith('/__x/')) {
      if (dest === 'document') return html(shell('Not available', '<h1>Not available</h1><p>This proxy only opens one site.</p>'), 403);
      const [, , scheme, host, ...rest] = u.pathname.split('/');
      if (!/^https?$/.test(scheme) || !host) throw new Error('bad path');
      real = new URL(`${scheme}://${host}/${rest.join('/')}${u.search}`);
    } else {
      real = new URL(T + u.pathname + u.search);
    }
  } catch { return html(shell('Not found', '<h1>Bad address</h1><p><a href="/">Back to the site</a></p>'), 404); }
  if (real.hostname === u.hostname) return html(shell('Loop', '<h1>That address points back at this proxy</h1>'), 508);

  const headers = new Headers();
  for (const [k, v] of request.headers) if (!SKIP_REQ.test(k)) headers.set(k, v);
  const cookie = Object.entries(cookies).filter(([k]) => !['__a', '__t', '__l', '__f'].includes(k)).map(([k, v]) => `${k}=${v}`).join('; ');
  if (cookie) headers.set('cookie', cookie);
  headers.set('referer', T + '/');
  if (request.headers.get('origin')) headers.set('origin', T);

  let up;
  try {
    up = await fetch(real, {
      method: request.method,
      headers,
      body: ['GET', 'HEAD'].includes(request.method) ? undefined : await request.arrayBuffer(),
      redirect: 'manual',
    });
  } catch (e) {
    return html(shell('Could not open the page', `<h1>Could not open that page</h1><p>${esc(e.message)}</p><p><a href="/">Try again</a></p>`), 502);
  }

  const out = new Headers(up.headers);
  const length = up.headers.get('content-length');
  const encoded = up.headers.get('content-encoding');
  for (const h of DROP_RES) out.delete(h);
  const vary = out.get('vary');
  if (vary !== '*') out.set('vary', vary ? vary + ', Cookie' : 'Cookie');
  for (const c of up.headers.getSetCookie?.() || []) {
    if (!/^__[atlf]=/.test(c)) out.append('set-cookie', c.replace(/;\s*domain=[^;]*/i, ''));
  }
  out.append('set-cookie', signIn(cookies.__a));
  if (left > 0) out.append('set-cookie', CLEAR_L);

  const loc = up.headers.get('location');
  if (up.status >= 300 && up.status < 400 && loc) {
    try { out.set('location', toProxy(new URL(loc, real), dest === 'document', T)); } catch {}
    return new Response(null, { status: up.status, headers: out });
  }

  const type = up.headers.get('content-type') || '';
  if (/text\/html/i.test(type) && up.body) {
    const bytes = await up.arrayBuffer();
    const charset = (type.match(/charset=["']?([^;"'\s]+)/i) || [])[1] || 'utf-8';
    let text;
    try { text = new TextDecoder(charset).decode(bytes); } catch { text = new TextDecoder().decode(bytes); }
    out.set('content-type', 'text/html; charset=utf-8');
    return new Response(rewriteHtml(text, real.href, T), { status: up.status, headers: out });
  }
  if (/text\/css/i.test(type)) {
    return new Response(rewriteCss(await up.text(), real.href, T), { status: up.status, headers: out });
  }
  if (/mpegurl/i.test(type) || /\.m3u8$/i.test(real.pathname)) {
    return new Response(rewriteHls(await up.text(), real.href, T), { status: up.status, headers: out });
  }
  if (length && !encoded) out.set('content-length', length);
  return new Response(up.body, { status: up.status, headers: out });
}

// Vercel runs this function for every request (vercel.json sends all addresses to it).
export default { fetch: (request) => handler(request) };
