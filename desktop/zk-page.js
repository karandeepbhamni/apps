// Zakariya Dola 1080P - shared page script (PC Electron + Android WebView)
(function () {
  'use strict';
  if (window.__ZK_LOADED__) return;
  window.__ZK_LOADED__ = true;

  const SALT_HEX = '4dd4c2e6b83162090e52b3c7a6733ba4'
    + '1cb2462b829ab58a196b39db57177524'
    + 'f49baf7f08e8d68d26a72e37c1a95a2f'
    + '1f05a51892aef2949732b62a38aadd58';

  const originalFetch = window.fetch.bind(window);
  const processedApis = new Set();
  const media = new Map();
  const downloadedKeys = new Set();

  // ---------- config (localStorage) ----------
  const CFG_KEY = 'zk_cfg';
  let cfg = { autoDownload: false, total: 0 };
  try { cfg = Object.assign(cfg, JSON.parse(localStorage.getItem(CFG_KEY) || '{}')); } catch (e) {}
  function saveCfg() { try { localStorage.setItem(CFG_KEY, JSON.stringify(cfg)); } catch (e) {} }

  // ---------- native bridge ----------
  let bridge = null;
  function androidBridge() {
    const cbs = {}; let n = 0;
    window.__zkCb = (id, ok, data) => {
      const c = cbs[id]; if (!c) return; delete cbs[id];
      ok ? c.res(data) : c.rej(new Error(data));
    };
    const call = (fn, arg) => new Promise((res, rej) => { const id = ++n; cbs[id] = { res, rej }; window.AndroidZK[fn](id, arg); });
    return {
      fetchText: (u) => call('fetchText', u).then(b => decodeURIComponent(escape(atob(b)))),
      download: (m) => call('download', JSON.stringify(m)).then(r => JSON.parse(r))
    };
  }
  function getBridge() {
    if (bridge) return bridge;
    if (window.ZKNative) bridge = window.ZKNative;
    else if (window.AndroidZK) bridge = androidBridge();
    return bridge;
  }

  // ---------- crypto helpers ----------
  function hexToBytes(hex) {
    const b = new Uint8Array(hex.length / 2);
    for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return b;
  }
  function concatBytes(a, b) { const r = new Uint8Array(a.length + b.length); r.set(a, 0); r.set(b, a.length); return r; }
  function padBase64(t) { return t + '='.repeat((4 - (t.length % 4)) % 4); }
  function base64DecodeLoose(text) {
    const input = String(text || '').trim();
    const variants = [
      input,
      input.replace(/[$@#]/g, c => ({ '$': '_', '@': '/', '#': '.' }[c])),
      input.replace(/[$@#]/g, c => ({ '$': '+', '@': '/', '#': '=' }[c])),
    ];
    for (const cand of variants) {
      try {
        const bin = atob(padBase64(cand).replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return bytes;
      } catch (e) {}
    }
    return null;
  }
  function asciiUrlFromBytes(bytes) {
    if (!bytes || !bytes.length) return '';
    for (const b of bytes) if (b !== 9 && b !== 10 && b !== 13 && (b < 32 || b > 126)) return '';
    return new TextDecoder().decode(bytes);
  }
  function stripPkcs7(bytes) {
    if (!bytes || !bytes.length) return new Uint8Array();
    const pad = bytes[bytes.length - 1];
    if (pad < 1 || pad > 16 || pad > bytes.length) return bytes;
    for (let i = bytes.length - pad; i < bytes.length; i++) if (bytes[i] !== pad) return bytes;
    return bytes.slice(0, bytes.length - pad);
  }
  async function decryptAesCbcUrl(payload, keyBytes, ivBytes) {
    if (!payload.length || payload.length % 16 !== 0) return '';
    try {
      const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-CBC', false, ['decrypt']);
      const plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv: ivBytes }, key, payload));
      const direct = asciiUrlFromBytes(plain);
      if (/^https?:\/\//i.test(direct)) return direct;
      const url = asciiUrlFromBytes(stripPkcs7(plain));
      return /^https?:\/\//i.test(url) ? url : '';
    } catch (e) { return ''; }
  }
  async function decodeQaabToken(token, keySeed) {
    const data = base64DecodeLoose(token);
    const seed = base64DecodeLoose(keySeed);
    if (!data || !seed) return '';
    const d1 = await crypto.subtle.digest('SHA-512', seed.slice(0, 32));
    const d2 = new Uint8Array(await crypto.subtle.digest('SHA-512', concatBytes(new Uint8Array(d1), hexToBytes(SALT_HEX))));
    const key = d2.slice(0, 16), iv = d2.slice(16, 32);
    const attempts = [];
    if (data.length >= 4 && data[0] === 0xa8 && data[1] === 0x00 && data[2] === 0x01 && data[3] === 0x00) {
      attempts.push({ payload: data.slice(4), key, iv });
      attempts.push({ payload: data.slice(4), key: iv, iv: key });
      if (data.length > 36) {
        attempts.push({ payload: data.slice(36), key, iv: data.slice(20, 36) });
        attempts.push({ payload: data.slice(36), key, iv });
      }
    } else attempts.push({ payload: data, key, iv });
    for (const a of attempts) {
      const url = await decryptAesCbcUrl(a.payload, a.key, a.iv);
      if (url) return url;
    }
    return '';
  }
  async function decodeMainUrl(token, keySeed = '') {
    if (!token) return '';
    if (/^https?:\/\//i.test(token.trim())) return token.trim();
    const bytes = base64DecodeLoose(token);
    if (bytes) { const t = asciiUrlFromBytes(bytes); if (/^https?:\/\//i.test(t)) return t; }
    if (token.startsWith('qAAB') && keySeed) return await decodeQaabToken(token, keySeed);
    return '';
  }
  function findKeySeedDeep(value, depth = 0) {
    if (depth > 10 || value == null) return '';
    if (typeof value === 'string') {
      let m = value.match(/(?:^|[?&])key_seed=([^&"'<>\\\s]+)/i);
      if (m) return decodeURIComponent(m[1]);
      m = value.match(/["']key_seed["']\s*:\s*["']([^"']+)/i);
      return m ? decodeURIComponent(m[1]) : '';
    }
    if (typeof value !== 'object') return '';
    if (typeof value.key_seed === 'string' && value.key_seed.trim()) return value.key_seed.trim();
    for (const item of Object.values(value)) { const h = findKeySeedDeep(item, depth + 1); if (h) return h; }
    return '';
  }
  function pickBestToken(data) {
    const list = data && data.video_list ? Object.values(data.video_list) : [data];
    let best = '', max = 0;
    for (const item of list) {
      const tok = item && (item.main_url || item.play_url);
      const score = Number((item && item.bitrate) || 0) + Number((item && item.width) || 0) * Number((item && item.height) || 0);
      if (tok && score >= max) { max = score; best = tok; }
    }
    return best;
  }

  // ---------- metadata from stream text ----------
  function extractSurroundingMetadata(text, idx) {
    const slice = text.slice(Math.max(0, idx - 2000), Math.min(text.length, idx + 2000));
    const first = (res, ok) => { for (const re of res) for (const m of slice.matchAll(re)) if (m[1] && ok(m[1])) return m[1]; return ''; };
    let prompt = first([
      /(?:"prompt"|"query"|"content"|"instruction"|"topic_title")\s*:\s*"([^"]+)"/g,
      /\\"(?:prompt|query|content|instruction|topic_title)\\"\s*:\s*\\"(.*?)\\"/g
    ], v => !v.includes('fallback_api') && v.length > 3);
    if (prompt) { try { prompt = JSON.parse(`"${prompt}"`); } catch (e) { prompt = prompt.replace(/\\n/g, ' ').replace(/\\"/g, '"'); } }
    let poster = first([
      /(?:"poster_url"|"poster"|"cover_url"|"image_url")\s*:\s*"([^"]+)"/g,
      /\\"(?:poster_url|poster|cover_url|image_url)\\"\s*:\s*\\"(.*?)\\"/g
    ], v => /^https?:\/\//i.test(v.replace(/\\u0026/g, '&').replace(/\\\//g, '/')));
    poster = poster.replace(/\\u0026/g, '&').replace(/\\\//g, '/');
    const vid = first([/(?:"vid"|"video_id"|"item_id")\s*:\s*"([^"]+)"/g, /\\"(?:vid|video_id|item_id)\\"\s*:\s*\\"(.*?)\\"/g], v => v.length > 5);
    const messageId = first([/(?:"message_id"|"mid"|"chat_id")\s*:\s*"([^"]+)"/g, /\\"(?:message_id|mid|chat_id)\\"\s*:\s*\\"(.*?)\\"/g], v => v.length > 3);
    const keySeed = first([/(?:"key_seed")\s*:\s*"([^"]+)"/g, /\\"(?:key_seed)\\"\s*:\s*\\"(.*?)\\"/g], () => true);
    return { prompt, poster, vid, messageId, keySeed };
  }

  // ---------- resolve ----------
  async function processFallback(fallbackUrl, meta) {
    if (!fallbackUrl || processedApis.has(fallbackUrl)) return;
    processedApis.add(fallbackUrl);
    try {
      const u = new URL(fallbackUrl, location.href);
      u.searchParams.set('channel', 'no');
      u.searchParams.set('codec_type', '8');
      u.searchParams.set('logo_type', 'unwatermarked');
      let text;
      try { text = await getBridge().fetchText(u.toString()); }
      catch (e) {
        const r = await originalFetch(u.toString(), { credentials: 'include' });
        if (!r.ok) throw e;
        text = await r.text();
      }
      const payload = JSON.parse(text);
      const v = (payload && payload.video_info && payload.video_info.data) || (payload && payload.data && payload.data.video_info) || (payload && payload.data) || payload;
      const token = pickBestToken(v);
      if (!token) return;
      const seed = findKeySeedDeep(payload) || u.searchParams.get('key_seed') || meta.keySeed || '';
      const rawUrl = await decodeMainUrl(token, seed);
      if (!rawUrl || !/^https?:\/\//i.test(rawUrl)) return;
      registerMedia({
        vid: v.vid || v.video_id || meta.vid || fallbackUrl,
        url: rawUrl,
        poster: v.poster_url || v.poster || meta.poster || '',
        prompt: meta.prompt || v.prompt || 'Dola 1080P Unwatermarked Video',
        messageId: meta.messageId || '',
        width: v.width || 1080, height: v.height || 1920, duration: v.duration || 0,
        fallbackUrl, timestamp: Date.now()
      });
    } catch (e) { console.warn('[Zakariya] resolve error', e); }
  }

  function scanText(text) {
    if (!text || !text.includes('fallback_api')) return;
    for (const re of [/"fallback_api"\s*:\s*"([^"]+)"/g, /fallback_api\\":\\"(.*?)\\"/g]) {
      let m;
      while ((m = re.exec(text)) !== null) {
        if (m[1]) processFallback(m[1].replace(/\\u0026/g, '&').replace(/\\\//g, '/'), extractSurroundingMetadata(text, m.index));
      }
    }
  }

  // ---------- hooks ----------
  window.fetch = async function (...args) {
    const response = await originalFetch.apply(this, args);
    const url = typeof args[0] === 'string' ? args[0] : ((args[0] && args[0].url) || '');
    if (url && (url.includes('/chat/completion') || url.includes('/im/chain/single') || url.includes('dola.com') || url.includes('doubao.com'))) {
      try {
        const clone = response.clone();
        if (clone.body && typeof clone.body.getReader === 'function') {
          const reader = clone.body.getReader(); const dec = new TextDecoder();
          (async () => {
            let buf = '';
            while (true) { const { done, value } = await reader.read(); if (done) break; buf += dec.decode(value, { stream: true }); scanText(buf); }
          })().catch(() => {});
        } else clone.text().then(scanText).catch(() => {});
      } catch (e) {}
    }
    return response;
  };
  const xOpen = XMLHttpRequest.prototype.open, xSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (...a) { this._zkUrl = a[1]; return xOpen.apply(this, a); };
  XMLHttpRequest.prototype.send = function (...a) {
    this.addEventListener('load', function () {
      try { if (this._zkUrl && (this.responseType === '' || this.responseType === 'text') && this.responseText) scanText(this.responseText); } catch (e) {}
    });
    return xSend.apply(this, a);
  };

  // ---------- media registry + download ----------
  function sanitize(t) {
    return String(t || 'video').replace(/[/\\?%*:|"<>#]/g, '_').replace(/\s+/g, '_').replace(/_+/g, '_').slice(0, 60);
  }
  function makeFilename(m) {
    const n = new Date(), p = x => String(x).padStart(2, '0');
    return `Zakariya_${n.getFullYear()}-${p(n.getMonth() + 1)}-${p(n.getDate())}_${p(n.getHours())}-${p(n.getMinutes())}-${p(n.getSeconds())}_${sanitize(m.prompt || '1080P_Master_Video')}.mp4`;
  }
  async function download(m, isAuto) {
    if (!m || !m.url) return { ok: false, error: 'No URL' };
    const key = m.vid || m.url;
    if (isAuto && downloadedKeys.has(key)) return { ok: true, skipped: true };
    downloadedKeys.add(key);
    try {
      const r = await getBridge().download({ url: m.url, filename: makeFilename(m) });
      if (r && r.ok) { cfg.total++; saveCfg(); refreshUI(); }
      return r || { ok: false };
    } catch (e) { downloadedKeys.delete(key); return { ok: false, error: String(e.message || e) }; }
  }
  function registerMedia(m) {
    if (!m || !m.url) return;
    const key = m.vid || m.url;
    const isNew = !media.has(key);
    media.set(key, Object.assign({}, media.get(key) || {}, m));
    if (isNew && cfg.autoDownload) download(media.get(key), true);
    refreshUI();
  }

  // ---------- DOM helpers ----------
  function extractTOSKey(url) {
    if (!url) return '';
    try {
      const path = new URL(url, location.href).pathname;
      const t = path.match(/tos-[a-zA-Z0-9_-]+\/([a-zA-Z0-9_-]+)/i);
      if (t && t[1]) return t[1].split('~')[0].split('.')[0];
      const parts = path.split('/').filter(Boolean);
      return (parts[parts.length - 1] || '').split('~')[0].split('.')[0];
    } catch (e) {
      const m = String(url).split('?')[0].match(/tos-[a-zA-Z0-9_-]+\/([a-zA-Z0-9_-]+)/i);
      return m ? m[1].split('~')[0].split('.')[0] : '';
    }
  }
  function getVideoCards() {
    const cards = [];
    document.querySelectorAll('[class*="block-video"], [class*="block_video"], [class*="image-box-grid-item"]').forEach(el => {
      const b = el.querySelector('[class*="block-video"]') || el;
      if (!cards.includes(b)) cards.push(b);
    });
    document.querySelectorAll('[class*="video-player-wrapper"]').forEach(el => {
      if (!el.closest('[class*="block-video"], [class*="block_video"], [class*="image-box-grid-item"]') && !cards.includes(el)) cards.push(el);
    });
    return cards;
  }
  function extractDomPrompt(card, i) {
    try {
      const rows = document.querySelectorAll('table tbody tr');
      if (rows.length > i) {
        const el = rows[i].querySelector('td:nth-child(2)');
        const t = el && (el.innerText || el.textContent || '').trim();
        if (t) return `Scene_${i + 1}_${t}`;
      }
      const c = card.closest('[data-container-type], [data-message-id], [class*="message"]') || card.parentElement;
      if (c) for (const h of c.querySelectorAll('h1,h2,h3,h4,strong')) {
        const t = (h.innerText || h.textContent || '').trim();
        if (t.length >= 4 && t.length <= 80 && !t.includes('1080P') && !t.includes('Zakariya')) return t;
      }
    } catch (e) {}
    return `Dola_Scene_${i + 1}`;
  }
  function findMatch(card, allCards) {
    const all = Array.from(media.values());
    if (!all.length) return null;
    const idx = allCards.indexOf(card);
    const keys = [];
    card.querySelectorAll('img').forEach(im => { const k = extractTOSKey(im.src || im.getAttribute('src') || ''); if (k && k.length > 8) keys.push(k); });
    const v = card.querySelector('video');
    if (v) { const k = extractTOSKey(v.currentSrc || v.src || ''); if (k && k.length > 8) keys.push(k); }
    for (const k of keys) for (const m of all) {
      if ([m.poster, m.vid, m.url].some(x => { const e = extractTOSKey(x); return e && e === k; })) return m;
    }
    for (const k of keys) for (const m of all) {
      if ((m.poster && m.poster.includes(k)) || (m.url && m.url.includes(k)) || (m.vid && String(m.vid).includes(k))) return m;
    }
    if (idx >= 0 && idx < all.length) return all[idx];
    return all[idx % all.length] || all[0];
  }
  function orderedList() {
    const cards = getVideoCards();
    const out = [], seen = new Set();
    cards.forEach((card, i) => {
      const m = findMatch(card, cards);
      if (m && !seen.has(m.url)) { seen.add(m.url); out.push(Object.assign({}, m, { sceneIndex: i + 1, prompt: extractDomPrompt(card, i) })); }
    });
    if (out.length) return out;
    return Array.from(media.values()).sort((a, b) => {
      const am = String(a.prompt || '').match(/Scene[_\s]*(\d+)/i), bm = String(b.prompt || '').match(/Scene[_\s]*(\d+)/i);
      if (am && bm) return +am[1] - +bm[1];
      return (a.timestamp || 0) - (b.timestamp || 0);
    }).map((m, i) => Object.assign({}, m, { sceneIndex: i + 1 }));
  }

  // ---------- UI ----------
  const CSS = `
.zakariya-download-btn{position:absolute;top:12px;right:12px;z-index:99999;display:flex;align-items:center;gap:6px;padding:6px 14px;font:600 13px -apple-system,Segoe UI,Roboto,sans-serif;color:#fff;background:linear-gradient(135deg,#00f0ff,#ff007b);border:none;border-radius:20px;cursor:pointer;box-shadow:0 4px 15px rgba(0,240,255,.4)}
.zakariya-download-btn.loading{opacity:.8;cursor:wait;background:#333344}
.zakariya-download-btn.success{background:#00e676}
#zk-fab{position:fixed;right:14px;bottom:80px;z-index:2147483647;padding:10px 14px;border:none;border-radius:24px;color:#fff;font:700 13px sans-serif;background:linear-gradient(135deg,#00f0ff,#ff007b);box-shadow:0 4px 15px rgba(0,0,0,.5);cursor:pointer}
#zk-panel{position:fixed;right:14px;bottom:130px;z-index:2147483647;width:min(340px,calc(100vw - 28px));max-height:60vh;display:none;flex-direction:column;gap:8px;padding:12px;background:#0d0f17;color:#e2e8f0;border:1px solid #232a3d;border-radius:12px;font:12px sans-serif;box-shadow:0 8px 30px rgba(0,0,0,.6)}
#zk-panel.open{display:flex}
#zk-panel .zk-row{display:flex;justify-content:space-between;align-items:center;gap:8px}
#zk-panel button{border:none;border-radius:6px;padding:6px 10px;font-weight:700;font-size:11px;cursor:pointer;color:#0d0f17;background:#00f0ff}
#zk-list{overflow-y:auto;display:flex;flex-direction:column;gap:6px}
.zk-item{display:flex;align-items:center;gap:8px;background:#161a26;border:1px solid #232a3d;border-radius:8px;padding:6px}
.zk-item img{width:40px;height:40px;object-fit:cover;border-radius:6px}
.zk-item .zk-t{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
`;
  let fab, panel, listEl, countEl, totalEl, autoEl, timer;
  function injectCss() {
    try {
      const s = new CSSStyleSheet(); s.replaceSync(CSS);
      document.adoptedStyleSheets = [...document.adoptedStyleSheets, s];
    } catch (e) {
      const st = document.createElement('style'); st.textContent = CSS; (document.head || document.documentElement).appendChild(st);
    }
  }
  function buildPanel() {
    if (document.getElementById('zk-fab')) return;
    fab = document.createElement('button'); fab.id = 'zk-fab'; fab.textContent = '⬇ 1080P (0)';
    panel = document.createElement('div'); panel.id = 'zk-panel';
    const head = document.createElement('div'); head.className = 'zk-row';
    const title = document.createElement('b'); title.textContent = 'Zakariya 1080P Downloader';
    totalEl = document.createElement('span'); head.append(title, totalEl);
    const row2 = document.createElement('div'); row2.className = 'zk-row';
    const lab = document.createElement('label');
    autoEl = document.createElement('input'); autoEl.type = 'checkbox'; autoEl.checked = !!cfg.autoDownload;
    autoEl.addEventListener('change', () => { cfg.autoDownload = autoEl.checked; saveCfg(); });
    lab.append(autoEl, document.createTextNode(' Auto-download'));
    const all = document.createElement('button'); all.textContent = 'Download All';
    all.addEventListener('click', async () => {
      all.textContent = 'Saving...';
      for (const m of orderedList()) { await download(m, false); await new Promise(r => setTimeout(r, 600)); }
      all.textContent = 'Done!'; setTimeout(() => all.textContent = 'Download All', 2000);
    });
    row2.append(lab, all);
    countEl = document.createElement('div');
    listEl = document.createElement('div'); listEl.id = 'zk-list';
    panel.append(head, row2, countEl, listEl);
    fab.addEventListener('click', () => { panel.classList.toggle('open'); refreshUI(true); });
    document.body.append(panel, fab);
  }
  function refreshUI(now) {
    clearTimeout(timer);
    timer = setTimeout(renderUI, now ? 0 : 300);
  }
  function renderUI() {
    if (!fab) return;
    const list = orderedList();
    fab.textContent = `⬇ 1080P (${list.length})`;
    if (!panel.classList.contains('open')) return;
    totalEl.textContent = `Saved: ${cfg.total}`;
    countEl.textContent = list.length ? '' : 'Koi video detect nahi hua. Chat mein video generate/open karo.';
    listEl.textContent = '';
    list.forEach((m, i) => {
      const it = document.createElement('div'); it.className = 'zk-item';
      if (m.poster) { const im = document.createElement('img'); im.src = m.poster; im.onerror = () => im.remove(); it.appendChild(im); }
      const t = document.createElement('div'); t.className = 'zk-t'; t.textContent = `#${m.sceneIndex || i + 1} ${m.prompt || ''}`;
      const b = document.createElement('button'); b.textContent = 'Save';
      b.addEventListener('click', async () => {
        b.textContent = '...'; const r = await download(m, false);
        b.textContent = r && r.ok ? 'Saved!' : 'Failed'; setTimeout(() => b.textContent = 'Save', 2000);
      });
      it.append(t, b); listEl.appendChild(it);
    });
  }
  function attachCardButtons() {
    const cards = getVideoCards();
    cards.forEach((card, index) => {
      if (card.querySelector(':scope > .zakariya-download-btn')) return;
      const btn = document.createElement('button');
      btn.className = 'zakariya-download-btn';
      const span = document.createElement('span'); span.textContent = '⬇ 1080P Master'; btn.appendChild(span);
      btn.addEventListener('click', async (e) => {
        e.preventDefault(); e.stopPropagation();
        const cur = getVideoCards();
        const idx = cur.indexOf(card) >= 0 ? cur.indexOf(card) : index;
        const m = findMatch(card, cur);
        const dp = extractDomPrompt(card, idx);
        const reset = (txt, ms) => setTimeout(() => { btn.classList.remove('success', 'loading'); span.textContent = '⬇ 1080P Master'; }, ms);
        if (!m || !m.url) { span.textContent = 'Video load hone do'; reset(0, 2500); return; }
        btn.classList.add('loading'); span.textContent = 'Downloading...';
        const r = await download(Object.assign({}, m, { prompt: (m.prompt && !m.prompt.includes('Dola 1080P')) ? m.prompt : dp }), false);
        btn.classList.remove('loading');
        if (r && r.ok) { btn.classList.add('success'); span.textContent = 'Saved!'; } else span.textContent = 'Failed';
        reset(0, 2500);
      });
      card.style.position = 'relative';
      card.appendChild(btn);
    });
  }
  function initUI() {
    injectCss(); buildPanel(); attachCardButtons();
    new MutationObserver(() => { attachCardButtons(); if (!document.getElementById('zk-fab')) buildPanel(); }).observe(document.body, { childList: true, subtree: true });
    setInterval(() => { attachCardButtons(); refreshUI(); }, 2500);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initUI); else initUI();
  setTimeout(() => scanText(document.documentElement.innerHTML), 1500);
})();
