// core.js — shared console runtime: session, API, shell, live stream, formatting.
// Everything rendered from detections is attacker-controlled; always go through esc().

const FS = (() => {
    const TOKEN_KEY = 'authToken';

    // ------------------------------------------------------------ icons (stroke, 24 grid)
    const P = {
        shield: '<path d="M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/>',
        overview: '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
        search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>',
        alert: '<path d="M12 3l9.5 16.5h-19L12 3z"/><path d="M12 10v4M12 17.5v.01"/>',
        plug: '<path d="M9 2v6M15 2v6"/><path d="M6 8h12v4a6 6 0 01-12 0V8z"/><path d="M12 18v4"/>',
        report: '<path d="M14 3H6a1 1 0 00-1 1v16a1 1 0 001 1h12a1 1 0 001-1V8l-5-5z"/><path d="M14 3v5h5M9 13h6M9 17h6"/>',
        settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 110-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3h0a1.7 1.7 0 001-1.5V3a2 2 0 114 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8v0a1.7 1.7 0 001.5 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1z"/>',
        mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
        phone: '<rect x="7" y="2" width="10" height="20" rx="2"/><path d="M11 18h2"/>',
        link: '<path d="M10 13a5 5 0 007.5.5l3-3a5 5 0 00-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 00-7.5-.5l-3 3a5 5 0 007 7l1.7-1.7"/>',
        image: '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="9" cy="9" r="2"/><path d="M21 15l-5-5L5 21"/>',
        message: '<path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/>',
        user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0116 0"/>',
        menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
        x: '<path d="M18 6L6 18M6 6l12 12"/>',
        copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 012-2h10"/>',
        download: '<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>',
        check: '<path d="M5 12l5 5L20 7"/>',
        bolt: '<path d="M13 2L4 14h7l-1 8 9-12h-7l1-8z"/>',
        globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 010 18M12 3a14 14 0 000 18"/>',
        lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 018 0v4"/>',
        server: '<rect x="3" y="4" width="18" height="7" rx="1"/><rect x="3" y="13" width="18" height="7" rx="1"/><path d="M7 7.5h.01M7 16.5h.01"/>',
        file: '<path d="M14 3H6a1 1 0 00-1 1v16a1 1 0 001 1h12a1 1 0 001-1V8l-5-5z"/><path d="M14 3v5h5"/>',
        logout: '<path d="M15 3h4a2 2 0 012 2v14a2 2 0 01-2 2h-4M10 17l5-5-5-5M15 12H3"/>',
        refresh: '<path d="M21 12a9 9 0 11-3-6.7L21 8"/><path d="M21 3v5h-5"/>',
        trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13a1 1 0 001 1h8a1 1 0 001-1l1-13M9 7V4h6v3"/>',
        print: '<path d="M6 9V3h12v6"/><rect x="3" y="9" width="18" height="8" rx="1"/><path d="M6 14h12v7H6z"/>',
        calendar: '<rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/>',
        chevronDown: '<path d="m6 9 6 6 6-6"/>',
        chevronsUpDown: '<path d="m7 15 5 5 5-5M7 9l5-5 5 5"/>',
        activity: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
        clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/>',
        shieldAlert: '<path d="M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z"/><path d="M12 8v4M12 16h.01"/>',
        inbox: '<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.5 5.1 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.5-6.9A2 2 0 0 0 16.8 4H7.2a2 2 0 0 0-1.7 1.1z"/>',
    };
    const icon = (name, cls = '') =>
        `<svg class="${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${P[name] || ''}</svg>`;

    // ------------------------------------------------------------ formatting
    const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const defang = s => String(s ?? '').replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
    const VERDICT_COLOR = { legit: 'var(--legit)', suspicious: 'var(--suspicious)', malicious: 'var(--malicious)' };
    const VERDICT_LABEL = { legit: 'Legit', suspicious: 'Suspicious', malicious: 'Malicious' };
    const VERDICT_ICON = { legit: 'check', suspicious: 'alert', malicious: 'alert' };
    const SOURCES = {
        manual: { label: 'Manual', icon: 'search' },
        screenshot: { label: 'Screenshot', icon: 'image' },
        gmail: { label: 'Gmail', icon: 'mail' },
        sms: { label: 'Android SMS', icon: 'phone' },
    };
    const STATUS_LABEL = { open: 'Open', acknowledged: 'Acknowledged', resolved: 'Resolved', false_positive: 'False positive' };

    const verdictBadge = v => `<span class="badge ${esc(v)}">${icon(VERDICT_ICON[v] || 'alert')}${esc(VERDICT_LABEL[v] || v)}</span>`;
    const riskColor = r => r >= 65 ? VERDICT_COLOR.malicious : r >= 30 ? VERDICT_COLOR.suspicious : VERDICT_COLOR.legit;
    const riskBar = r => `<div class="riskbar" title="Risk ${r}/100"><div class="track"><div class="fill" style="width:${Math.max(2, r)}%;background:${riskColor(r)}"></div></div><span class="num">${r}</span></div>`;
    const sourceLabel = s => { const x = SOURCES[s] || { label: s, icon: 'file' }; return `<span class="source">${icon(x.icon)}${esc(x.label)}</span>`; };

    function timeAgo(iso) {
        const s = Math.round((Date.now() - new Date(iso)) / 1000);
        if (s < 45) return 'just now';
        if (s < 3600) return `${Math.round(s / 60)}m ago`;
        if (s < 86400) return `${Math.round(s / 3600)}h ago`;
        return `${Math.round(s / 86400)}d ago`;
    }
    const fmtTime = iso => new Date(iso).toLocaleString(undefined, { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const fmtNum = n => (n ?? 0).toLocaleString();

    // ------------------------------------------------------------ session & API
    // The session lives in an HttpOnly cookie that scripts cannot read. Only the
    // per-session CSRF token is held here, in memory, and sent on writes.
    let session = { user: {}, csrf: null };
    const user = () => session.user || {};
    try { localStorage.removeItem(TOKEN_KEY); localStorage.removeItem('user'); } catch { /* storage unavailable */ }

    const toLogin = () => location.replace('/index.html#login');

    // Server unreachable / no network → the "Connection Lost" page, which returns here when it can.
    const toOffline = () => location.replace(`/offline.html?return=${encodeURIComponent(location.pathname + location.search)}`);
    const toServerError = () => location.replace(`/500.html?return=${encodeURIComponent(location.pathname + location.search)}`);

    /** A fetch threw: is it really the connection (and not a one-off)? */
    async function connectionLost() {
        if (navigator.onLine === false) return true;
        try {
            const r = await fetch('/healthz', { cache: 'no-store' });
            return !r.ok;
        } catch {
            return true;
        }
    }

    // Offline fallback for page loads (see /sw.js). Needs a secure context: https or localhost.
    if ('serviceWorker' in navigator && window.isSecureContext) {
        window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js').catch(() => {}));
    }

    async function logout() {
        try {
            await fetch('/api/logout', { method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': session.csrf || '' } });
        } finally {
            location.href = '/index.html';
        }
    }

    async function api(path, { method = 'GET', body, form } = {}) {
        const headers = {};
        if (body !== undefined) headers['Content-Type'] = 'application/json';
        if (method !== 'GET' && session.csrf) headers['X-CSRF-Token'] = session.csrf;
        let res;
        try {
            res = await fetch(`/api${path}`, { method, headers, credentials: 'same-origin', body: form || (body !== undefined ? JSON.stringify(body) : undefined) });
        } catch (err) {
            if (await connectionLost()) { toOffline(); throw new Error('Connection lost'); }
            throw new Error('Request failed — please try again.');
        }
        if (res.status === 401) { toLogin(); throw new Error('Session expired'); }
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.message || `Request failed (${res.status})`);
        return data;
    }

    function updateUser(patch) {
        session.user = { ...session.user, ...patch };
    }

    // ------------------------------------------------------------ toasts
    function toast(message, type = 'info', title) {
        let box = document.querySelector('.toasts');
        if (!box) { box = document.createElement('div'); box.className = 'toasts'; box.setAttribute('role', 'status'); document.body.appendChild(box); }
        const el = document.createElement('div');
        el.className = `toast ${type}`;
        el.innerHTML = `${title ? `<b>${esc(title)}</b>` : ''}${esc(message)}`;
        box.appendChild(el);
        setTimeout(() => el.remove(), type === 'alert' ? 9000 : 4500);
    }

    // ------------------------------------------------------------ live stream
    const listeners = {};
    const on = (event, fn) => (listeners[event] = listeners[event] || []).push(fn);
    const emit = (event, data) => (listeners[event] || []).forEach(fn => fn(data));
    let streamState = 'connecting';

    function connectStream() {
        const es = new EventSource('/api/stream', { withCredentials: true }); // same-origin cookie; no token in the URL
        const setState = s => { streamState = s; emit('stream', s); renderFeedState(); };
        es.addEventListener('hello', () => setState('live'));
        es.addEventListener('detection', e => {
            const d = JSON.parse(e.data);
            emit('detection', d);
            if (d.verdict === 'malicious' && d.source !== 'manual') {
                toast(`${SOURCES[d.source]?.label || d.source}: ${d.subject || d.sender || d.target}`, 'alert', `Malicious · risk ${d.risk}`);
            }
            bumpOpenCount(d);
        });
        es.addEventListener('integration', e => emit('integration', JSON.parse(e.data)));
        es.onerror = () => setState(es.readyState === EventSource.CLOSED ? 'down' : 'reconnecting');
    }

    function renderFeedState() {
        const el = document.getElementById('feed-state');
        if (!el) return;
        const map = { live: ['live', 'Live feed connected'], reconnecting: ['warn', 'Reconnecting…'], connecting: ['warn', 'Connecting…'], down: ['down', 'Feed offline'] };
        const [cls, text] = map[streamState] || map.connecting;
        el.innerHTML = `<span class="dot ${cls}"></span>${text}`;
    }

    let openCount = 0;
    function setOpenCount(n) {
        openCount = n;
        const el = document.getElementById('nav-open-count');
        if (el) { el.textContent = n; el.classList.toggle('hidden', !n); }
    }
    const bumpOpenCount = d => { if (d.verdict !== 'legit') setOpenCount(openCount + 1); };

    // ------------------------------------------------------------ shell

    function initials(name) {
        return String(name || '?').split(/\s+/).filter(Boolean).slice(0, 2).map(w => w[0].toUpperCase()).join('');
    }

    // Top navigation shared by every console page (minimal light design).
    const PRIMARY = [
        { id: 'overview', href: '/dashboard.html', label: 'Overview' },
        { id: 'investigate', href: '/analyzer.html', label: 'Investigate' },
        { id: 'detections', href: '/detections.html', label: 'Detections', badge: true },
        { id: 'integrations', href: '/integrations.html', label: 'Integrations' },
    ];

    function buildShell() {
        const page = document.body.dataset.page;
        const main = document.querySelector('main');
        const u = user();
        document.body.classList.add('light');

        const chrome = document.createElement('div');
        chrome.innerHTML = `
          <div id="banner-slot"></div>
          <header class="ld-nav">
            <button class="ld-workspace" id="ws-btn" type="button" aria-haspopup="true" aria-expanded="false">
              <span class="ld-ws-avatar">${icon('shield')}</span>FraudShield SOC${icon('chevronsUpDown')}
            </button>
            <nav class="ld-links" aria-label="Primary">
              ${PRIMARY.map(n => `<a href="${n.href}"${n.id === page ? ' class="active" aria-current="page"' : ''}>${n.label}${n.badge ? ' <span class="count hidden" id="nav-open-count"></span>' : ''}</a>`).join('')}
            </nav>
            <div class="ld-nav-right">
              <form class="ld-search" id="search-form" role="search">
                ${icon('search')}
                <input type="search" name="q" placeholder="Search detections…" aria-label="Search detections" maxlength="100" autocomplete="off">
              </form>
              <span class="ld-live" id="feed-state"></span>
              <button class="ld-avatar-btn" id="topbar-avatar" type="button" aria-haspopup="true" aria-expanded="false" aria-label="Account menu">
                ${u.avatarUrl ? `<img src="${esc(u.avatarUrl)}" alt="">` : esc(initials(u.name))}
              </button>
            </div>
            <div class="ld-menu ld-menu-ws hidden" id="ws-menu" role="menu">
              <div class="ld-menu-label">Workspace</div>
              <a href="/weekly-summary.html" role="menuitem">${icon('report')}Reports</a>
              <a href="/integrations.html" role="menuitem">${icon('plug')}Sources &amp; integrations</a>
              <a href="/profile.html" role="menuitem">${icon('settings')}Settings</a>
            </div>
            <div class="ld-menu ld-menu-user hidden" id="user-menu" role="menu">
              <div class="ld-menu-label">${esc(u.email || u.name || '')}</div>
              <a href="/profile.html" role="menuitem">${icon('user')}Profile &amp; security</a>
              <button type="button" id="logout-btn" role="menuitem">${icon('logout')}Sign out</button>
            </div>
          </header>`;
        document.body.prepend(...chrome.children);
        main.classList.add('ld-page');

        // Menus: one open at a time; close on outside click or Escape.
        const menus = [[document.getElementById('ws-btn'), document.getElementById('ws-menu')],
            [document.getElementById('topbar-avatar'), document.getElementById('user-menu')]];
        const closeMenus = () => menus.forEach(([b, m]) => { m.classList.add('hidden'); b.setAttribute('aria-expanded', 'false'); });
        for (const [btn, menu] of menus) {
            btn.addEventListener('click', e => {
                e.stopPropagation();
                const open = menu.classList.contains('hidden');
                closeMenus();
                if (open) { menu.classList.remove('hidden'); btn.setAttribute('aria-expanded', 'true'); }
            });
        }
        document.addEventListener('click', closeMenus);
        document.addEventListener('keydown', e => { if (e.key === 'Escape') closeMenus(); });
        document.getElementById('logout-btn').addEventListener('click', logout);
        document.getElementById('search-form').addEventListener('submit', e => {
            e.preventDefault();
            const q = e.target.q.value.trim();
            location.href = q ? `/detections.html?q=${encodeURIComponent(q)}` : '/detections.html';
        });
        renderFeedState();
    }

    /** Load the session (or bounce to sign-in), then build the console shell. */
    /** `{ shell: false }` = the page renders its own navigation (e.g. the light dashboard). */
    async function init({ shell = true } = {}) {
        const res = await fetch('/api/session', { credentials: 'same-origin' }).catch(() => null);
        if (!res) { toOffline(); return false; }            // server unreachable / no network
        if (res.status >= 500) { toServerError(); return false; }
        if (!res.ok) { toLogin(); return false; }
        const data = await res.json();
        session = { user: data.user || {}, csrf: data.csrf };
        if (shell) buildShell();
        connectStream();
        Promise.all([
            api('/detections?status=open&verdict=malicious&limit=1'),
            api('/detections?status=open&verdict=suspicious&limit=1'),
        ]).then(([m, s]) => setOpenCount(m.total + s.total)).catch(() => {});
        return true;
    }

    function download(filename, text, type = 'application/json') {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([text], { type }));
        a.download = filename;
        a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    }

    async function copy(text) {
        try { await navigator.clipboard.writeText(text); toast('Copied to clipboard', 'success'); }
        catch { toast('Clipboard unavailable', 'error'); }
    }

    // ------------------------------------------------------------ announcement banner
    /**
     * Sticky banner above the topbar (port of the shadcn Banner: 'normal' | 'rainbow').
     * Text is set with textContent and links must be same-origin paths, so a
     * banner can never inject markup or send users off-site. With an `id`, a
     * dismissal is remembered in this browser (convenience only).
     */
    function banner({ id, message, variant = 'normal', height = '2.5rem', link, container } = {}) {
        const main = container || document.getElementById('banner-slot');
        if (!main || !message) return null;
        const key = id ? `banner-${id}` : null;
        try { if (key && localStorage.getItem(key) === 'true') return null; } catch { /* storage unavailable */ }

        const el = document.createElement('div');
        el.className = `fs-banner${variant === 'rainbow' ? ' rainbow' : ''}`;
        el.setAttribute('role', 'region');
        el.setAttribute('aria-label', 'Announcement');
        el.style.height = height;
        if (variant === 'rainbow') {
            for (const n of [1, 2]) {
                const layer = document.createElement('div');
                layer.className = `fs-banner-layer rainbow-banner-gradient-${n}`;
                el.appendChild(layer);
            }
        }
        const text = document.createElement('span');
        text.className = 'fs-banner-text';
        text.textContent = message;
        el.appendChild(text);
        if (link && typeof link.href === 'string' && /^\/(?!\/)/.test(link.href)) {
            const a = document.createElement('a');
            a.href = link.href;
            a.textContent = link.text || 'Learn more';
            el.appendChild(a);
        }
        if (key) {
            const close = document.createElement('button');
            close.type = 'button';
            close.className = 'fs-banner-close';
            close.setAttribute('aria-label', 'Close banner');
            close.innerHTML = icon('x'); // static icon markup, no user data
            close.addEventListener('click', () => {
                el.remove();
                document.documentElement.style.removeProperty('--banner-height');
                try { localStorage.setItem(key, 'true'); } catch { /* storage unavailable */ }
            });
            el.appendChild(close);
        }
        main.prepend(el);
        document.documentElement.style.setProperty('--banner-height', height); // keeps the sticky topbar below it
        return el;
    }

    return {
        banner,
        icon, esc, defang, verdictBadge, riskBar, riskColor, sourceLabel, timeAgo, fmtTime, fmtNum,
        api, toast, on, init, user, updateUser, logout, download, copy, initials,
        VERDICT_COLOR, VERDICT_LABEL, SOURCES, STATUS_LABEL, setOpenCount,
    };
})();
