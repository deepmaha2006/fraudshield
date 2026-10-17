// landing.js — public page: sign in, sign up, support.

(() => {
    const $ = id => document.getElementById(id);
    document.querySelectorAll('[data-icon]').forEach(el => { el.outerHTML = FS.icon(el.dataset.icon, el.className); });
    $('year').textContent = new Date().getFullYear();

    // ── Cloudflare Turnstile widgets ─────────────────────────────────────────
    // Widgets are rendered explicitly after app-config is fetched.
    // If TURNSTILE_SITE_KEY is not configured, containers stay empty and the
    // server-side requireTurnstile middleware also passes through.
    let tsWidgets = {}; // { signup, forgot, support } → widget id

    function initTurnstile(siteKey) {
        if (!siteKey || typeof window.turnstile === 'undefined') return;
        const render = (id) => {
            const el = $(id);
            if (el && !tsWidgets[id]) {
                tsWidgets[id] = window.turnstile.render(el, { sitekey: siteKey });
            }
        };
        render('turnstile-signup');
        render('turnstile-forgot');
        render('turnstile-support');
    }

    let _tsKey = null;
    // Called by the Turnstile script once it is loaded (see api.js?onload=... in index.html).
    window._onTurnstileLoad = () => { if (_tsKey) initTurnstile(_tsKey); };

    fetch('/api/app-config').then(r => r.json()).then(cfg => {
        _tsKey = cfg.turnstileSiteKey || null;
        if (_tsKey) initTurnstile(_tsKey); // may be a no-op if script not loaded yet
    }).catch(() => {});

    function getTurnstileToken(widgetId) {
        if (typeof window.turnstile === 'undefined' || widgetId == null) return null;
        return window.turnstile.getResponse(widgetId) || null;
    }

    function resetTurnstile(widgetId) {
        if (typeof window.turnstile !== 'undefined' && widgetId != null) window.turnstile.reset(widgetId);
    }

    try { localStorage.removeItem('authToken'); localStorage.removeItem('user'); } catch { /* legacy cleanup */ }
    fetch('/api/session', { credentials: 'same-origin' }).then(r => {
        const signedIn = r.ok;
        $('nav-auth').classList.toggle('hidden', signedIn);
        $('nav-console').classList.toggle('hidden', !signedIn);
        if (signedIn) {
            const cta = $('hero-cta');
            cta.textContent = 'Open console';
            cta.removeAttribute('data-open');
            cta.addEventListener('click', () => { location.href = '/dashboard.html'; });
        }
    }).catch(() => {});

    const modals = { login: $('modal-login'), signup: $('modal-signup'), forgot: $('modal-forgot') };
    const open = name => { Object.values(modals).forEach(m => m.open && m.close()); modals[name].showModal(); modals[name].querySelector('input').focus(); };
    document.querySelectorAll('[data-open]').forEach(b => b.addEventListener('click', () => open(b.dataset.open)));
    document.querySelectorAll('[data-switch]').forEach(a => a.addEventListener('click', e => { e.preventDefault(); open(a.dataset.switch); }));
    document.querySelectorAll('[data-close]').forEach(b => b.addEventListener('click', () => b.closest('dialog').close()));
    Object.values(modals).forEach(m => m.addEventListener('click', e => { if (e.target === m) m.close(); }));
    if (location.hash === '#login') open('login');

    async function post(path, body) {
        const res = await fetch(`/api${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.message || 'Request failed');
        return data;
    }

    function bind(form, handler) {
        form.addEventListener('submit', async e => {
            e.preventDefault();
            const btn = form.querySelector('button[type="submit"]');
            const err = form.querySelector('[data-error]');
            const label = btn.textContent;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner"></span>';
            err?.classList.add('hidden');
            try {
                await handler(Object.fromEntries(new FormData(form)));
            } catch (ex) {
                if (err) { err.textContent = ex.message; err.classList.remove('hidden'); } else FS.toast(ex.message, 'error');
            } finally {
                btn.disabled = false;
                btn.textContent = label;
            }
        });
    }

    bind($('login-form'), async data => {
        await post('/login', data); // sets the HttpOnly session cookie
        location.href = '/dashboard.html';
    });

    bind($('signup-form'), async data => {
        // Checkbox values arrive as strings from FormData; validate() expects a boolean.
        data.termsAccepted = data.termsAccepted === 'true';
        const token = getTurnstileToken(tsWidgets['turnstile-signup']);
        if (token) data['cf-turnstile-response'] = token;
        try {
            const r = await post('/register', data);
            $('signup-form').reset();
            resetTurnstile(tsWidgets['turnstile-signup']);
            open('login');
            $('l-email').value = data.email;
            $('l-pass').focus();
            FS.toast(r.message, 'success');
        } catch (ex) {
            resetTurnstile(tsWidgets['turnstile-signup']);
            throw ex;
        }
    });

    bind($('forgot-form'), async data => {
        const token = getTurnstileToken(tsWidgets['turnstile-forgot']);
        if (token) data['cf-turnstile-response'] = token;
        try {
            const r = await post('/password/forgot', data);
            $('forgot-form').reset();
            resetTurnstile(tsWidgets['turnstile-forgot']);
            modals.forgot.close();
            FS.toast(r.message, 'success');
        } catch (ex) {
            resetTurnstile(tsWidgets['turnstile-forgot']);
            throw ex;
        }
    });

    bind($('support-form'), async data => {
        const token = getTurnstileToken(tsWidgets['turnstile-support']);
        if (token) data['cf-turnstile-response'] = token;
        try {
            const r = await post('/support', data);
            $('support-form').reset();
            resetTurnstile(tsWidgets['turnstile-support']);
            FS.toast(r.message, 'success');
        } catch (ex) {
            resetTurnstile(tsWidgets['turnstile-support']);
            throw ex;
        }
    });
})();
