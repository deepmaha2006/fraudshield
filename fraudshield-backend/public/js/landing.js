// landing.js — public page: sign in, sign up, support.

(() => {
    const $ = id => document.getElementById(id);
    document.querySelectorAll('[data-icon]').forEach(el => { el.outerHTML = FS.icon(el.dataset.icon, el.className); });
    $('year').textContent = new Date().getFullYear();

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
        const r = await post('/register', data);
        $('signup-form').reset();
        open('login');
        $('l-email').value = data.email;
        $('l-pass').focus();
        FS.toast(r.message, 'success');
    });

    bind($('forgot-form'), async data => {
        const r = await post('/password/forgot', data);
        $('forgot-form').reset();
        modals.forgot.close();
        FS.toast(r.message, 'success');
    });

    bind($('support-form'), async data => {
        const r = await post('/support', data);
        $('support-form').reset();
        FS.toast(r.message, 'success');
    });
})();
