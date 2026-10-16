// verify-email.js — confirms e-mail ownership. Token arrives in the URL fragment
// (never sent in the request line or Referer) and is removed immediately.

(async () => {
    document.querySelectorAll('[data-icon]').forEach(el => { el.outerHTML = FS.icon(el.dataset.icon, el.className); });
    const status = document.getElementById('status');
    const token = new URLSearchParams(location.hash.slice(1)).get('token') || '';
    history.replaceState(null, '', location.pathname);
    const show = (cls, msg) => { status.className = `callout ${cls}`; status.textContent = msg; };

    if (!/^[\w-]{20,100}$/.test(token)) return show('danger', 'This confirmation link is incomplete. Request a new one from Settings.');
    try {
        const res = await fetch('/api/email/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token }),
        });
        const data = await res.json().catch(() => ({}));
        show(res.ok ? 'ok' : 'danger', data.message || 'Confirmation failed.');
    } catch {
        show('danger', 'Could not reach the server. Try the link again.');
    }
})();
