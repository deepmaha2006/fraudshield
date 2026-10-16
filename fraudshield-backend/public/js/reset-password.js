// reset-password.js — completes a password reset. The token arrives in the URL
// fragment (never sent to the server in the request line or Referer) and is
// removed from the address bar immediately.

(() => {
    const $ = id => document.getElementById(id);
    document.querySelectorAll('[data-icon]').forEach(el => { el.outerHTML = FS.icon(el.dataset.icon, el.className); });

    const token = new URLSearchParams(location.hash.slice(1)).get('token') || '';
    history.replaceState(null, '', location.pathname);

    const showError = msg => { $('error').textContent = msg; $('error').classList.remove('hidden'); };
    if (!/^[\w-]{20,100}$/.test(token)) {
        showError('This reset link is incomplete. Request a new one from the sign-in page.');
        $('submit').disabled = true;
    }

    $('reset-form').addEventListener('submit', async e => {
        e.preventDefault();
        $('error').classList.add('hidden');
        if ($('p1').value !== $('p2').value) return showError('The passwords do not match.');
        $('submit').disabled = true;
        try {
            const res = await fetch('/api/password/reset', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token, newPassword: $('p1').value }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) throw new Error(data.message || 'Reset failed.');
            $('done').textContent = data.message;
            $('done').classList.remove('hidden');
            $('reset-form').querySelectorAll('input').forEach(i => { i.value = ''; i.disabled = true; });
            setTimeout(() => { location.href = '/index.html#login'; }, 2500);
        } catch (err) {
            showError(err.message);
            $('submit').disabled = false;
        }
    });
})();
