// integrations.js — Gmail connector and Android device pairing.

(async () => {
    if (!(await FS.init())) return;
    const { esc, icon, timeAgo, fmtNum, fmtTime } = FS;
    const $ = id => document.getElementById(id);
    document.querySelectorAll('[data-icon]').forEach(el => { el.outerHTML = icon(el.dataset.icon); });

    let state = { gmail: null, devices: [], serverUrls: [] };

    // ------------------------------------------------------------ Gmail
    const GMAIL_STATUS = {
        live: ['live', 'Live'], connecting: ['warn', 'Connecting'], reconnecting: ['warn', 'Reconnecting'],
        auth_failed: ['down', 'Credentials rejected'], paused: ['', 'Paused'],
    };

    function renderGmail() {
        const g = state.gmail;
        const status = g ? (g.live || g.status) : null;
        const [dot, text] = GMAIL_STATUS[status] || ['', status || 'Not connected'];
        $('gmail-state').innerHTML = `<span class="dot ${dot}"></span><span style="font-size:12px">${esc(text)}</span>`;

        if (!g) {
            if ($('gmail-form') && !$('g-toggle')) return; // keep what the user is typing
            $('gmail-body').innerHTML = `
              <p class="muted" style="margin:0">FraudShield signs in over IMAP and holds an IDLE connection, so Gmail pushes each new message instantly.
                Every e-mail gets SPF/DKIM/DMARC checks, sender-spoofing checks, and live analysis of each link it contains. Malicious mail is labelled <span class="mono">FraudShield/Threat</span> in Gmail.</p>
              <ol class="steps">
                <li>Turn on <b>2-Step Verification</b> for the Google account.</li>
                <li>Create an <b>App Password</b> at <a href="https://myaccount.google.com/apppasswords" target="_blank" rel="noopener noreferrer">myaccount.google.com/apppasswords</a>.</li>
                <li>Paste the 16-character password below. It is encrypted with AES-256-GCM before it is stored.</li>
              </ol>
              <form class="stack" id="gmail-form">
                <div class="form-row">
                  <div class="field"><label for="g-email">Gmail address</label><input class="input" id="g-email" name="email" type="email" required placeholder="you@gmail.com" autocomplete="off"></div>
                  <div class="field"><label for="g-pass">App Password</label><input class="input mono" id="g-pass" name="appPassword" type="password" required placeholder="xxxx xxxx xxxx xxxx" autocomplete="new-password"></div>
                </div>
                <div><button class="btn btn-primary" type="submit">Connect &amp; start monitoring</button></div>
              </form>`;
            $('gmail-form').addEventListener('submit', connectGmail);
            return;
        }

        $('gmail-body').innerHTML = `
          <dl class="kv">
            <dt>Mailbox</dt><dd class="mono">${esc(g.email)}</dd>
            <dt>Status</dt><dd>${esc(text)}</dd>
            <dt>Messages scanned</dt><dd>${fmtNum(g.messages_scanned)}</dd>
            <dt>Last message</dt><dd>${g.last_event_at ? `${esc(fmtTime(g.last_event_at))} (${timeAgo(g.last_event_at)})` : '—'}</dd>
            <dt>Connected since</dt><dd>${esc(fmtTime(g.created_at))}</dd>
          </dl>
          ${g.last_error ? `<div class="callout ${status === 'auth_failed' ? 'danger' : 'warn'}">${esc(g.last_error)}</div>` : ''}
          <div class="row">
            <button class="btn" id="g-toggle">${g.enabled ? 'Pause monitoring' : 'Resume monitoring'}</button>
            <a class="btn" href="/detections.html?source=gmail">View Gmail detections</a>
            <button class="btn btn-danger" id="g-remove" style="margin-left:auto">Disconnect</button>
          </div>
          ${status === 'auth_failed' ? `<details><summary style="cursor:pointer">Replace App Password</summary>
            <form class="row" id="gmail-form" style="margin-top:10px;flex-wrap:nowrap"><input type="hidden" name="email" value="${esc(g.email)}">
              <input class="input mono" name="appPassword" type="password" required placeholder="new app password" autocomplete="new-password">
              <button class="btn btn-primary" type="submit">Reconnect</button></form></details>` : ''}`;
        $('g-toggle').addEventListener('click', async () => {
            try { const r = await FS.api('/integrations/gmail', { method: 'PATCH', body: { enabled: !g.enabled } }); FS.toast(r.message, 'success'); load(); }
            catch (err) { FS.toast(err.message, 'error'); }
        });
        $('g-remove').addEventListener('click', async () => {
            if (!confirm(`Disconnect ${g.email}? Stored credentials will be deleted. Past detections are kept.`)) return;
            try { const r = await FS.api('/integrations/gmail', { method: 'DELETE' }); FS.toast(r.message, 'success'); load(); }
            catch (err) { FS.toast(err.message, 'error'); }
        });
        $('gmail-form')?.addEventListener('submit', connectGmail);
    }

    async function connectGmail(e) {
        e.preventDefault();
        const btn = e.target.querySelector('button[type="submit"]');
        const body = Object.fromEntries(new FormData(e.target));
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Verifying with Gmail…';
        try {
            const r = await FS.api('/integrations/gmail', { method: 'POST', body });
            FS.toast(r.message, 'success', 'Gmail connected');
            load();
        } catch (err) {
            FS.toast(err.message, 'error', 'Gmail connection failed');
            btn.disabled = false;
            btn.textContent = 'Connect & start monitoring';
        }
    }

    // ------------------------------------------------------------ Android devices
    function renderDevices() {
        const rows = state.devices;
        $('devices').innerHTML = rows.length ? rows.map(d => `
          <tr><td><div style="font-weight:500">${esc(d.name)}</div><div class="dim" style="font-size:12px">paired ${esc(fmtTime(d.created_at))}</div></td>
            <td class="mono">${fmtNum(d.messages_received)}</td>
            <td class="nowrap">${d.last_seen_at ? `<span class="row" style="gap:6px"><span class="dot ${Date.now() - new Date(d.last_seen_at) < 864e5 ? 'live' : ''}"></span>${timeAgo(d.last_seen_at)}</span>` : '<span class="dim">never</span>'}</td>
            <td style="text-align:right"><button class="btn btn-ghost btn-sm" data-revoke="${d.id}" data-name="${esc(d.name)}">${icon('trash')}Revoke</button></td></tr>`).join('') :
            `<tr><td colspan="4"><div class="empty">No devices paired yet.</div></td></tr>`;
    }

    $('devices').addEventListener('click', async e => {
        const btn = e.target.closest('[data-revoke]');
        if (!btn || !confirm(`Revoke "${btn.dataset.name}"? The phone will stop reporting SMS.`)) return;
        try { const r = await FS.api(`/integrations/devices/${btn.dataset.revoke}`, { method: 'DELETE' }); FS.toast(r.message, 'success'); load(); }
        catch (err) { FS.toast(err.message, 'error'); }
    });

    $('pair-form').addEventListener('submit', async e => {
        e.preventDefault();
        const name = e.target.name.value.trim();
        try {
            const r = await FS.api('/integrations/devices', { method: 'POST', body: { name } });
            e.target.reset();
            const urls = r.serverUrls.length ? r.serverUrls : [location.origin];
            const box = $('pair-result');
            box.classList.remove('hidden');
            box.innerHTML = `
              <div class="callout ok"><b>${esc(r.name)}</b> paired. Copy the token now — it is shown only once.</div>
              <div class="field" style="margin-top:10px"><span class="label">Server URL (pick the one on the phone's network)</span>
                ${urls.map(u => `<div class="row" style="flex-wrap:nowrap"><div class="secret" style="flex:1">${esc(u)}</div><button class="btn btn-sm" data-copy="${esc(u)}">${icon('copy')}</button></div>`).join('')}</div>
              <div class="field" style="margin-top:10px"><span class="label">Device token</span>
                <div class="row" style="flex-wrap:nowrap"><div class="secret" style="flex:1">${esc(r.token)}</div><button class="btn btn-sm" data-copy="${esc(r.token)}">${icon('copy')}</button></div></div>
              <details style="margin-top:10px"><summary class="dim" style="cursor:pointer">Test from a terminal</summary>
                <div class="secret" style="margin-top:6px;white-space:pre-wrap">curl -X POST ${esc(urls[0])}/api/ingest/sms \\
  -H "Authorization: Device ${esc(r.token)}" -H "Content-Type: application/json" \\
  -d '{"sender":"VM-TESTER","body":"Your account is blocked, verify now at http://example.com"}'</div></details>`;
            box.querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', () => FS.copy(b.dataset.copy)));
            load();
        } catch (err) { FS.toast(err.message, 'error'); }
    });

    // ------------------------------------------------------------ live events
    function logEvent(text) {
        const list = $('events');
        if (list.querySelector('.dim')) list.innerHTML = '';
        list.insertAdjacentHTML('afterbegin', `<li><span class="code">${new Date().toLocaleTimeString()}</span>${esc(text)}</li>`);
        while (list.children.length > 30) list.lastElementChild.remove();
    }
    FS.on('integration', ev => {
        logEvent(ev.type === 'gmail' ? `gmail · ${ev.status}${ev.error ? ' — ' + ev.error : ''}` : `device #${ev.id} · ${ev.status}`);
        load();
    });
    FS.on('detection', d => logEvent(`detection #${d.id} · ${d.source} · ${d.verdict} (${d.risk})`));
    FS.on('stream', s => logEvent(`stream · ${s}`));

    async function load() {
        state = await FS.api('/integrations');
        renderGmail();
        renderDevices();
    }
    load().catch(err => FS.toast(err.message, 'error'));
})();
