// profile.js — analyst settings.

(async () => {
    if (!(await FS.init())) return;
    const { esc, initials, fmtTime } = FS;
    const $ = id => document.getElementById(id);
    let profile;

    const saveUser = patch => FS.updateUser(patch);

    // ---- active sessions (revoke any you do not recognise)
    async function loadSessions() {
        const rows = await FS.api('/user/sessions');
        $('sessions').innerHTML = rows.map(s => `
          <tr><td><div style="font-weight:500">${esc(s.user_agent ? s.user_agent.replace(/\(.*?\)/g, '').slice(0, 60) : 'Unknown client')}</div>
            <div class="dim" style="font-size:12px">${esc(s.ip || '')} · signed in ${esc(fmtTime(s.created_at))}</div></td>
            <td class="nowrap dim">${esc(FS.timeAgo(s.last_seen_at))}</td>
            <td style="text-align:right">${s.current ? '<span class="badge info">This session</span>' : `<button class="btn btn-ghost btn-sm" data-revoke="${s.id}">Sign out</button>`}</td></tr>`).join('');
    }
    $('sessions').addEventListener('click', async e => {
        const b = e.target.closest('[data-revoke]');
        if (!b) return;
        try { const r = await FS.api(`/user/sessions/${b.dataset.revoke}`, { method: 'DELETE' }); FS.toast(r.message, 'success'); loadSessions(); }
        catch (err) { FS.toast(err.message, 'error'); }
    });

    $('delete-form').addEventListener('submit', async e => {
        e.preventDefault();
        if (!confirm('Delete your account permanently? Detections, Gmail connection and paired devices are removed. This cannot be undone.')) return;
        try {
            await FS.api('/user/account', { method: 'DELETE', body: { password: e.target.password.value } });
            location.href = '/index.html';
        } catch (err) { FS.toast(err.message, 'error'); }
    });

    function renderAvatar() {
        const html = profile.avatar_url ? `<img src="${esc(profile.avatar_url)}" alt="Profile photo">` : esc(initials(profile.full_name));
        $('avatar').innerHTML = html;
        const top = document.getElementById('topbar-avatar');
        if (top) top.innerHTML = profile.avatar_url ? `<img src="${esc(profile.avatar_url)}" alt="">` : esc(initials(profile.full_name));
        $('avatar-remove').classList.toggle('hidden', !profile.avatar_url);
    }

    function renderVerification() {
        const s = profile.verification_status;
        const cls = { Approved: 'legit', Pending: 'suspicious', Rejected: 'malicious' }[s] || 'neutral';
        $('verify-status').innerHTML = `<span class="badge ${cls}">${esc(s)}</span>`;
        if (s === 'Pending' || s === 'Approved') {
            $('verify-body').innerHTML = `<p class="muted" style="margin:0">${s === 'Approved' ? 'Your identity is verified.' : 'Your documents are under review.'} Document numbers are stored only as salted hashes.</p>`;
            return;
        }
        $('verify-body').innerHTML = `
          <form class="stack" id="verify-form">
            <p class="muted" style="margin:0">Verified analysts can be trusted with shared reports. Document numbers are hashed with bcrypt and never stored in clear.</p>
            <div class="form-row">
              <div class="field"><label for="v-name">Name on document</label><input class="input" id="v-name" name="fullNameOnDoc" required maxlength="120"></div>
              <div class="field"><label for="v-dob">Date of birth</label><input class="input" id="v-dob" name="dob" type="date" required></div>
            </div>
            <div class="form-row">
              <div class="field"><label for="v-type">Document</label>
                <select class="select" id="v-type" name="docType" required>
                  <option value="">Select…</option><option value="Aadhaar">Aadhaar</option><option value="PAN">PAN</option><option value="DL">Driving licence</option><option value="Passport">Passport</option>
                </select></div>
              <div class="field"><label for="v-num">Document number</label><input class="input mono" id="v-num" name="docNumber" required maxlength="20" autocomplete="off"></div>
            </div>
            <div><button class="btn btn-primary" type="submit">Submit for verification</button></div>
          </form>`;
        const PATTERNS = { Aadhaar: ['\\d{12}', '12 digits'], PAN: ['[A-Z]{5}[0-9]{4}[A-Z]', 'ABCDE1234F'], DL: ['[A-Z0-9\\- ]{8,20}', 'e.g. MH1420110012345'], Passport: ['[A-Z][0-9]{7}', 'e.g. K1234567'] };
        $('v-type').addEventListener('change', e => {
            const [pattern, hint] = PATTERNS[e.target.value] || ['.*', ''];
            $('v-num').pattern = pattern;
            $('v-num').placeholder = hint;
        });
        $('verify-form').addEventListener('submit', async e => {
            e.preventDefault();
            try {
                const r = await FS.api('/user/verify-identity', { method: 'POST', body: Object.fromEntries(new FormData(e.target)) });
                FS.toast(r.message, 'success');
                load();
            } catch (err) { FS.toast(err.message, 'error'); }
        });
    }

    async function load() {
        profile = await FS.api('/user/profile');
        $('p-name').value = profile.full_name;
        $('p-phone').value = profile.phone_number || '';
        $('p-email').value = profile.email;
        const vrow = $('verify-email-row');
        if (profile.email_verified_at) {
            vrow.innerHTML = '<span class="badge legit">Verified</span><span class="hint">High-risk alerts are delivered to this address.</span>';
        } else {
            vrow.innerHTML = '<span class="badge suspicious">Unverified</span><span class="hint">Alerts are not e-mailed until you confirm this address.</span><button type="button" class="btn btn-sm" id="resend-verify">Resend confirmation</button>';
            $('resend-verify').addEventListener('click', async () => {
                try { const r = await FS.api('/user/resend-verification', { method: 'POST', body: {} }); FS.toast(r.message, 'success'); }
                catch (err) { FS.toast(err.message, 'error'); }
            });
        }
        $('member-since').textContent = `Member since ${fmtTime(profile.created_at.replace(' ', 'T') + (profile.created_at.includes('Z') ? '' : 'Z'))}`;
        $('prefs-form').emailHighRisk.checked = Boolean(profile.email_high_risk_enabled);
        $('prefs-form').emailWeeklySummary.checked = Boolean(profile.email_weekly_summary_enabled);
        renderAvatar();
        renderVerification();
    }

    $('profile-form').addEventListener('submit', async e => {
        e.preventDefault();
        try {
            const body = Object.fromEntries(new FormData(e.target));
            const r = await FS.api('/user/profile', { method: 'PUT', body });
            saveUser({ name: body.fullName });
            FS.toast(r.message, 'success');
        } catch (err) { FS.toast(err.message, 'error'); }
    });

    $('password-form').addEventListener('submit', async e => {
        e.preventDefault();
        if ($('new-pass').value !== $('new-pass2').value) return FS.toast('New passwords do not match.', 'error');
        try {
            const r = await FS.api('/user/change-password', { method: 'POST', body: Object.fromEntries(new FormData(e.target)) });
            e.target.reset();
            FS.toast(r.message, 'success');
        } catch (err) { FS.toast(err.message, 'error'); }
    });

    $('prefs-form').addEventListener('change', async e => {
        const f = e.currentTarget;
        try {
            const r = await FS.api('/user/preferences', { method: 'PUT', body: { emailHighRisk: f.emailHighRisk.checked, emailWeeklySummary: f.emailWeeklySummary.checked } });
            FS.toast(r.message, 'success');
        } catch (err) { FS.toast(err.message, 'error'); }
    });

    $('avatar-input').addEventListener('change', async e => {
        const file = e.target.files[0];
        if (!file) return;
        const form = new FormData();
        form.append('avatar', file);
        try {
            const r = await FS.api('/user/upload-picture', { method: 'POST', form });
            profile.avatar_url = r.avatarUrl;
            saveUser({ avatarUrl: r.avatarUrl });
            renderAvatar();
            FS.toast(r.message, 'success');
        } catch (err) { FS.toast(err.message, 'error'); }
        e.target.value = '';
    });

    $('avatar-remove').addEventListener('click', async () => {
        try {
            const r = await FS.api('/user/remove-picture', { method: 'DELETE' });
            profile.avatar_url = null;
            saveUser({ avatarUrl: null });
            renderAvatar();
            FS.toast(r.message, 'success');
        } catch (err) { FS.toast(err.message, 'error'); }
    });

    load().catch(err => FS.toast(err.message, 'error'));
    loadSessions().catch(err => FS.toast(err.message, 'error'));
})();
