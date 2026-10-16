// analyzer.js — manual investigation (URL, message text, screenshot OCR).

(async () => {
    if (!(await FS.init())) return;
    const { esc, icon, verdictBadge, riskBar, timeAgo, defang } = FS;
    const $ = id => document.getElementById(id);
    const result = $('result');

    document.querySelectorAll('[data-icon]').forEach(el => { el.outerHTML = icon(el.dataset.icon); });

    // ---- tabs
    const tabs = document.querySelectorAll('.tab');
    function selectTab(name) {
        tabs.forEach(t => { const on = t.dataset.tab === name; t.classList.toggle('active', on); t.setAttribute('aria-selected', on); });
        document.querySelectorAll('[data-pane]').forEach(p => p.classList.toggle('hidden', p.dataset.pane !== name));
    }
    tabs.forEach(t => t.addEventListener('click', () => selectTab(t.dataset.tab)));

    // ---- run an analysis
    const URL_STAGES = ['URL structure', 'DNS resolution', 'HTTP fetch & redirects', 'TLS certificate', 'Domain registration (RDAP)', 'Page content analysis'];
    const MSG_STAGES = ['Language signals', 'Link extraction', 'Live link analysis'];

    async function run(button, label, stages, request) {
        const original = button.textContent;
        button.disabled = true;
        button.innerHTML = '<span class="spinner"></span> Analysing';
        result.classList.remove('hidden');
        Report.renderPending(result, label, stages);
        result.scrollIntoView({ behavior: 'smooth', block: 'start' });
        try {
            const { detection, report } = await request();
            Report.render(result, report, detection);
            loadHistory();
        } catch (err) {
            result.innerHTML = `<div class="panel-body"><div class="callout danger">${esc(err.message)}</div></div>`;
        } finally {
            button.disabled = false;
            button.textContent = original;
        }
    }

    $('form-url').addEventListener('submit', e => {
        e.preventDefault();
        const url = $('url-input').value.trim();
        if (!url) return;
        run($('url-submit'), url, URL_STAGES, () => FS.api('/analyze/url', { method: 'POST', body: { url } }));
    });

    $('form-message').addEventListener('submit', e => {
        e.preventDefault();
        const text = $('msg-text').value.trim();
        if (!text) return;
        run($('msg-submit'), text.slice(0, 140), MSG_STAGES, () =>
            FS.api('/analyze/message', { method: 'POST', body: { text, sender: $('msg-sender').value.trim() || undefined } }));
    });

    // ---- screenshot
    const shotInput = $('shot-input');
    const dz = $('dropzone');
    let file = null;
    const setFile = f => {
        file = f;
        $('shot-name').textContent = f ? `${f.name} · ${(f.size / 1024).toFixed(0)} KB` : 'PNG, JPEG, WebP · max 6 MB';
        $('shot-submit').disabled = !f;
    };
    shotInput.addEventListener('change', () => setFile(shotInput.files[0] || null));
    ['dragenter', 'dragover'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add('over'); }));
    ['dragleave', 'drop'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove('over'); }));
    dz.addEventListener('drop', e => { const f = e.dataTransfer.files[0]; if (f && f.type.startsWith('image/')) setFile(f); });
    $('form-screenshot').addEventListener('submit', e => {
        e.preventDefault();
        if (!file) return;
        const form = new FormData();
        form.append('screenshot', file);
        run($('shot-submit'), file.name, ['OCR (eng+hin)', ...MSG_STAGES], () => FS.api('/analyze/screenshot', { method: 'POST', form }));
    });

    // ---- history
    async function loadHistory() {
        const { items } = await FS.api('/detections?source=manual&limit=8');
        $('history').innerHTML = items.length ? items.map(d => `
          <tr class="clickable" data-id="${d.id}" tabindex="0">
            <td class="nowrap dim">${timeAgo(d.created_at)}</td>
            <td class="cell-main"><div class="t mono">${esc(d.kind === 'url' ? defang(d.target) : d.target)}</div><div class="s">${esc(d.summary || '')}</div></td>
            <td>${verdictBadge(d.verdict)}</td><td>${riskBar(d.risk)}</td></tr>`).join('') :
            `<tr><td colspan="4"><div class="empty">No investigations yet.</div></td></tr>`;
    }
    $('history').addEventListener('click', e => { const tr = e.target.closest('tr[data-id]'); if (tr) Drawer.open(tr.dataset.id); });

    // Deep link: analyzer.html?url=...
    const pre = new URLSearchParams(location.search).get('url');
    if (pre) { $('url-input').value = pre; }

    loadHistory().catch(() => {});
})();
