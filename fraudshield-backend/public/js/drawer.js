// drawer.js — side panel that opens a detection's full report with triage actions.

const Drawer = (() => {
    const { esc, icon, STATUS_LABEL } = FS;
    let onStatusChange = () => {};

    function close() {
        document.getElementById('drawer-root').innerHTML = '';
        document.removeEventListener('keydown', escKey);
    }
    const escKey = e => { if (e.key === 'Escape') close(); };

    async function open(id) {
        const root = document.getElementById('drawer-root');
        root.innerHTML = `
          <div class="drawer-backdrop" data-close></div>
          <aside class="drawer" role="dialog" aria-modal="true" aria-label="Detection ${esc(id)}">
            <div class="drawer-head">
              <span class="eyebrow">Detection #${esc(id)}</span>
              <div class="row" style="margin-left:auto" id="drawer-actions"></div>
              <button class="btn btn-ghost btn-sm" data-close aria-label="Close">${icon('x')}</button>
            </div>
            <div class="drawer-body" id="drawer-body"><div class="empty"><span class="spinner"></span></div></div>
          </aside>`;
        root.querySelectorAll('[data-close]').forEach(el => el.addEventListener('click', close));
        document.addEventListener('keydown', escKey);

        try {
            const { detection, report } = await FS.api(`/detections/${encodeURIComponent(id)}`);
            Report.render(document.getElementById('drawer-body'), report, detection);
            renderActions(detection);
        } catch (err) {
            document.getElementById('drawer-body').innerHTML = `<div class="empty">${esc(err.message)}</div>`;
        }
    }

    function renderActions(d) {
        const box = document.getElementById('drawer-actions');
        const options = Object.entries(STATUS_LABEL).map(([k, v]) => `<option value="${k}" ${k === d.status ? 'selected' : ''}>${v}</option>`).join('');
        box.innerHTML = `<label class="label" for="status-select">Triage</label><select class="select" id="status-select" style="height:30px;width:auto">${options}</select>`;
        box.querySelector('select').addEventListener('change', async e => {
            try {
                await FS.api(`/detections/${d.id}`, { method: 'PATCH', body: { status: e.target.value } });
                FS.toast(`Marked as ${STATUS_LABEL[e.target.value]}`, 'success');
                onStatusChange(d.id, e.target.value);
            } catch (err) { FS.toast(err.message, 'error'); }
        });
    }

    return { open, close, onStatus: fn => { onStatusChange = fn; } };
})();
