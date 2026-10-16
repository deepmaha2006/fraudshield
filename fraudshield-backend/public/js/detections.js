// detections.js — filterable detection queue with live inserts.

(async () => {
    if (!(await FS.init())) return;
    const { esc, icon, verdictBadge, riskBar, sourceLabel, fmtTime, defang, STATUS_LABEL } = FS;
    const $ = id => document.getElementById(id);
    const form = $('filters');
    const PAGE = 50;
    let offset = 0;
    let total = 0;
    let lastItems = [];

    $('export-btn').innerHTML = `${icon('download')}Export CSV`;

    // Restore filters from the query string (deep links from other pages).
    const params = new URLSearchParams(location.search);
    for (const el of form.elements) if (el.name && params.has(el.name)) el.value = params.get(el.name);

    const filters = () => Object.fromEntries([...new FormData(form)].filter(([, v]) => v));

    const statusChip = s => `<span class="badge ${s === 'open' ? 'info' : 'neutral'}">${esc(STATUS_LABEL[s] || s)}</span>`;
    const row = d => `
      <tr class="clickable" data-id="${d.id}" tabindex="0">
        <td class="mono dim">${d.id}</td>
        <td class="nowrap dim">${esc(fmtTime(d.created_at))}</td>
        <td class="nowrap">${sourceLabel(d.source)}</td>
        <td class="cell-main"><div class="t ${d.subject ? '' : 'mono'}">${esc(d.subject || (d.kind === 'url' || /^https?:/i.test(d.target) ? defang(d.target) : d.target))}</div>
          <div class="s">${esc([d.sender, d.summary].filter(Boolean).join(' — '))}</div></td>
        <td>${verdictBadge(d.verdict)}</td>
        <td>${riskBar(d.risk)}</td>
        <td data-status>${statusChip(d.status)}</td>
      </tr>`;

    async function load() {
        const q = new URLSearchParams({ ...filters(), limit: PAGE, offset });
        history.replaceState(null, '', `?${new URLSearchParams(filters())}`);
        const data = await FS.api(`/detections?${q}`);
        total = data.total;
        lastItems = data.items;
        $('rows').innerHTML = data.items.length ? data.items.map(row).join('') :
            `<tr><td colspan="7"><div class="empty">${icon('search')}<div>No detections match these filters.</div></div></td></tr>`;
        $('count').textContent = `${total.toLocaleString()} result${total === 1 ? '' : 's'}`;
        $('page-info').textContent = total ? `${offset + 1}–${Math.min(offset + PAGE, total)} of ${total.toLocaleString()}` : '';
        $('prev').disabled = offset === 0;
        $('next').disabled = offset + PAGE >= total;
    }

    let debounce;
    form.addEventListener('input', () => { clearTimeout(debounce); debounce = setTimeout(() => { offset = 0; load(); }, 250); });
    form.addEventListener('submit', e => e.preventDefault());
    $('prev').addEventListener('click', () => { offset = Math.max(0, offset - PAGE); load(); });
    $('next').addEventListener('click', () => { offset += PAGE; load(); });

    const openRow = tr => tr && Drawer.open(tr.dataset.id);
    $('rows').addEventListener('click', e => openRow(e.target.closest('tr[data-id]')));
    $('rows').addEventListener('keydown', e => { if (e.key === 'Enter') openRow(e.target.closest('tr[data-id]')); });

    Drawer.onStatus((id, status) => {
        const cell = document.querySelector(`tr[data-id="${id}"] [data-status]`);
        if (cell) cell.innerHTML = statusChip(status);
    });

    FS.on('detection', d => {
        const f = filters();
        const matches = offset === 0 && !f.q && (!f.verdict || f.verdict === d.verdict) && (!f.source || f.source === d.source) && (!f.status || f.status === d.status);
        if (!matches) return;
        const tbody = $('rows');
        if (tbody.querySelector('.empty')) tbody.innerHTML = '';
        tbody.insertAdjacentHTML('afterbegin', row(d));
        tbody.firstElementChild.classList.add('flash');
        total++;
        $('count').textContent = `${total.toLocaleString()} results`;
    });

    $('export-btn').addEventListener('click', () => {
        const cols = ['id', 'created_at', 'source', 'verdict', 'risk', 'confidence', 'status', 'sender', 'subject', 'target', 'summary'];
        const cell = v => `"${String(v ?? '').replace(/"/g, '""').replace(/^[=+\-@]/, "'$&")}"`;
        const csv = [cols.join(','), ...lastItems.map(d => cols.map(c => cell(c === 'target' ? defang(d[c]) : d[c])).join(','))].join('\r\n');
        FS.download(`fraudshield-detections-${new Date().toISOString().slice(0, 10)}.csv`, csv, 'text/csv');
    });

    load().catch(err => FS.toast(err.message, 'error'));
})();
