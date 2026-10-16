// dashboard.js — SOC overview.

(async () => {
    if (!(await FS.init())) return;
    const { esc, icon, verdictBadge, riskBar, sourceLabel, timeAgo, fmtNum, defang } = FS;
    const $ = id => document.getElementById(id);
    const css = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

    $('investigate-btn').innerHTML = `${icon('search')}Investigate URL / message`;

    let chart;
    const VERDICTS = [['legit', 'Legit', '--legit'], ['suspicious', 'Suspicious', '--suspicious'], ['malicious', 'Malicious', '--malicious']];

    function kpi(label, value, meta, barPct, barColor) {
        return `<div class="panel kpi"><div class="eyebrow">${esc(label)}</div><div class="value">${value}</div>
          <div class="meta">${meta}</div>${barPct != null ? `<div class="bar"><span style="width:${barPct}%;background:${barColor}"></span></div>` : ''}</div>`;
    }

    function renderKpis(k) {
        const pct = (a, b) => b ? Math.round(a / b * 100) : 0;
        $('kpis').innerHTML = [
            kpi('Analysed · 24h', fmtNum(k.total24h), `${fmtNum(k.total7d)} in the last 7 days`),
            kpi('Malicious · 24h', fmtNum(k.malicious24h), `${pct(k.malicious24h, k.total24h)}% of traffic`, pct(k.malicious24h, k.total24h), 'var(--malicious)'),
            kpi('Suspicious · 24h', fmtNum(k.suspicious24h), `${pct(k.suspicious24h, k.total24h)}% of traffic`, pct(k.suspicious24h, k.total24h), 'var(--suspicious)'),
            kpi('Open incidents', fmtNum(k.openIncidents), 'awaiting triage'),
            kpi('Mean time to verdict', k.avgAnalysisMs != null ? `${(k.avgAnalysisMs / 1000).toFixed(1)}s` : '—', 'live probe, 7d average'),
            kpi('Mean confidence', k.avgConfidence != null ? `${k.avgConfidence}%` : '—', 'probe stages completed'),
        ].join('');
    }

    function renderTimeline(timeline) {
        const labels = timeline.map(d => new Date(d.day + 'T00:00:00').toLocaleDateString(undefined, { weekday: 'short', day: 'numeric' }));
        $('timeline-legend').innerHTML = VERDICTS.map(([, l, v]) => `<span><i style="background:var(${v})"></i>${l}</span>`).join('');
        $('timeline-table').innerHTML = `<table class="data"><thead><tr><th>Day</th>${VERDICTS.map(([, l]) => `<th>${l}</th>`).join('')}</tr></thead>
          <tbody>${timeline.map((d, i) => `<tr><td>${esc(labels[i])}</td>${VERDICTS.map(([k]) => `<td class="mono">${d[k]}</td>`).join('')}</tr>`).join('')}</tbody></table>`;

        const datasets = VERDICTS.map(([k, l, v]) => ({
            label: l, data: timeline.map(d => d[k]), backgroundColor: css(v),
            borderColor: css('--surface-1'), borderWidth: { top: 2 }, borderSkipped: false, borderRadius: 3, maxBarThickness: 34,
        }));
        if (chart) { chart.data.labels = labels; chart.data.datasets.forEach((ds, i) => ds.data = datasets[i].data); chart.update(); return; }
        chart = new Chart($('timeline'), {
            type: 'bar',
            data: { labels, datasets },
            options: {
                maintainAspectRatio: false,
                animation: { duration: 300 },
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    legend: { display: false },
                    tooltip: { backgroundColor: css('--surface-3'), borderColor: css('--border-strong'), borderWidth: 1, titleColor: css('--text'), bodyColor: css('--text-2'), padding: 10, boxPadding: 4 },
                },
                scales: {
                    x: { stacked: true, grid: { display: false }, ticks: { color: css('--text-3'), font: { size: 11 } }, border: { color: css('--border') } },
                    y: { stacked: true, beginAtZero: true, ticks: { color: css('--text-3'), precision: 0, font: { size: 11 } }, grid: { color: css('--border') }, border: { display: false } },
                },
            },
        });
    }

    function renderCoverage(integ) {
        const g = integ.gmail;
        const gState = !g ? ['', 'Not connected'] : g.live === 'live' ? ['live', 'Live · IMAP IDLE'] : g.status === 'paused' ? ['', 'Paused'] :
            g.status === 'auth_failed' ? ['down', 'Credentials rejected'] : ['warn', g.status];
        const devs = integ.devices || [];
        const recent = d => d.last_seen_at && Date.now() - new Date(d.last_seen_at) < 24 * 3600 * 1000;
        $('coverage').innerHTML = `
          <div class="row" style="justify-content:space-between">
            <div class="row">${icon('mail')}<div><div style="font-weight:500">Gmail</div><div class="dim" style="font-size:12px">${g ? esc(g.email) : 'Connect an inbox to scan mail as it arrives'}</div></div></div>
            <div class="row" style="font-size:12px"><span class="dot ${gState[0]}"></span>${esc(gState[1])}</div>
          </div>
          ${g ? `<div class="dim" style="font-size:12px">${fmtNum(g.messages_scanned)} messages scanned${g.last_event_at ? ` · last ${timeAgo(g.last_event_at)}` : ''}</div>` : ''}
          <div style="border-top:1px solid var(--border)"></div>
          <div class="row" style="justify-content:space-between">
            <div class="row">${icon('phone')}<div><div style="font-weight:500">Android SMS</div><div class="dim" style="font-size:12px">${devs.length ? `${devs.length} paired device${devs.length > 1 ? 's' : ''}` : 'Pair a phone to scan SMS in real time'}</div></div></div>
            <div class="row" style="font-size:12px"><span class="dot ${devs.some(recent) ? 'live' : devs.length ? 'warn' : ''}"></span>${devs.some(recent) ? 'Reporting' : devs.length ? 'Idle' : 'None'}</div>
          </div>
          ${devs.map(d => `<div class="dim" style="font-size:12px">${esc(d.name)} · ${fmtNum(d.messages_received)} SMS${d.last_seen_at ? ` · seen ${timeAgo(d.last_seen_at)}` : ' · never seen'}</div>`).join('')}
          ${!g || !devs.length ? `<a class="btn btn-sm" href="/integrations.html" style="align-self:flex-start">${icon('plug')}Connect a source</a>` : ''}`;
    }

    function feedRow(d) {
        const main = d.subject || d.target;
        const sub = d.sender || d.summary || '';
        return `<tr class="clickable" data-id="${d.id}" tabindex="0">
          <td class="nowrap dim" title="${esc(d.created_at)}">${timeAgo(d.created_at)}</td>
          <td class="nowrap">${sourceLabel(d.source)}</td>
          <td class="cell-main"><div class="t ${d.subject ? '' : 'mono'}">${esc(d.subject ? main : defang(main))}</div><div class="s">${esc(sub)}</div></td>
          <td>${verdictBadge(d.verdict)}</td>
          <td>${riskBar(d.risk)}</td></tr>`;
    }

    function renderFeed(rows) {
        $('feed').innerHTML = rows.length ? rows.map(feedRow).join('') :
            `<tr><td colspan="5"><div class="empty">${icon('alert')}<div>No detections yet. Connect Gmail or an Android phone, or investigate a link.</div></div></td></tr>`;
    }

    function hbars(el, items, labelFn, color) {
        const max = Math.max(1, ...items.map(i => i.count));
        el.innerHTML = items.length ? items.map(i => `<div class="hbar"><span class="lbl" title="${esc(labelFn(i))}">${esc(labelFn(i))}</span><span class="n">${i.count}</span>
          <div class="track"><span style="width:${i.count / max * 100}%;background:${color}"></span></div></div>`).join('') : `<div class="dim" style="font-size:12.5px">Nothing to show yet.</div>`;
    }

    async function load() {
        const o = await FS.api('/overview');
        renderKpis(o.kpis);
        renderTimeline(o.timeline);
        renderCoverage(o.integrations);
        renderFeed(o.recent);
        hbars($('indicators'), o.topIndicators, i => i.label, 'var(--serious)');
        hbars($('hosts'), o.topMaliciousHosts, i => defang(i.host), 'var(--malicious)');
        FS.setOpenCount(o.kpis.openIncidents);
    }

    $('feed').addEventListener('click', e => { const tr = e.target.closest('tr[data-id]'); if (tr) Drawer.open(tr.dataset.id); });
    $('feed').addEventListener('keydown', e => { const tr = e.target.closest('tr[data-id]'); if (tr && e.key === 'Enter') Drawer.open(tr.dataset.id); });

    let reloadTimer;
    const scheduleReload = () => { clearTimeout(reloadTimer); reloadTimer = setTimeout(() => load().catch(() => {}), 1200); };

    FS.on('detection', d => {
        const tbody = $('feed');
        if (tbody.querySelector('.empty')) tbody.innerHTML = '';
        tbody.insertAdjacentHTML('afterbegin', feedRow(d));
        tbody.firstElementChild.classList.add('flash');
        while (tbody.children.length > 25) tbody.lastElementChild.remove();
        scheduleReload();
    });
    FS.on('integration', scheduleReload);
    Drawer.onStatus(scheduleReload);
    setInterval(() => document.querySelectorAll('#feed td[title]').forEach(td => td.textContent = timeAgo(td.title)), 30000);

    load().catch(err => FS.toast(err.message, 'error'));
})();
