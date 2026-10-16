// dashboard.js — minimalist light dashboard over real FraudShield data.
// Everything rendered from detections is attacker-controlled: always esc()/defang().

(async () => {
    if (!(await FS.init())) return;
    const { esc, icon, timeAgo, fmtNum, defang, SOURCES } = FS;
    const $ = id => document.getElementById(id);

    FS.banner({
        id: 'release-2026-10-live-monitoring',
        height: '2.5rem',
        message: 'New: real-time Gmail & Android SMS monitoring — every link is analysed live, no blocklists.',
        link: { href: '/integrations.html', text: 'Connect a source →' },
    });

    // ------------------------------------------------------------ components
    const metricCard = ({ title, iconName, value, sub }) => `
      <article class="ld-card ld-metric">
        <div class="ld-metric-head"><span class="ld-metric-title">${esc(title)}</span>${icon(iconName)}</div>
        <div class="ld-metric-value">${esc(value)}</div>
        <div class="ld-metric-sub">${esc(sub)}</div>
      </article>`;

    const activityRow = d => {
        const src = SOURCES[d.source] || { label: d.source, icon: 'file' };
        const title = d.subject || (/^https?:/i.test(d.target) ? defang(d.target) : d.target);
        const sub = [src.label, d.sender, timeAgo(d.created_at)].filter(Boolean).join(' · ');
        return `
          <li class="ld-row" data-id="${d.id}" tabindex="0" role="button" aria-label="Open detection ${d.id}">
            <span class="ld-row-avatar" title="${esc(src.label)}">${icon(src.icon)}</span>
            <span style="min-width:0"><div class="ld-row-title">${esc(title)}</div><div class="ld-row-sub">${esc(sub)}</div></span>
            <span class="ld-row-meta"><div class="ld-row-risk">${esc(d.risk)}<span class="dim" style="font-weight:400">/100</span></div>
              <div class="ld-row-verdict ${esc(d.verdict)}">${esc(FS.VERDICT_LABEL[d.verdict] || d.verdict)}</div></span>
          </li>`;
    };

    const sourceRow = (iconName, name, detail, state, dotClass) => `
      <div class="ld-source">
        <span class="ld-source-name">${icon(iconName)}<span style="min-width:0"><div style="font-weight:500">${esc(name)}</div><div class="dim truncate" style="font-size:12.5px">${esc(detail)}</div></span></span>
        <span class="ld-source-state"><span class="dot ${dotClass}"></span>${esc(state)}</span>
      </div>`;

    // ------------------------------------------------------------ renderers
    function renderMetrics(k) {
        const pct = (a, b) => (b ? Math.round((a / b) * 100) : 0);
        $('metrics').innerHTML = [
            { title: 'Analysed', iconName: 'activity', value: fmtNum(k.total24h), sub: `Last 24 hours · ${fmtNum(k.total7d)} in 7 days` },
            { title: 'Malicious', iconName: 'shieldAlert', value: fmtNum(k.malicious24h), sub: `${pct(k.malicious24h, k.total24h)}% of the last 24 hours` },
            { title: 'Open incidents', iconName: 'inbox', value: fmtNum(k.openIncidents), sub: 'Suspicious or malicious, awaiting triage' },
            { title: 'Time to verdict', iconName: 'clock', value: k.avgAnalysisMs != null ? `${(k.avgAnalysisMs / 1000).toFixed(1)}s` : '—', sub: k.avgConfidence != null ? `Live probe · ${k.avgConfidence}% confidence` : 'Live probe, 7-day average' },
        ].map(metricCard).join('');
    }

    const dayLabel = iso => new Date(`${iso}T00:00:00`).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });

    let chart;
    function renderTrend(trend) {
        $('range-text').textContent = `${dayLabel(trend[0].day)} – ${dayLabel(trend.at(-1).day)}, ${trend.at(-1).day.slice(0, 4)}`;
        $('trend-table').innerHTML = `<table class="data"><thead><tr><th>Day</th><th>Detections</th></tr></thead><tbody>${
            trend.map(d => `<tr><td>${esc(dayLabel(d.day))}</td><td class="mono">${d.total}</td></tr>`).join('')}</tbody></table>`;

        const labels = trend.map(d => dayLabel(d.day));
        const data = trend.map(d => d.total);
        if (chart) { chart.data.labels = labels; chart.data.datasets[0].data = data; chart.update(); return; }
        chart = new Chart($('trend'), {
            type: 'bar',
            data: { labels, datasets: [{ label: 'Detections', data, backgroundColor: '#18181b', hoverBackgroundColor: '#3f3f46', borderRadius: 4, borderSkipped: 'start', maxBarThickness: 44 }] },
            options: {
                maintainAspectRatio: false,
                animation: { duration: 300 },
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    legend: { display: false },
                    tooltip: { backgroundColor: '#18181b', titleColor: '#fff', bodyColor: '#e4e4e7', padding: 10, displayColors: false,
                        callbacks: { label: c => `${c.parsed.y} detection${c.parsed.y === 1 ? '' : 's'}` } },
                },
                scales: {
                    x: { grid: { display: false }, border: { display: false }, ticks: { color: '#777780', font: { size: 12 }, maxRotation: 0, autoSkipPadding: 10 } },
                    y: { beginAtZero: true, grid: { display: false }, border: { display: false }, ticks: { color: '#777780', font: { size: 12 }, precision: 0, maxTicksLimit: 6 } },
                },
            },
        });
    }

    function renderActivity(recent, total7d) {
        $('activity-sub').textContent = `${fmtNum(total7d)} item${total7d === 1 ? '' : 's'} analysed in the last 7 days.`;
        $('activity').innerHTML = recent.length
            ? recent.slice(0, 5).map(activityRow).join('')
            : '<li class="ld-empty">No detections yet. Investigate a link or connect Gmail / Android SMS.</li>';
    }

    function renderIndicators(items) {
        const max = Math.max(1, ...items.map(i => i.count));
        $('indicators').innerHTML = items.length ? items.slice(0, 6).map(i => `
          <div class="hbar"><span class="lbl" title="${esc(i.label)}">${esc(i.label)}</span><span class="n">${i.count}</span>
            <div class="track"><span style="width:${(i.count / max) * 100}%"></span></div></div>`).join('')
            : '<div class="ld-empty" style="padding:12px 0;text-align:left">Nothing suspicious in the last 7 days.</div>';
    }

    function renderSources(integ) {
        const g = integ.gmail;
        const devs = integ.devices || [];
        const live = g && g.live === 'live';
        const reporting = devs.some(d => d.last_seen_at && Date.now() - new Date(d.last_seen_at) < 864e5);
        $('sources').innerHTML = [
            sourceRow('mail', 'Gmail', g ? `${g.email} · ${fmtNum(g.messages_scanned)} scanned` : 'Not connected',
                g ? (live ? 'Live' : g.status) : 'Off', g ? (live ? 'live' : 'warn') : ''),
            sourceRow('phone', 'Android SMS', devs.length ? `${devs.length} device${devs.length > 1 ? 's' : ''} · ${fmtNum(devs.reduce((s, d) => s + d.messages_received, 0))} SMS` : 'No paired phone',
                devs.length ? (reporting ? 'Reporting' : 'Idle') : 'Off', devs.length ? (reporting ? 'live' : 'warn') : ''),
            sourceRow('search', 'Manual investigations', 'URLs, messages and screenshots', 'Ready', 'live'),
        ].join('');
    }

    // ------------------------------------------------------------ data
    let recent = [];
    let total7d = 0;
    async function load() {
        const o = await FS.api('/overview');
        recent = o.recent;
        total7d = o.kpis.total7d;
        renderMetrics(o.kpis);
        renderTrend(o.trend);
        renderActivity(o.recent, o.kpis.total7d);
        renderIndicators(o.topIndicators);
        renderSources(o.integrations);
        FS.setOpenCount(o.kpis.openIncidents);
    }

    const openRow = el => el && Drawer.open(el.dataset.id);
    $('activity').addEventListener('click', e => openRow(e.target.closest('.ld-row')));
    $('activity').addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openRow(e.target.closest('.ld-row')); } });

    let reloadTimer;
    const scheduleReload = () => { clearTimeout(reloadTimer); reloadTimer = setTimeout(() => load().catch(() => {}), 1200); };
    FS.on('detection', d => {
        recent = [d, ...recent];
        total7d += 1;
        renderActivity(recent, total7d);
        $('activity').firstElementChild?.classList.add('flash');
        scheduleReload();
    });
    FS.on('integration', scheduleReload);
    Drawer.onStatus(scheduleReload);

    load().catch(err => FS.toast(err.message, 'error'));
})();
