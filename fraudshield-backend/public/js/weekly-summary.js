// weekly-summary.js — period threat report.

(async () => {
    if (!(await FS.init())) return;
    const { esc, icon, riskBar, sourceLabel, fmtTime, fmtNum, defang, SOURCES, STATUS_LABEL } = FS;
    const $ = id => document.getElementById(id);
    const css = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    const VERDICTS = [['legit', 'Legit', '--legit'], ['suspicious', 'Suspicious', '--suspicious'], ['malicious', 'Malicious', '--malicious']];
    let chart;

    $('print-btn').innerHTML = `${icon('print')}Print / PDF`;
    $('print-btn').addEventListener('click', () => window.print());

    const hbars = (el, items, color) => {
        const max = Math.max(1, ...items.map(i => i.count));
        el.innerHTML = items.some(i => i.count) ? items.map(i => `<div class="hbar"><span class="lbl">${esc(i.label)}</span><span class="n">${fmtNum(i.count)}</span>
          <div class="track"><span style="width:${i.count / max * 100}%;background:${color}"></span></div></div>`).join('') : '<div class="dim">No data for this period.</div>';
    };

    function fillDays(daily, days) {
        const map = Object.fromEntries(daily.map(d => [d.day, d]));
        const out = [];
        for (let i = days - 1; i >= 0; i--) {
            const day = new Date(Date.now() - i * 864e5).toISOString().slice(0, 10);
            out.push(map[day] || { day, legit: 0, suspicious: 0, malicious: 0 });
        }
        return out;
    }

    async function load() {
        const days = Number($('days').value);
        const r = await FS.api(`/report?days=${days}`);
        $('period').textContent = `${new Date(r.from).toLocaleDateString()} – ${new Date(r.to).toLocaleDateString()} · generated ${fmtTime(r.to)}`;
        const pct = n => r.total ? `${Math.round(n / r.total * 100)}% of total` : '—';
        $('kpis').innerHTML = [
            ['Items analysed', fmtNum(r.total), `${(r.total / days).toFixed(1)} per day`],
            ['Malicious', fmtNum(r.byVerdict.malicious), pct(r.byVerdict.malicious)],
            ['Suspicious', fmtNum(r.byVerdict.suspicious), pct(r.byVerdict.suspicious)],
            ['Legit', fmtNum(r.byVerdict.legit), pct(r.byVerdict.legit)],
            ['Still open', fmtNum(r.byStatus.open), 'need triage'],
        ].map(([l, v, m]) => `<div class="panel kpi"><div class="eyebrow">${l}</div><div class="value">${v}</div><div class="meta">${m}</div></div>`).join('');

        hbars($('sources'), Object.entries(r.bySource).map(([k, n]) => ({ label: SOURCES[k]?.label || k, count: n })), 'var(--info)');
        hbars($('statuses'), Object.entries(r.byStatus).map(([k, n]) => ({ label: STATUS_LABEL[k], count: n })), 'var(--text-3)');
        hbars($('indicators'), r.topIndicators.map(i => ({ label: i.label, count: i.count })), 'var(--serious)');

        $('high').innerHTML = r.highRisk.length ? r.highRisk.map(d => `
          <tr class="clickable" data-id="${d.id}"><td class="nowrap dim">${esc(fmtTime(d.created_at))}</td><td>${sourceLabel(d.source)}</td>
            <td class="cell-main"><div class="t">${esc(d.subject || defang(d.target))}</div><div class="s">${esc(d.sender || d.summary || '')}</div></td>
            <td>${riskBar(d.risk)}</td></tr>`).join('') : '<tr><td colspan="4"><div class="empty">No malicious items in this period.</div></td></tr>';

        const series = fillDays(r.daily, days);
        const labels = series.map(d => new Date(d.day + 'T00:00:00').toLocaleDateString(undefined, { month: 'short', day: 'numeric' }));
        $('legend').innerHTML = VERDICTS.map(([, l, v]) => `<span><i style="background:var(${v})"></i>${l}</span>`).join('');
        $('daily-table').innerHTML = `<table class="data"><thead><tr><th>Day</th>${VERDICTS.map(([, l]) => `<th>${l}</th>`).join('')}</tr></thead>
          <tbody>${series.filter(d => d.legit + d.suspicious + d.malicious).map((d, i) => `<tr><td>${esc(d.day)}</td>${VERDICTS.map(([k]) => `<td class="mono">${d[k]}</td>`).join('')}</tr>`).join('') || '<tr><td colspan="4" class="dim">No data</td></tr>'}</tbody></table>`;

        chart?.destroy();
        chart = new Chart($('daily'), {
            type: 'bar',
            data: {
                labels,
                datasets: VERDICTS.map(([k, l, v]) => ({
                    label: l, data: series.map(d => d[k]), backgroundColor: css(v),
                    borderColor: css('--surface-1'), borderWidth: { top: 2 }, borderSkipped: false, borderRadius: 3, maxBarThickness: 28,
                })),
            },
            options: {
                maintainAspectRatio: false, animation: { duration: 250 },
                interaction: { mode: 'index', intersect: false },
                plugins: { legend: { display: false }, tooltip: { backgroundColor: css('--surface-3'), borderColor: css('--border-strong'), borderWidth: 1, titleColor: css('--text'), bodyColor: css('--text-2'), padding: 10 } },
                scales: {
                    x: { stacked: true, grid: { display: false }, ticks: { color: css('--text-3'), maxRotation: 0, autoSkipPadding: 12, font: { size: 11 } }, border: { color: css('--border') } },
                    y: { stacked: true, beginAtZero: true, ticks: { color: css('--text-3'), precision: 0, font: { size: 11 } }, grid: { color: css('--border') }, border: { display: false } },
                },
            },
        });
    }

    $('high').addEventListener('click', e => { const tr = e.target.closest('tr[data-id]'); if (tr) Drawer.open(tr.dataset.id); });
    $('days').addEventListener('change', () => load().catch(err => FS.toast(err.message, 'error')));
    load().catch(err => FS.toast(err.message, 'error'));
})();
