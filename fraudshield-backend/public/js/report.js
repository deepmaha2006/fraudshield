// report.js — renders an engine report (URL or message) as an analyst view.

const Report = (() => {
    const { esc, icon, verdictBadge, riskColor, defang, fmtTime, sourceLabel } = FS;

    function gauge(risk, verdict) {
        const r = 42, c = 2 * Math.PI * r;
        return `<div class="gauge" role="img" aria-label="Risk ${risk} of 100, ${verdict}">
          <svg viewBox="0 0 100 100"><circle cx="50" cy="50" r="${r}" fill="none" stroke="var(--surface-3)" stroke-width="7"/>
          <circle cx="50" cy="50" r="${r}" fill="none" stroke="${riskColor(risk)}" stroke-width="7" stroke-linecap="round"
            stroke-dasharray="${(risk / 100) * c} ${c}"/></svg>
          <div class="score"><div><b>${risk}</b><small>RISK</small></div></div></div>`;
    }

    function pipeline(stages = []) {
        if (!stages.length) return '';
        return `<div class="pipeline">${stages.map(s => `
          <span class="stage ${esc(s.status)}" title="${esc(s.error || s.status)}"><span class="s-dot"></span>${esc(s.name)}
          ${s.ms ? `<span class="ms">${s.ms}ms</span>` : ''}</span>`).join('')}</div>`;
    }

    function signalsTable(signals = []) {
        if (!signals.length) return `<div class="empty">No indicators were raised.</div>`;
        return `<table class="signals"><tbody>${signals.map(s => `
          <tr>
            <td style="width:96px"><span class="sev ${esc(s.severity)}">${esc(s.severity)}</span></td>
            <td><div class="lbl">${esc(s.label)}</div><div class="det">${esc(s.detail)}</div></td>
            <td class="cat">${esc(s.category)}</td>
            <td class="w" title="Contribution to the risk model">${s.weight > 0 ? '+' : '−'}${Math.abs(s.weight).toFixed(2)}</td>
          </tr>`).join('')}</tbody></table>`;
    }

    const kv = rows => `<dl class="kv">${rows.filter(([, v]) => v !== undefined && v !== null && v !== '')
        .map(([k, v, raw]) => `<dt>${esc(k)}</dt><dd>${raw ? v : esc(v)}</dd>`).join('')}</dl>`;
    const panel = (title, ico, body) => `<section class="panel"><div class="panel-head">${icon(ico)}<h3>${esc(title)}</h3></div><div class="panel-body">${body}</div></section>`;
    const mono = v => `<span class="mono">${esc(v)}</span>`;
    const days = n => n == null ? null : n >= 365 ? `${(n / 365).toFixed(1)} years (${n} days)` : `${n} days`;

    function urlEvidence(rep) {
        const e = rep.evidence || {};
        const out = [];
        const u = e.url;
        if (u) {
            out.push(panel('URL anatomy', 'link', kv([
                ['Scheme', u.scheme], ['Host', mono(u.host), true],
                ['Displays as', u.unicodeHost !== u.host ? mono(u.unicodeHost) : null, true],
                ['Registrable', mono(u.registrableDomain), true], ['Subdomain', u.subdomain ? mono(u.subdomain) : null, true],
                ['Public suffix', u.publicSuffix], ['Port', u.port], ['Path', u.path !== '/' ? mono(u.path) : null, true],
                ['Length', `${u.length} chars`], ['Label entropy', `${u.hostEntropy} bits/char`],
            ])));
        }
        if (e.http) {
            const chain = e.http.chain.map(h => `<li><span class="code">${esc(h.status)}</span>${esc(h.url)}<div class="dim">${esc(h.ip)} · ${h.timeMs}ms${h.server ? ' · ' + esc(h.server) : ''}</div></li>`).join('');
            out.push(panel(`Redirect chain · ${e.http.chain.length} hop${e.http.chain.length > 1 ? 's' : ''}`, 'globe',
                `<ol class="chain">${chain}</ol>${kv([['Final status', e.http.finalStatus], ['Content type', e.http.contentType], ['Body size', e.http.bytes ? `${(e.http.bytes / 1024).toFixed(1)} KB` : null]])}`));
        }
        if (e.tls) {
            const t = e.tls;
            out.push(panel('TLS certificate', 'lock', kv([
                ['Trusted', t.authorized ? '<span class="sev trust">valid chain</span>' : `<span class="sev critical">${esc(t.authorizationError || 'untrusted')}</span>`, true],
                ['Subject CN', t.subject?.CN], ['Organisation', t.subject?.O], ['Issuer', [t.issuer?.O, t.issuer?.CN].filter(Boolean).join(' · ')],
                ['Valid from', t.validFrom?.slice(0, 10)], ['Valid to', t.validTo?.slice(0, 10)], ['Certificate age', days(t.ageDays)],
                ['Protocol', t.protocol], ['SANs', t.sans?.length ? mono(t.sans.slice(0, 6).join(', ') + (t.sans.length > 6 ? ` +${t.sans.length - 6}` : '')) : null, true],
                ['SHA-256', t.fingerprint256 ? `<span class="mono dim">${esc(t.fingerprint256.slice(0, 47))}…</span>` : null, true],
            ])));
        }
        if (e.dns) {
            const d = e.dns;
            out.push(panel('DNS', 'server', kv([
                ['A', d.a?.length ? mono(d.a.map(r => r.address + (r.ttl != null ? ` (ttl ${r.ttl})` : '')).join(', ')) : 'none', true],
                ['AAAA', d.aaaa?.length ? mono(d.aaaa.slice(0, 3).join(', ')) : null, true],
                ['MX', d.mx?.length ? mono(d.mx.slice(0, 3).join(', ')) : (d.recordQueries ? 'none' : 'n/a'), true],
                ['NS', d.ns?.length ? mono(d.ns.slice(0, 4).join(', ')) : null, true],
                ['SPF', d.spf ? mono(d.spf.slice(0, 120)) : (d.recordQueries ? 'none' : 'n/a'), true],
                ['DMARC', d.dmarc ? mono(d.dmarc.slice(0, 120)) : (d.recordQueries ? 'none' : 'n/a'), true],
            ])));
        }
        for (const [key, title] of [['registration', 'Domain registration (RDAP)'], ['originRegistration', 'Redirector registration (RDAP)']]) {
            const r = e[key];
            if (!r) continue;
            out.push(panel(title, 'file', r.found === false ? `<div class="callout danger">${esc(r.domain)} is not registered.</div>` : kv([
                ['Domain', mono(r.domain), true], ['Age', days(r.ageDays)], ['Registered', r.registered?.slice(0, 10)],
                ['Expires', r.expires?.slice(0, 10)], ['Registrar', r.registrar], ['Status', r.status?.join(', ')],
            ])));
        }
        if (e.content) {
            const c = e.content;
            out.push(panel('Landing page behaviour', 'file', kv([
                ['Title', c.title], ['Claims to be', c.claimedBrand], ['Forms', c.forms], ['Password fields', c.passwordFields],
                ['Sensitive fields', c.sensitiveFields?.length ? c.sensitiveFields.join('; ') : null],
                ['Form targets', c.formTargets?.length ? mono(c.formTargets.join(', ')) : null, true],
                ['External assets', c.externalResourceDomains?.length ? mono(c.externalResourceDomains.map(d => `${d.domain} ×${d.count}`).join(', ')) : null, true],
                ['Links', c.links], ['Page size', `${(c.bytes / 1024).toFixed(1)} KB`],
            ])));
        }
        return out.length ? `<div class="evidence">${out.join('')}</div>` : '';
    }

    function messageEvidence(rep) {
        const out = [];
        const s = rep.evidence?.sender;
        if (s) {
            const res = v => v ? `<span class="sev ${v === 'pass' ? 'trust' : v === 'none' ? 'info' : 'critical'}">${esc(v)}</span>` : '<span class="dim">not reported</span>';
            out.push(panel('Sender & authentication', 'mail', kv([
                ['Display name', s.name], ['Address', mono(s.address), true], ['Reply-To', s.replyTo ? mono(s.replyTo) : null, true],
                ['SPF', res(s.auth?.spf), true], ['DKIM', res(s.auth?.dkim), true], ['DMARC', res(s.auth?.dmarc), true],
            ])));
        }
        const ch = rep.channel;
        if (ch) {
            out.push(panel('Channel', ch.type === 'sms' ? 'phone' : 'mail', kv([
                ['Type', ch.type === 'sms' ? 'Android SMS' : 'Gmail (IMAP IDLE)'], ['Device', ch.device], ['Mailbox', ch.mailbox],
                ['Sender', ch.sender], ['Received', ch.receivedAt || ch.date ? fmtTime(ch.receivedAt || ch.date) : null], ['Message-ID', ch.messageId ? mono(ch.messageId) : null, true],
            ])));
        }
        if (rep.ocr) out.push(panel('OCR', 'image', kv([['Characters read', rep.ocr.characters], ['OCR confidence', `${rep.ocr.confidence}%`]])));
        if (rep.preview) {
            out.push(panel('Message content', 'message', `<div class="mono" style="white-space:pre-wrap;color:var(--text-2);max-height:220px;overflow:auto">${esc(rep.preview)}</div>`));
        }
        return out.length ? `<div class="evidence">${out.join('')}</div>` : '';
    }

    function linksSection(rep) {
        if (!rep.links?.length) return '';
        return `<section class="panel" style="margin:0 16px 16px"><div class="panel-head">${icon('link')}<h3>Embedded links</h3>
          <span class="sub">${rep.links.length} analysed live${rep.evidence?.urlsFound > rep.links.length ? ` of ${rep.evidence.urlsFound} found` : ''}</span></div>
          <div class="links-list">${rep.links.map(l => `
            <details class="link-item">
              <summary>${verdictBadge(l.verdict)}<span class="mono truncate">${esc(defang(l.finalUrl || l.url))}</span><span class="mono dim">${l.risk}/100</span></summary>
              <div>${l.report ? urlBody(l.report, true) : `<div class="panel-body muted">${esc(l.summary)}</div>`}</div>
            </details>`).join('')}</div></section>`;
    }

    function urlBody(rep, nested = false) {
        return `${nested ? pipeline(rep.stages) : ''}
          <div class="panel-head" style="border-top:${nested ? '0' : '1px solid var(--border)'}"><h3>Indicators</h3><span class="sub">${rep.signals?.length || 0} signals · noisy-OR risk model</span></div>
          ${signalsTable(rep.signals)}${urlEvidence(rep)}`;
    }

    /** Render a full report. `detection` (optional) adds source / time / sender context. */
    function render(container, rep, detection) {
        const isUrl = rep.kind === 'url';
        const target = isUrl ? rep.url : (rep.links?.[0]?.url || rep.preview?.slice(0, 160) || '');
        container.innerHTML = `
          <div class="verdict-hero">
            ${gauge(rep.risk, rep.verdict)}
            <div style="min-width:0">
              <div class="verdict-title">${verdictBadge(rep.verdict)}<span>${esc(rep.summary || '')}</span></div>
              <div class="verdict-meta">
                ${detection ? `<span>${sourceLabel(detection.source)}</span>` : ''}
                <span>Confidence <b>${rep.confidence ?? '—'}%</b></span>
                <span>Analysed in <b>${rep.durationMs != null ? (rep.durationMs / 1000).toFixed(1) + 's' : '—'}</b>${rep.cached ? ' (cached)' : ''}</span>
                <span>${esc(fmtTime(rep.analyzedAt || detection?.created_at || Date.now()))}</span>
                ${detection?.sender ? `<span>From <b>${esc(detection.sender)}</b></span>` : ''}
              </div>
              ${detection?.subject ? `<div style="margin-top:8px;font-weight:500">${esc(detection.subject)}</div>` : ''}
              ${target ? `<div class="ioc" title="Defanged — safe to copy into tickets">${esc(isUrl || /^https?:/i.test(target) ? defang(target) : target)}</div>` : ''}
              ${isUrl && rep.finalUrl && rep.finalUrl !== rep.url ? `<div class="dim mono" style="margin-top:6px;font-size:12px">→ lands on ${esc(defang(rep.finalUrl))}</div>` : ''}
            </div>
            <div class="row no-print">
              ${target && /^https?:/i.test(target) ? `<button class="btn btn-sm" data-act="copy-ioc">${icon('copy')}Copy IOC</button>` : ''}
              <button class="btn btn-sm" data-act="export">${icon('download')}JSON</button>
            </div>
          </div>
          ${isUrl ? pipeline(rep.stages) : ''}
          ${isUrl ? urlBody(rep) : `
            <div class="panel-head"><h3>Indicators</h3><span class="sub">${rep.signals?.length || 0} signals</span></div>
            ${signalsTable(rep.signals)}
            ${messageEvidence(rep)}
            ${linksSection(rep)}`}`;

        container.querySelector('[data-act="copy-ioc"]')?.addEventListener('click', () => FS.copy(defang(target)));
        container.querySelector('[data-act="export"]').addEventListener('click', () =>
            FS.download(`fraudshield-${detection?.id || 'report'}-${rep.verdict}.json`, JSON.stringify({ detection, report: rep }, null, 2)));
    }

    function renderPending(container, label, stages) {
        container.innerHTML = `
          <div class="verdict-hero"><div class="gauge"><div class="score"><span class="spinner"></span></div></div>
            <div><div class="verdict-title">Analysing…</div><div class="ioc">${esc(label)}</div></div><div></div></div>
          <div class="pipeline">${stages.map(s => `<span class="stage running"><span class="s-dot"></span>${esc(s)}</span>`).join('')}</div>
          <div class="empty">Resolving, connecting and inspecting the target in real time.</div>`;
    }

    return { render, renderPending };
})();
