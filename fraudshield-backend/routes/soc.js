// routes/soc.js — analysis, detection queue, overview metrics, reports, live stream.

const express = require('express');
const multer = require('multer');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { createWorker } = require('tesseract.js');
const { run, get, all } = require('../db');
const { authenticate, requireCsrf, rateLimit, validate, httpError } = require('../lib/http');
const { log } = require('../lib/logger');
const { subscribe } = require('../lib/realtime');
const { recordDetection, toRow } = require('../lib/detections');
const { inspectImage } = require('../lib/images');
const { analyzeUrl, analyzeMessage } = require('../engine');
const gmail = require('../integrations/gmail');

const router = express.Router();
router.use(authenticate, requireCsrf);

const analysisLimiter = rateLimit({ name: 'analysis-user', windowMs: 60 * 1000, max: 30, keyFn: req => `u${req.user.id}`, message: 'Analysis rate limit reached (30/min).' });
const ocrLimiter = rateLimit({ name: 'ocr-user', windowMs: 10 * 60 * 1000, max: 10, keyFn: req => `u${req.user.id}`, message: 'Screenshot limit reached (10 per 10 minutes).' });
const screenshotUpload = multer({
    dest: os.tmpdir(),
    limits: { fileSize: 6 * 1024 * 1024, files: 1, fields: 0 },
    fileFilter: (req, file, cb) => cb(null, /^image\/(png|jpeg|webp|bmp)$/.test(file.mimetype)),
});

// ---------------------------------------------------------------- live stream
router.get('/stream', (req, res) => subscribe(req.user.id, res));

// ---------------------------------------------------------------- analysis
router.post('/analyze/url', analysisLimiter, validate({ url: { type: 'string', required: true, max: 2048, label: 'URL' } }), async (req, res) => {
    let report;
    try { report = await analyzeUrl(req.valid.url); } catch (err) {
        if (err.status) throw err;
        throw httpError(400, 'Cannot analyse this URL: it is malformed or uses an unsupported scheme.');
    }
    const detection = await recordDetection(req.user.id, { source: 'manual', target: report.url, report });
    res.json({ detection: toRow(detection), report });
});

router.post('/analyze/message', analysisLimiter, validate({
    text: { type: 'string', required: true, max: 20000, label: 'Message text' },
    sender: { type: 'string', max: 120 },
}), async (req, res) => {
    const report = await analyzeMessage({ text: req.valid.text });
    const detection = await recordDetection(req.user.id, {
        source: 'manual', sender: req.valid.sender || null,
        target: report.links[0]?.url || report.preview.slice(0, 160), report,
    });
    res.json({ detection: toRow(detection), report });
});

// OCR is CPU- and memory-heavy: one job at a time, a short queue, a hard time limit,
// and language data loaded from the bundled files (no network download at runtime).
const OCR_LANG_PATH = path.join(__dirname, '..');
const OCR_TIMEOUT_MS = 60 * 1000;
const OCR_MAX_QUEUE = 3;
let ocrBusy = false;
const ocrWaiting = [];
async function withOcrSlot(fn) {
    if (ocrBusy) {
        if (ocrWaiting.length >= OCR_MAX_QUEUE) throw httpError(503, 'The OCR service is busy. Try again in a minute.');
        await new Promise(resolve => ocrWaiting.push(resolve));
    }
    ocrBusy = true;
    try { return await fn(); } finally {
        const next = ocrWaiting.shift();
        if (next) next(); else ocrBusy = false;
    }
}

async function recognise(filePath) {
    const worker = await createWorker('eng+hin', 1, { langPath: OCR_LANG_PATH, cachePath: OCR_LANG_PATH, cacheMethod: 'readOnly', gzip: false });
    let timer;
    try {
        return await Promise.race([
            worker.recognize(filePath),
            new Promise((_, reject) => { timer = setTimeout(() => reject(httpError(422, 'The image took too long to process.')), OCR_TIMEOUT_MS); }),
        ]);
    } finally {
        clearTimeout(timer);
        await worker.terminate().catch(() => {});
    }
}

router.post('/analyze/screenshot', ocrLimiter, (req, res, next) => screenshotUpload.single('screenshot')(req, res, err => {
    if (err) return next(httpError(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400, err.code === 'LIMIT_FILE_SIZE' ? 'Screenshot must be under 6 MB.' : 'Upload rejected.'));
    next();
}), async (req, res) => {
    if (!req.file) throw httpError(400, 'Upload a PNG, JPEG, WebP or BMP screenshot under 6 MB.');
    try {
        try {
            await inspectImage(req.file.path, ['png', 'jpeg', 'webp', 'bmp']);
        } catch (err) {
            log.security('upload.rejected', { rid: req.id, uid: req.user.id, kind: 'screenshot', reason: err.message });
            throw err;
        }
        const { data } = await withOcrSlot(() => recognise(req.file.path));
        const text = (data.text || '').trim().slice(0, 20000);
        if (!text) throw httpError(422, 'No readable text was found in the image.');
        const report = await analyzeMessage({ text });
        report.ocr = { characters: text.length, confidence: Math.round(data.confidence || 0) };
        const detection = await recordDetection(req.user.id, {
            source: 'screenshot', target: report.links[0]?.url || report.preview.slice(0, 160), report,
        });
        res.json({ detection: toRow(detection), report });
    } finally {
        // eslint-disable-next-line security/detect-non-literal-fs-filename -- path is server-generated (config dir + multer/regex-validated name), never user input
        fs.promises.unlink(req.file.path).catch(() => {});
    }
});

// ---------------------------------------------------------------- detection queue
router.get('/detections', async (req, res) => {
    const where = ['user_id = ?'];
    const params = [req.user.id];
    const { verdict, source, status, q } = req.query;
    if (['legit', 'suspicious', 'malicious'].includes(verdict)) { where.push('verdict = ?'); params.push(verdict); }
    if (['manual', 'screenshot', 'gmail', 'sms'].includes(source)) { where.push('source = ?'); params.push(source); }
    if (['open', 'acknowledged', 'resolved', 'false_positive'].includes(status)) { where.push('status = ?'); params.push(status); }
    if (q) {
        where.push('(target LIKE ? OR sender LIKE ? OR subject LIKE ? OR summary LIKE ?)');
        const like = `%${String(q).slice(0, 100).replace(/[%_]/g, m => '\\' + m)}%`;
        params.push(like, like, like, like);
    }
    // SQLite treats a negative LIMIT as "no limit": clamp both ends.
    const limit = Math.min(Math.max(Math.trunc(Number(req.query.limit)) || 50, 1), 200);
    const offset = Math.min(Math.max(Math.trunc(Number(req.query.offset)) || 0, 0), 1e6);
    const clause = where.join(' AND ').replace(/LIKE \?/g, "LIKE ? ESCAPE '\\'");
    const [rows, count] = await Promise.all([
        all(`SELECT id, source, kind, sender, subject, target, risk, verdict, confidence, summary, status, created_at
             FROM detections WHERE ${clause} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`, [...params, limit, offset]),
        get(`SELECT COUNT(*) AS n FROM detections WHERE ${clause}`, params),
    ]);
    res.json({ total: count.n, items: rows });
});

const detectionId = req => {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) throw httpError(404, 'Detection not found.');
    return id;
};

// Ownership is enforced in the query itself; another user's id is indistinguishable from a missing one.
router.get('/detections/:id', async (req, res) => {
    const row = await get('SELECT * FROM detections WHERE id = ? AND user_id = ?', [detectionId(req), req.user.id]);
    if (!row) throw httpError(404, 'Detection not found.');
    res.json({ detection: toRow(row), report: JSON.parse(row.report) });
});

router.patch('/detections/:id', validate({
    status: { type: 'string', required: true, enum: ['open', 'acknowledged', 'resolved', 'false_positive'] },
}), async (req, res) => {
    const { status } = req.valid;
    const { changes } = await run('UPDATE detections SET status = ? WHERE id = ? AND user_id = ?', [status, detectionId(req), req.user.id]);
    if (!changes) throw httpError(404, 'Detection not found.');
    res.json({ message: 'Status updated.', status });
});

// ---------------------------------------------------------------- overview & reports
const daysAgoIso = d => new Date(Date.now() - d * 86400000).toISOString();

function topIndicators(rows, limit = 8) {
    const tally = new Map();
    for (const r of rows) {
        if (r.verdict === 'legit') continue;
        const report = JSON.parse(r.report);
        for (const s of report.signals || []) {
            if (s.weight <= 0.1 || s.category === 'Embedded links') continue;
            const t = tally.get(s.label) || { label: s.label, category: s.category, severity: s.severity, count: 0 };
            t.count++;
            tally.set(s.label, t);
        }
        for (const l of report.links || []) {
            for (const s of l.report?.signals || []) {
                if (s.weight <= 0.1) continue;
                const t = tally.get(s.label) || { label: s.label, category: s.category, severity: s.severity, count: 0 };
                t.count++;
                tally.set(s.label, t);
            }
        }
    }
    return [...tally.values()].sort((a, b) => b.count - a.count).slice(0, limit);
}

function hostOf(target) {
    try { return new URL(/^https?:/i.test(target) ? target : `https://${target}`).hostname; } catch { return null; }
}

router.get('/overview', async (req, res) => {
    const uid = req.user.id;
    const since24 = daysAgoIso(1);
    const since7 = daysAgoIso(7);
    const [k24, k7, open, rows7, recent, gmailRow, devices] = await Promise.all([
        get(`SELECT COUNT(*) total, SUM(CASE WHEN verdict = 'malicious' THEN 1 ELSE 0 END) malicious, SUM(CASE WHEN verdict = 'suspicious' THEN 1 ELSE 0 END) suspicious, SUM(CASE WHEN verdict = 'legit' THEN 1 ELSE 0 END) legit
             FROM detections WHERE user_id = ? AND created_at >= ?`, [uid, since24]),
        get(`SELECT COUNT(*) total, SUM(CASE WHEN verdict = 'malicious' THEN 1 ELSE 0 END) malicious, AVG(confidence) confidence FROM detections WHERE user_id = ? AND created_at >= ?`, [uid, since7]),
        get(`SELECT COUNT(*) n FROM detections WHERE user_id = ? AND status = 'open' AND verdict != 'legit'`, [uid]),
        all('SELECT verdict, source, target, report, created_at FROM detections WHERE user_id = ? AND created_at >= ? ORDER BY id DESC LIMIT 1000', [uid, since7]),
        all(`SELECT id, source, kind, sender, subject, target, risk, verdict, confidence, summary, status, created_at
             FROM detections WHERE user_id = ? ORDER BY id DESC LIMIT 25`, [uid]),
        get('SELECT email, status, last_error, messages_scanned, last_event_at, enabled FROM gmail_accounts WHERE user_id = ?', [uid]),
        all('SELECT id, name, platform, messages_received, last_seen_at FROM devices WHERE user_id = ? ORDER BY id', [uid]),
    ]);

    // 12-day daily totals for the dashboard bar chart (aggregated in SQL; scoped to the user).
    const trendRows = await all(`SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS n FROM detections
                                 WHERE user_id = ? AND created_at >= ? GROUP BY day`, [uid, daysAgoIso(12)]);
    const trendMap = new Map(trendRows.map(r => [r.day, r.n]));
    const trend = [];
    for (let i = 11; i >= 0; i--) {
        const day = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
        trend.push({ day, total: trendMap.get(day) || 0 });
    }

    const timeline = [];
    for (let i = 6; i >= 0; i--) {
        const day = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
        timeline.push({ day, legit: 0, suspicious: 0, malicious: 0 });
    }
    const bySource = { manual: 0, screenshot: 0, gmail: 0, sms: 0 };
    const maliciousHosts = new Map();
    let durationSum = 0, durationN = 0;
    for (const r of rows7) {
        const t = timeline.find(d => d.day === r.created_at.slice(0, 10));
        if (t) t[r.verdict]++;
        bySource[r.source]++;
        if (r.verdict === 'malicious') {
            const h = hostOf(r.target);
            if (h) maliciousHosts.set(h, (maliciousHosts.get(h) || 0) + 1);
        }
        const d = JSON.parse(r.report).durationMs;
        if (d) { durationSum += d; durationN++; }
    }

    res.json({
        kpis: {
            total24h: k24.total || 0,
            malicious24h: k24.malicious || 0,
            suspicious24h: k24.suspicious || 0,
            legit24h: k24.legit || 0,
            total7d: k7.total || 0,
            malicious7d: k7.malicious || 0,
            openIncidents: open.n || 0,
            avgConfidence: k7.confidence ? Math.round(k7.confidence) : null,
            avgAnalysisMs: durationN ? Math.round(durationSum / durationN) : null,
        },
        timeline,
        trend,
        bySource,
        topIndicators: topIndicators(rows7),
        topMaliciousHosts: [...maliciousHosts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([host, count]) => ({ host, count })),
        recent,
        integrations: {
            gmail: gmailRow ? { ...gmailRow, live: gmail.watcherStatus(uid) } : null,
            devices,
        },
    });
});

router.get('/report', async (req, res) => {
    const days = Math.min(Math.max(Number(req.query.days) || 7, 1), 90);
    const since = daysAgoIso(days);
    const rows = await all('SELECT id, source, verdict, risk, target, sender, subject, summary, status, report, created_at FROM detections WHERE user_id = ? AND created_at >= ? ORDER BY id DESC', [req.user.id, since]);
    const byVerdict = { legit: 0, suspicious: 0, malicious: 0 };
    const bySource = { manual: 0, screenshot: 0, gmail: 0, sms: 0 };
    const byStatus = { open: 0, acknowledged: 0, resolved: 0, false_positive: 0 };
    const daily = {};
    for (const r of rows) {
        byVerdict[r.verdict]++; bySource[r.source]++; byStatus[r.status]++;
        const d = r.created_at.slice(0, 10);
        daily[d] = daily[d] || { day: d, legit: 0, suspicious: 0, malicious: 0 };
        daily[d][r.verdict]++;
    }
    res.json({
        days, from: since, to: new Date().toISOString(),
        total: rows.length, byVerdict, bySource, byStatus,
        daily: Object.values(daily).sort((a, b) => a.day.localeCompare(b.day)),
        topIndicators: topIndicators(rows, 10),
        highRisk: rows.filter(r => r.verdict === 'malicious').slice(0, 20).map(({ report, ...r }) => r),
    });
});

// Kept for older clients.
router.get('/user/summary', async (req, res) => {
    const rows = await all('SELECT source, verdict FROM detections WHERE user_id = ? AND created_at >= ?', [req.user.id, daysAgoIso(7)]);
    res.json({
        totalScans: rows.length,
        threats: rows.filter(r => r.verdict !== 'legit').length,
        legit: rows.filter(r => r.verdict === 'legit').length,
        types: rows.reduce((t, r) => (t[r.source] = (t[r.source] || 0) + 1, t), {}),
    });
});

module.exports = router;
