// lib/detections.js — persist a detection, push it live, alert on high risk.

const { run, get } = require('../db');
const { publish } = require('./realtime');
const { sendHighRiskAlert } = require('../mailer');
const { log } = require('./logger');

const ALERT_THRESHOLD = 65;

function toRow(d) {
    return {
        id: d.id,
        source: d.source,
        kind: d.kind,
        sender: d.sender,
        subject: d.subject,
        target: d.target,
        risk: d.risk,
        verdict: d.verdict,
        confidence: d.confidence,
        summary: d.summary,
        status: d.status,
        created_at: d.created_at,
    };
}

/**
 * @param {number} userId
 * @param {object} opts { source, sender, subject, target, report }
 */
async function recordDetection(userId, { source, sender = null, subject = null, target, report }) {
    const { lastID } = await run(
        `INSERT INTO detections (user_id, source, kind, sender, subject, target, risk, verdict, confidence, summary, report)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [userId, source, report.kind, sender, subject, String(target).slice(0, 1000), report.risk, report.verdict,
            report.confidence ?? null, report.summary ?? null, JSON.stringify(report)]);

    const row = await get('SELECT * FROM detections WHERE id = ?', [lastID]);
    publish(userId, 'detection', toRow(row));

    if (report.risk >= ALERT_THRESHOLD) {
        get('SELECT full_name, email, email_high_risk_enabled, email_verified_at FROM users WHERE id = ?', [userId])
            .then(user => {
                // Only verified addresses: otherwise anyone could register a victim's address and
                // use FraudShield to mail them.
                if (user && user.email_high_risk_enabled && user.email_verified_at) return sendHighRiskAlert(user, row, report);
            })
            .catch(err => log.error('alert.failed', { uid: userId, message: err.message }));
    }
    return row;
}

module.exports = { recordDetection, toRow, ALERT_THRESHOLD };
