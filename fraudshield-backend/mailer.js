// mailer.js — alert and account e-mails.
// Content originates from attackers (subjects, senders, URLs), so every value
// is HTML-escaped and every URL is defanged so it cannot be clicked.

const nodemailer = require('nodemailer');
const config = require('./lib/config');
const { log } = require('./lib/logger');

const ALERT_HEADER = 'X-FraudShield-Alert';

// In-memory outbox for MAIL_TRANSPORT=memory (tests); never used in production.
const outbox = [];

function createTransport() {
    const m = config.mail;
    switch (m.transport) {
        case 'gmail':
            // Port 465, implicit TLS, certificate verified (nodemailer default).
            return nodemailer.createTransport({ service: 'gmail', auth: { user: m.gmailUser, pass: m.gmailPass }, tls: { minVersion: 'TLSv1.2' } });
        case 'smtp':
            return nodemailer.createTransport({
                host: m.smtpHost, port: m.smtpPort, secure: [465, 2465].includes(m.smtpPort), requireTLS: ![465, 2465].includes(m.smtpPort),
                auth: m.smtpUser ? { user: m.smtpUser, pass: m.smtpPass } : undefined,
                tls: { minVersion: 'TLSv1.2', rejectUnauthorized: true },
            });
        case 'memory':
            return { sendMail: async msg => { outbox.push(msg); return { messageId: `memory-${outbox.length}` }; } };
        default:
            return null;
    }
}
const transporter = createTransport();
if (!config.isTest) {
    const m = config.mail;
    if (m.transport === 'gmail') log.info('mail.configured', { transport: 'gmail' });
    else if (m.transport === 'smtp') log.info('mail.configured', { transport: 'smtp', host: m.smtpHost, port: m.smtpPort, secure: [465, 2465].includes(m.smtpPort) });
    else log.warn('mail.not_configured', { transport: m.transport });
}
const fromAddress = () => `"FraudShield SOC" <${config.mail.from || 'no-reply@fraudshield.invalid'}>`;
// eslint-disable-next-line no-control-regex -- deliberately strips control characters (log/header injection defence)
const oneLine = s => String(s ?? '').replace(/[\r\n\u0000-\u001f]+/g, ' ').trim();

async function send(msg, kind) {
    if (!transporter) {
        log.warn('mail.not_sent', { kind, reason: 'no transport configured' });
        return false;
    }
    try {
        await transporter.sendMail({ from: fromAddress(), ...msg, subject: oneLine(msg.subject).slice(0, 200) });
        log.info('mail.sent', { kind });
        return true;
    } catch (error) {
        log.error('mail.failed', { kind, code: error.code, message: error.message });
        return false;
    }
}

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const defang = s => String(s ?? '').replace(/^http/i, 'hxxp').replace(/\./g, '[.]');

const SOURCE_LABEL = { manual: 'Manual investigation', screenshot: 'Screenshot OCR', gmail: 'Gmail inbox', sms: 'Android SMS' };
const SEV_COLOR = { critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#2563eb', info: '#64748b', trust: '#16a34a' };

async function sendHighRiskAlert(user, detection, report) {
    const indicators = (report.signals || []).filter(s => s.weight > 0).slice(0, 6).map(s => `
        <tr>
          <td style="padding:6px 10px;border-bottom:1px solid #e5e7eb;font:600 11px monospace;color:${SEV_COLOR[s.severity] || '#334155'};text-transform:uppercase;white-space:nowrap">${esc(s.severity)}</td>
          <td style="padding:6px 10px;border-bottom:1px solid #e5e7eb;font:13px Arial,sans-serif;color:#0f172a"><b>${esc(s.label)}</b><br><span style="color:#475569">${esc(defang(s.detail).slice(0, 240))}</span></td>
        </tr>`).join('');

    const html = `
    <div style="max-width:640px;margin:auto;font-family:Arial,sans-serif;border:1px solid #cbd5e1;border-radius:6px;overflow:hidden">
      <div style="background:#0b1220;color:#e2e8f0;padding:18px 22px">
        <div style="font:600 11px monospace;letter-spacing:.12em;color:#22d3ee">FRAUDSHIELD SOC · DETECTION #${esc(detection.id)}</div>
        <div style="font-size:20px;font-weight:700;margin-top:6px">${esc(detection.verdict.toUpperCase())} — risk ${esc(detection.risk)}/100</div>
      </div>
      <div style="padding:20px 22px;color:#0f172a">
        <p style="margin:0 0 12px">Hello ${esc(user.full_name || '')}, a high-risk item was detected and logged to your console.</p>
        <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:16px">
          <tr><td style="padding:4px 0;color:#64748b;width:110px">Source</td><td>${esc(SOURCE_LABEL[detection.source] || detection.source)}</td></tr>
          ${detection.sender ? `<tr><td style="padding:4px 0;color:#64748b">Sender</td><td>${esc(detection.sender)}</td></tr>` : ''}
          ${detection.subject ? `<tr><td style="padding:4px 0;color:#64748b">Subject</td><td>${esc(detection.subject)}</td></tr>` : ''}
          <tr><td style="padding:4px 0;color:#64748b">Target</td><td style="font-family:monospace">${esc(defang(detection.target).slice(0, 200))}</td></tr>
          <tr><td style="padding:4px 0;color:#64748b">Confidence</td><td>${esc(detection.confidence)}%</td></tr>
        </table>
        <div style="font:600 11px monospace;letter-spacing:.1em;color:#64748b;margin-bottom:6px">TOP INDICATORS</div>
        <table style="width:100%;border-collapse:collapse">${indicators}</table>
        <div style="margin-top:18px;padding:12px 14px;background:#fef2f2;border-left:4px solid #dc2626;font-size:13px">
          Do not open the link, reply, call back, or share OTPs / PINs. Delete the message and block the sender.
        </div>
      </div>
      <div style="background:#f1f5f9;color:#64748b;font-size:11px;padding:12px 22px">Links in this alert are defanged (hxxp, [.]) on purpose. You receive this because high-risk alerts are enabled in your FraudShield settings. <a href="${esc(config.publicBaseUrl)}/profile.html" style="color:#0e7490">Manage alert preferences</a>.</div>
    </div>`;

    return send({
        to: user.email,
        subject: `[FraudShield] ${detection.verdict.toUpperCase()} ${detection.risk}/100 — ${defang(detection.subject || detection.target || '').slice(0, 60)}`,
        html,
        headers: { [ALERT_HEADER]: '1' },
    }, 'alert');
}

/** Password reset link. The token is single-use, expires in 30 minutes and is never logged. */
async function sendPasswordReset(user, resetUrl) {
    const html = `
    <div style="max-width:560px;margin:auto;font-family:Arial,sans-serif;color:#0f172a">
      <h2 style="margin:0 0 12px">Reset your FraudShield password</h2>
      <p>Hello ${esc(user.full_name || '')}, someone (hopefully you) asked to reset the password for this account.</p>
      <p><a href="${esc(resetUrl)}" style="display:inline-block;background:#0e7490;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none">Choose a new password</a></p>
      <p style="font-size:13px;color:#475569">The link works once and expires in 30 minutes. If you did not request it, ignore this e-mail — your password stays unchanged. Completing a reset signs out every active session.</p>
    </div>`;
    return send({
        to: user.email,
        subject: 'Reset your FraudShield password',
        html,
        text: `Reset your FraudShield password (valid 30 minutes, single use): ${resetUrl}\nIf you did not request this, ignore this e-mail.`,
        headers: { [ALERT_HEADER]: '1' },
    }, 'password_reset');
}

/** E-mail ownership confirmation. Single use, 24 hours. */
async function sendEmailVerification(user, verifyUrl) {
    const html = `
    <div style="max-width:560px;margin:auto;font-family:Arial,sans-serif;color:#0f172a">
      <h2 style="margin:0 0 12px">Confirm your e-mail for FraudShield</h2>
      <p>Hello ${esc(user.full_name || '')}, confirm this address to receive high-risk alerts.</p>
      <p><a href="${esc(verifyUrl)}" style="display:inline-block;background:#0e7490;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none">Confirm e-mail address</a></p>
      <p style="font-size:13px;color:#475569">The link works once and expires in 24 hours. If you did not create a FraudShield account, ignore this e-mail.</p>
    </div>`;
    return send({
        to: user.email,
        subject: 'Confirm your FraudShield e-mail address',
        html,
        text: `Confirm your FraudShield e-mail address (valid 24 hours, single use): ${verifyUrl}`,
        headers: { [ALERT_HEADER]: '1' },
    }, 'email_verification');
}

module.exports = { sendHighRiskAlert, sendPasswordReset, sendEmailVerification, ALERT_HEADER, outbox };
