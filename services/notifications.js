'use strict';
const nodemailer = require('nodemailer');

// ── Email ────────────────────────────────────────────────────
let _transporter = null;

function getTransporter() {
  if (!_transporter) {
    _transporter = nodemailer.createTransport({
      host:   process.env.SMTP_HOST,
      port:   parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  }
  return _transporter;
}

async function sendEmail({ to, subject, text, html }) {
  if (!process.env.SMTP_HOST) {
    console.warn('[notifications] SMTP_HOST not set — skipping email to', to);
    return false;
  }
  try {
    await getTransporter().sendMail({
      from: `"${process.env.SMTP_FROM_NAME || 'BookIt'}" <${process.env.SMTP_FROM_EMAIL || process.env.SMTP_USER}>`,
      to,
      subject,
      text,
      html,
    });
    return true;
  } catch (err) {
    console.error('[notifications] email failed:', err.message);
    return false;
  }
}

// ── Cancellation code dispatch ───────────────────────────────
async function sendCancellationCode(appt, code) {
  const subject = `Cancellation code for "${appt.title}"`;
  const text =
    `Your BookIt cancellation code is: ${code}\n\n` +
    `This code expires in 15 minutes.\n` +
    `If you did not request this, please ignore this message.`;
  const html = `
    <div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto;color:#0f172a">
      <h2 style="margin-bottom:.5rem">Booking Cancellation Request</h2>
      <p style="color:#475569">You requested to cancel:</p>
      <p style="font-weight:700;font-size:1.05rem">${appt.title}</p>
      <div style="background:#f1f5f9;border-radius:10px;padding:1.5rem;text-align:center;margin:1.5rem 0">
        <p style="margin:0 0 .5rem;color:#64748b;font-size:.85rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em">Your cancellation code</p>
        <p style="margin:0;font-size:2.5rem;font-weight:800;letter-spacing:.3em;color:#0f172a">${code}</p>
      </div>
      <p style="color:#64748b;font-size:.875rem">
        This code expires in <strong>15 minutes</strong>.<br>
        If you did not request this, please ignore this message.
      </p>
    </div>
  `;

  const sent = await sendEmail({ to: appt.booked_by_email, subject, text, html });

  // If email not delivered, log to console so the code is usable during development
  if (!sent) {
    console.log(`\n  ⚠️  SMTP not configured.`);
    console.log(`  📋 Cancellation code for "${appt.title}": ${code}`);
    console.log(`     (Configure SMTP_HOST in .env to send real messages)\n`);
  }

  return { email: sent };
}

// ── Booking confirmation ─────────────────────────────────────
async function sendBookingConfirmation(appt) {
  if (!process.env.SMTP_HOST) return false;

  const fmt = iso => new Date(iso).toLocaleString('en-US', {
    timeZone: appt.timezone || 'UTC',
    weekday: 'short', month: 'short', day: 'numeric',
    year: 'numeric', hour: 'numeric', minute: '2-digit',
  });

  const subject = `Booking confirmed: ${appt.title}`;
  const text =
    `Hi ${appt.booked_by_name},\n\n` +
    `Your booking has been confirmed.\n\n` +
    `Resource: ${appt.resource_name}\n` +
    `Start:    ${fmt(appt.start_time)}\n` +
    `End:      ${fmt(appt.end_time)}\n\n` +
    `To cancel, visit the booking site and click on your appointment.`;
  const html = `
    <div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto;color:#0f172a">
      <h2>Booking Confirmed ✓</h2>
      <p>Hi ${appt.booked_by_name},</p>
      <p>Your booking has been confirmed.</p>
      <table style="width:100%;border-collapse:collapse;margin:1rem 0">
        <tr><td style="padding:.4rem 0;color:#64748b;font-size:.85rem">Resource</td>
            <td style="padding:.4rem 0;font-weight:600">${appt.resource_name}</td></tr>
        <tr><td style="padding:.4rem 0;color:#64748b;font-size:.85rem">Start</td>
            <td style="padding:.4rem 0">${fmt(appt.start_time)}</td></tr>
        <tr><td style="padding:.4rem 0;color:#64748b;font-size:.85rem">End</td>
            <td style="padding:.4rem 0">${fmt(appt.end_time)}</td></tr>
      </table>
      <p style="color:#64748b;font-size:.875rem">To cancel, visit the booking site and click on your appointment.</p>
    </div>
  `;

  return sendEmail({ to: appt.booked_by_email, subject, text, html });
}

// ── Cancellation confirmation ────────────────────────────────
async function sendCancellationConfirmation(appt) {
  if (!process.env.SMTP_HOST) return false;

  const fmt = iso => new Date(iso).toLocaleString('en-US', {
    timeZone: appt.timezone || 'UTC',
    weekday: 'short', month: 'short', day: 'numeric',
    year: 'numeric', hour: 'numeric', minute: '2-digit',
  });

  const subject = `Booking cancelled: ${appt.title}`;
  const text =
    `Hi ${appt.booked_by_name},\n\n` +
    `Your booking has been cancelled.\n\n` +
    `Resource: ${appt.resource_name}\n` +
    `Start:    ${fmt(appt.start_time)}\n` +
    `End:      ${fmt(appt.end_time)}\n\n` +
    `If this was a mistake, please visit the booking site to make a new reservation.`;
  const html = `
    <div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto;color:#0f172a">
      <h2 style="color:#b91c1c">Booking Cancelled</h2>
      <p>Hi ${appt.booked_by_name},</p>
      <p>Your booking has been cancelled.</p>
      <table style="width:100%;border-collapse:collapse;margin:1rem 0">
        <tr><td style="padding:.4rem 0;color:#64748b;font-size:.85rem">Resource</td>
            <td style="padding:.4rem 0;font-weight:600">${appt.resource_name}</td></tr>
        <tr><td style="padding:.4rem 0;color:#64748b;font-size:.85rem">Start</td>
            <td style="padding:.4rem 0">${fmt(appt.start_time)}</td></tr>
        <tr><td style="padding:.4rem 0;color:#64748b;font-size:.85rem">End</td>
            <td style="padding:.4rem 0">${fmt(appt.end_time)}</td></tr>
      </table>
      <p style="color:#64748b;font-size:.875rem">If this was a mistake, please visit the booking site to make a new reservation.</p>
    </div>
  `;

  return sendEmail({ to: appt.booked_by_email, subject, text, html });
}

// ── Password reset ───────────────────────────────────────────
async function sendPasswordReset(user, resetUrl) {
  if (!process.env.SMTP_HOST) return false;

  const subject = 'Reset your BookIt password';
  const text =
    `Hi ${user.name},\n\n` +
    `You requested a password reset for your BookIt account.\n\n` +
    `Click the link below to set a new password:\n${resetUrl}\n\n` +
    `This link expires in 1 hour.\n` +
    `If you didn't request this, you can safely ignore this email.`;
  const html = `
    <div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto;color:#0f172a">
      <h2>Reset your password</h2>
      <p>Hi ${user.name},</p>
      <p>You requested a password reset for your BookIt account. Click the button below to choose a new password.</p>
      <div style="text-align:center;margin:2rem 0">
        <a href="${resetUrl}"
           style="display:inline-block;background:#0f172a;color:#fff;text-decoration:none;
                  padding:.75rem 1.5rem;border-radius:8px;font-weight:600;font-size:.95rem">
          Reset Password
        </a>
      </div>
      <p style="color:#64748b;font-size:.875rem">
        This link expires in <strong>1 hour</strong>.<br>
        If you didn't request a password reset, you can safely ignore this email.
      </p>
      <hr style="border:none;border-top:1px solid #e2e8f0;margin:1.5rem 0">
      <p style="color:#94a3b8;font-size:.78rem">
        Can't click the button? Copy and paste this link:<br>
        <a href="${resetUrl}" style="color:#64748b;word-break:break-all">${resetUrl}</a>
      </p>
    </div>
  `;

  return sendEmail({ to: user.email, subject, text, html });
}

module.exports = { sendEmail, sendCancellationCode, sendBookingConfirmation, sendCancellationConfirmation, sendPasswordReset };
