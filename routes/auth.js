// قبل — حذفنا هذا كله
const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({...});

// بعد — Resend مباشرة بدون مكتبة إضافية
async function sendEmail(to, subject, html) {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: 'onboarding@resend.dev',
      to, subject, html
    })
  });
}
