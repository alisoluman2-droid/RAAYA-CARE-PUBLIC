const crypto = require('node:crypto');
const admin = require('firebase-admin');

const respond = (statusCode, data) => ({
  statusCode,
  headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  body: JSON.stringify(data)
});

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = crypto.createHash('sha256').update(a, 'utf8').digest();
  const y = crypto.createHash('sha256').update(b, 'utf8').digest();
  return crypto.timingSafeEqual(x, y);
}

function normalizePhone(value) {
  if (typeof value !== 'string') return '';
  const digits = value.normalize('NFKC').replace(/[^0-9]/g, '');
  // Allow common international and local representations of Palestinian numbers.
  if (digits.startsWith('00970')) return digits.slice(5);
  if (digits.startsWith('970')) return digits.slice(3);
  if (digits.startsWith('00972')) return digits.slice(5);
  if (digits.startsWith('972')) return digits.slice(3);
  return digits.replace(/^0/, '');
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return respond(405, { error: 'Method not allowed' });
  if (event.body && event.body.length > 2048) return respond(413, { error: 'Invalid request' });
  let input;
  try { input = JSON.parse(event.body || '{}'); }
  catch { return respond(400, { error: 'Invalid request' }); }

  const { who, phone, secret } = input || {};
  if (!['ali', 'samar'].includes(who) || typeof phone !== 'string' || phone.length > 40 ||
      typeof secret !== 'string' || !secret || secret.length > 256) {
    return respond(400, { error: 'Invalid request' });
  }

  const expectedSecret = process.env.RAAYA_ADMIN_SECRET;
  const expectedPhone = process.env[who === 'ali' ? 'RAAYA_ALI_PHONE' : 'RAAYA_SAMAR_PHONE'];
  const uid = process.env[who === 'ali' ? 'RAAYA_ALI_UID' : 'RAAYA_SAMAR_UID'];
  if (!expectedSecret || !expectedPhone || !uid || !process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    return respond(503, { error: 'Login unavailable' });
  }
  const submittedPhone = normalizePhone(phone);
  const storedPhone = normalizePhone(expectedPhone);
  if (!submittedPhone || submittedPhone.length < 7 || !storedPhone ||
      !safeEqual(submittedPhone, storedPhone) || !safeEqual(secret, expectedSecret)) {
    return respond(401, { error: 'Invalid credentials' });
  }

  try {
    if (!admin.apps.length) {
      const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
      admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    }
    await admin.auth().getUser(uid);
    const customToken = await admin.auth().createCustomToken(uid);
    return respond(200, { customToken });
  } catch (error) {
    console.error('Admin login service error:', error?.code || 'internal_error');
    return respond(500, { error: 'Login failed' });
  }
};
