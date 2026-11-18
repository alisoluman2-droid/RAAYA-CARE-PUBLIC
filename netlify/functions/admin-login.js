
const crypto = require("node:crypto");
const admin = require("firebase-admin");

function respond(statusCode, data) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    },
    body: JSON.stringify(data)
  };
}

function equal(a, b) {
  const x = crypto.createHash("sha256").update(a).digest();
  const y = crypto.createHash("sha256").update(b).digest();
  return crypto.timingSafeEqual(x, y);
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return respond(405, { error: "Method not allowed" });
  }

  let input;
  try {
    input = JSON.parse(event.body || "{}");
  } catch {
    return respond(400, { error: "Invalid request" });
  }

  const who = input.who;
  const secret = input.secret;

  if (
    !["ali", "samar"].includes(who) ||
    typeof secret !== "string" ||
    secret.length > 256
  ) {
    return respond(400, { error: "Invalid request" });
  }

  const expected = process.env.RAAYA_ADMIN_SECRET;
  const uid = process.env[
    who === "ali" ? "RAAYA_ALI_UID" : "RAAYA_SAMAR_UID"
  ];

  if (!expected || !uid) {
    return respond(503, { error: "Login unavailable" });
  }

  if (!equal(secret, expected)) {
    return respond(401, { error: "Invalid credentials" });
  }

  try {
    if (!admin.apps.length) {
      const json = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
      if (!json) {
        return respond(503, { error: "Firebase not configured" });
      }
      admin.initializeApp({
        credential: admin.credential.cert(JSON.parse(json))
      });
    }

    await admin.auth().getUser(uid);
    const customToken = await admin.auth().createCustomToken(uid);

    return respond(200, { customToken });
  } catch {
    return respond(500, { error: "Login failed" });
  }
};
