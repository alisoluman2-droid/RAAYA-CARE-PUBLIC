
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
  const x = crypto.createHash("sha256")
    .update(String(a)).digest();
  const y = crypto.createHash("sha256")
    .update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

function normalizePhone(value) {
  let phone = String(value || "")
    .replace(/[\s()+\-]/g, "");

  if (phone.startsWith("00")) {
    phone = phone.slice(2);
  }

  if (phone.startsWith("970")) {
    phone = "0" + phone.slice(3);
  } else if (phone.startsWith("972")) {
    phone = "0" + phone.slice(3);
  }

  return phone;
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return respond(405, {
      error: "Method not allowed"
    });
  }

  let input;
  try {
    input = JSON.parse(event.body || "{}");
  } catch {
    return respond(400, {
      error: "Invalid request"
    });
  }

  const who = input.who;
  const phone = input.phone;
  const secret = input.secret;

  if (
    !["ali", "samar"].includes(who) ||
    typeof phone !== "string" ||
    phone.length > 32 ||
    typeof secret !== "string" ||
    !secret ||
    secret.length > 256
  ) {
    return respond(400, {
      error: "Invalid request"
    });
  }

  const prefix = who === "ali"
    ? "RAAYA_ALI"
    : "RAAYA_SAMAR";

  const expectedPhone =
    process.env[prefix + "_PHONE"];
  const uid = process.env[prefix + "_UID"];
  const expectedSecret =
    process.env.RAAYA_ADMIN_SECRET;

  if (!expectedPhone || !uid || !expectedSecret) {
    return respond(503, {
      error: "Login unavailable"
    });
  }

  const phoneMatches = equal(
    normalizePhone(phone),
    normalizePhone(expectedPhone)
  );

  const secretMatches = equal(
    secret,
    expectedSecret
  );

  if (!phoneMatches || !secretMatches) {
    return respond(401, {
      error: "Invalid credentials"
    });
  }

  try {
    if (!admin.apps.length) {
      const json =
        process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

      if (!json) {
        return respond(503, {
          error: "Firebase not configured"
        });
      }

      admin.initializeApp({
        credential: admin.credential.cert(
          JSON.parse(json)
        )
      });
    }

    await admin.auth().getUser(uid);

    const customToken =
      await admin.auth().createCustomToken(uid);

    return respond(200, { customToken });
  } catch {
    return respond(500, {
      error: "Login failed"
    });
  }
};
