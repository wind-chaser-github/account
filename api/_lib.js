const crypto = require("node:crypto");

const DB_PATH = "encrypted-vault/db.json";
const DEFAULT_DB = {
  users: [],
  vaults: {},
};

function json(res, status, payload, headers = {}) {
  const body = JSON.stringify(payload);
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  for (const [key, value] of Object.entries(headers)) {
    res.setHeader(key, value);
  }
  res.end(body);
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      if (!chunks.length) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });
}

async function blobSdk() {
  return import("@vercel/blob");
}

async function readDb() {
  const { get } = await blobSdk();
  const blob = await get(DB_PATH, { access: "private" });
  if (!blob || blob.statusCode === 304) {
    return structuredClone(DEFAULT_DB);
  }
  const raw = await new Response(blob.stream).text();
  const parsed = JSON.parse(raw || "{}");
  return {
    users: Array.isArray(parsed.users) ? parsed.users : [],
    vaults: parsed.vaults && typeof parsed.vaults === "object" ? parsed.vaults : {},
  };
}

async function writeDb(db) {
  const { put } = await blobSdk();
  await put(DB_PATH, JSON.stringify(db, null, 2), {
    access: "private",
    allowOverwrite: true,
    contentType: "application/json",
  });
}

function randomToken(size = 32) {
  return crypto.randomBytes(size).toString("base64url");
}

async function hashPassword(password, salt, iterations = 210000) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, iterations, 64, "sha256", (error, derivedKey) => {
      if (error) {
        reject(error);
        return;
      }
      resolve({
        iterations,
        salt,
        hash: derivedKey.toString("base64"),
      });
    });
  });
}

async function verifyPassword(password, record) {
  const derived = await hashPassword(password, record.salt, record.iterations);
  const left = Buffer.from(derived.hash, "base64");
  const right = Buffer.from(record.hash, "base64");
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function authSecret() {
  const secret = process.env.AUTH_SECRET;
  if (!secret) {
    throw new Error("AUTH_SECRET is required");
  }
  return secret;
}

function createToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.createHmac("sha256", authSecret()).update(body).digest("base64url");
  return `${body}.${signature}`;
}

function verifyToken(token) {
  if (!token || typeof token !== "string") return null;
  const [body, signature] = token.split(".");
  if (!body || !signature) return null;
  const expected = crypto.createHmac("sha256", authSecret()).update(body).digest("base64url");
  const left = Buffer.from(signature);
  const right = Buffer.from(expected);
  if (left.length !== right.length) return null;
  if (!crypto.timingSafeEqual(left, right)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (!payload.exp || Date.parse(payload.exp) < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function bearerToken(req) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) return null;
  return header.slice(7).trim();
}

function createSessionToken(userId) {
  return createToken({
    sub: userId,
    exp: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString(),
    iat: new Date().toISOString(),
  });
}

function authenticate(req, db) {
  const payload = verifyToken(bearerToken(req));
  if (!payload) return null;
  return db.users.find((user) => user.id === payload.sub) || null;
}

function sanitizeUser(user) {
  return {
    id: user.id,
    email: user.email,
    createdAt: user.createdAt,
  };
}

function sanitizeVault(vault) {
  return vault ? { ...vault } : null;
}

module.exports = {
  json,
  parseBody,
  readDb,
  writeDb,
  randomToken,
  hashPassword,
  verifyPassword,
  createSessionToken,
  authenticate,
  sanitizeUser,
  sanitizeVault,
};

