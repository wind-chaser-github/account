const crypto = require("node:crypto");
const blobStore = require("@vercel/blob");

const STORE_PREFIX = "encrypted-vault";

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

function hashKey(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

async function readJson(pathname) {
  const { get } = blobStore;
  let record;
  try {
    record = await get(pathname, { access: "private" });
  } catch (error) {
    if (error && (error.name === "BlobNotFoundError" || String(error.message).includes("not found"))) {
      return null;
    }
    throw error;
  }
  if (!record || record.statusCode === 304) {
    return null;
  }
  const raw = await new Response(record.stream).text();
  return JSON.parse(raw || "null");
}

async function writeJson(pathname, payload, options = {}) {
  const { put } = blobStore;
  await put(pathname, JSON.stringify(payload, null, 2), {
    access: "private",
    allowOverwrite: Boolean(options.allowOverwrite),
    cacheControlMaxAge: 0,
    contentType: "application/json",
  });
}

function userEmailPath(email) {
  return `${STORE_PREFIX}/users/email-${hashKey(email)}.json`;
}

async function readUserByEmail(email) {
  return readJson(userEmailPath(email));
}

async function writeUser(user) {
  await writeJson(userEmailPath(user.email), user, { allowOverwrite: false });
}

async function writeVault(userId, vault) {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const suffix = randomToken(8);
  await writeJson(`${STORE_PREFIX}/vaults/${userId}/${stamp}-${suffix}.json`, vault, {
    allowOverwrite: false,
  });
}

async function readLatestVault(userId) {
  const vaults = await readRecentVaults(userId);
  return vaults[0] || null;
}

async function readRecentVaults(userId, limit = 20) {
  const { list } = blobStore;
  const prefix = `${STORE_PREFIX}/vaults/${userId}/`;
  const result = await list({ prefix, limit: 1000 });
  const latest = result.blobs
    .filter((item) => item.pathname.endsWith(".json"))
    .sort((left, right) => String(right.pathname).localeCompare(String(left.pathname)))
    .slice(0, limit);
  const records = await Promise.all(latest.map((item) => readJson(item.pathname)));
  return records.filter(Boolean);
}

async function listVaultMetadata(userId) {
  const { list } = blobStore;
  const prefix = `${STORE_PREFIX}/vaults/${userId}/`;
  const result = await list({ prefix, limit: 1000 });
  return result.blobs
    .filter((item) => item.pathname.endsWith(".json"))
    .sort((left, right) => String(right.pathname).localeCompare(String(left.pathname)))
    .map((item) => ({
      pathname: item.pathname,
      uploadedAt: item.uploadedAt,
      size: item.size,
      urlHash: hashKey(item.url || item.pathname).slice(0, 16),
    }));
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

function createSessionToken(userId, email) {
  return createToken({
    sub: userId,
    email,
    exp: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString(),
    iat: new Date().toISOString(),
  });
}

function authenticate(req) {
  const payload = verifyToken(bearerToken(req));
  if (!payload) return null;
  return {
    id: payload.sub,
    email: payload.email || "",
    createdAt: payload.iat,
  };
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
  readUserByEmail,
  writeUser,
  readLatestVault,
  readRecentVaults,
  listVaultMetadata,
  writeVault,
  randomToken,
  hashPassword,
  verifyPassword,
  createSessionToken,
  authenticate,
  sanitizeUser,
  sanitizeVault,
};
