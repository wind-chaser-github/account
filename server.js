const http = require("node:http");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const STORE_FILE = path.join(DATA_DIR, "store.json");

const DEFAULT_STORE = {
  users: [],
  sessions: [],
  vaults: [],
};

function json(res, status, payload, headers = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
    ...headers,
  });
  res.end(body);
}

function text(res, status, payload, contentType = "text/plain; charset=utf-8") {
  res.writeHead(status, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
  });
  res.end(payload);
}

async function ensureStore() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.access(STORE_FILE);
  } catch {
    await fs.writeFile(STORE_FILE, JSON.stringify(DEFAULT_STORE, null, 2));
  }
}

async function readStore() {
  await ensureStore();
  const raw = await fs.readFile(STORE_FILE, "utf8");
  const parsed = JSON.parse(raw || "{}");
  return {
    users: Array.isArray(parsed.users) ? parsed.users : [],
    sessions: Array.isArray(parsed.sessions) ? parsed.sessions : [],
    vaults: Array.isArray(parsed.vaults) ? parsed.vaults : [],
  };
}

async function writeStore(store) {
  const next = JSON.stringify(store, null, 2);
  const tmp = `${STORE_FILE}.tmp`;
  await fs.writeFile(tmp, next);
  await fs.rename(tmp, STORE_FILE);
}

function readBody(req) {
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

function parseAuth(req) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) return null;
  return header.slice(7).trim();
}

function randomToken(size = 32) {
  return crypto.randomBytes(size).toString("base64url");
}

function nowIso() {
  return new Date().toISOString();
}

async function hashPassword(password, salt, iterations = 210000) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, iterations, 64, "sha256", (err, derivedKey) => {
      if (err) {
        reject(err);
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
  const a = Buffer.from(derived.hash, "base64");
  const b = Buffer.from(record.hash, "base64");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

async function authenticate(req, store) {
  const token = parseAuth(req);
  if (!token) return null;
  const session = store.sessions.find((item) => item.token === token);
  if (!session) return null;
  if (Date.parse(session.expiresAt) < Date.now()) {
    return null;
  }
  return store.users.find((user) => user.id === session.userId) || null;
}

function sanitizeUser(user) {
  return {
    id: user.id,
    email: user.email,
    createdAt: user.createdAt,
  };
}

function sanitizeVault(vault) {
  if (!vault) return null;
  return {
    userId: vault.userId,
    version: vault.version,
    salt: vault.salt,
    iv: vault.iv,
    iterations: vault.iterations,
    ciphertext: vault.ciphertext,
    updatedAt: vault.updatedAt,
  };
}

function serveStatic(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const fileMap = {
    "/": "index.html",
    "/index.html": "index.html",
    "/styles.css": "styles.css",
    "/app.js": "public/app.js",
  };
  if (url.pathname === "/favicon.ico") {
    res.writeHead(204, {
      "Cache-Control": "no-store",
    });
    res.end();
    return;
  }
  const file = fileMap[url.pathname];
  if (!file) {
    text(res, 404, "Not found");
    return;
  }
  const filePath = path.join(ROOT, file);
  fs.readFile(filePath)
    .then((content) => {
      const contentType = file.endsWith(".css")
        ? "text/css; charset=utf-8"
        : file.endsWith(".js")
          ? "application/javascript; charset=utf-8"
          : "text/html; charset=utf-8";
      res.writeHead(200, {
        "Content-Type": contentType,
        "Cache-Control": file === "index.html" ? "no-store" : "public, max-age=3600",
      });
      res.end(content);
    })
    .catch(() => text(res, 404, "Not found"));
}

async function createSession(store, userId) {
  const token = randomToken(32);
  const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString();
  store.sessions = store.sessions.filter((item) => Date.parse(item.expiresAt) > Date.now());
  store.sessions.push({
    token,
    userId,
    expiresAt,
    createdAt: nowIso(),
  });
  return { token, expiresAt };
}

async function handleApi(req, res) {
  const store = await readStore();
  store.sessions = store.sessions.filter((item) => Date.parse(item.expiresAt) > Date.now());

  if (req.method === "POST" && req.url === "/api/register") {
    const body = await readBody(req);
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!email || !password) {
      return json(res, 400, { error: "EMAIL_AND_PASSWORD_REQUIRED" });
    }
    if (store.users.some((user) => user.email === email)) {
      return json(res, 409, { error: "ACCOUNT_EXISTS" });
    }
    const salt = randomToken(16);
    const hash = await hashPassword(password, salt);
    const user = {
      id: crypto.randomUUID(),
      email,
      salt,
      iterations: hash.iterations,
      hash: hash.hash,
      createdAt: nowIso(),
    };
    store.users.push(user);
    const session = await createSession(store, user.id);
    await writeStore(store);
    return json(res, 201, { user: sanitizeUser(user), token: session.token, expiresAt: session.expiresAt });
  }

  if (req.method === "POST" && req.url === "/api/login") {
    const body = await readBody(req);
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    const user = store.users.find((item) => item.email === email);
    if (!user) {
      return json(res, 401, { error: "INVALID_CREDENTIALS" });
    }
    const ok = await verifyPassword(password, user);
    if (!ok) {
      return json(res, 401, { error: "INVALID_CREDENTIALS" });
    }
    const session = await createSession(store, user.id);
    await writeStore(store);
    return json(res, 200, { user: sanitizeUser(user), token: session.token, expiresAt: session.expiresAt });
  }

  if (req.method === "POST" && req.url === "/api/logout") {
    const token = parseAuth(req);
    if (token) {
      store.sessions = store.sessions.filter((item) => item.token !== token);
      await writeStore(store);
    }
    return json(res, 200, { ok: true });
  }

  if (req.method === "GET" && req.url === "/api/me") {
    const user = await authenticate(req, store);
    if (!user) return json(res, 401, { error: "UNAUTHENTICATED" });
    return json(res, 200, { user: sanitizeUser(user) });
  }

  if (req.method === "GET" && req.url === "/api/vault") {
    const user = await authenticate(req, store);
    if (!user) return json(res, 401, { error: "UNAUTHENTICATED" });
    const vault = store.vaults.find((item) => item.userId === user.id) || null;
    if (!vault) return json(res, 200, { exists: false, vault: null });
    return json(res, 200, { exists: true, vault: sanitizeVault(vault) });
  }

  if (req.method === "PUT" && req.url === "/api/vault") {
    const user = await authenticate(req, store);
    if (!user) return json(res, 401, { error: "UNAUTHENTICATED" });
    const body = await readBody(req);
    const envelope = body.vault || body.envelope || null;
    if (!envelope || !envelope.ciphertext || !envelope.salt || !envelope.iv) {
      return json(res, 400, { error: "INVALID_VAULT_ENVELOPE" });
    }
    const record = {
      userId: user.id,
      version: Number(envelope.version || 1),
      salt: String(envelope.salt),
      iv: String(envelope.iv),
      iterations: Number(envelope.iterations || 310000),
      ciphertext: String(envelope.ciphertext),
      updatedAt: nowIso(),
    };
    const index = store.vaults.findIndex((item) => item.userId === user.id);
    if (index >= 0) {
      store.vaults[index] = record;
    } else {
      store.vaults.push(record);
    }
    await writeStore(store);
    return json(res, 200, { ok: true, vault: sanitizeVault(record) });
  }

  return json(res, 404, { error: "NOT_FOUND" });
}

async function main() {
  await ensureStore();
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (url.pathname.startsWith("/api/")) {
      handleApi(req, res).catch((error) => {
        console.error(error);
        json(res, 500, { error: "INTERNAL_ERROR" });
      });
      return;
    }
    serveStatic(req, res);
  });

  server.listen(PORT, () => {
    console.log(`Encrypted Vault running at http://localhost:${PORT}`);
  });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
