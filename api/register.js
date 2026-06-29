const crypto = require("node:crypto");
const {
  json,
  parseBody,
  readDb,
  writeDb,
  randomToken,
  hashPassword,
  createSessionToken,
  sanitizeUser,
} = require("./_lib");

module.exports = async function register(req, res) {
  if (req.method !== "POST") {
    return json(res, 405, { error: "METHOD_NOT_ALLOWED" });
  }
  const body = await parseBody(req);
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  if (!email || !password) {
    return json(res, 400, { error: "EMAIL_AND_PASSWORD_REQUIRED" });
  }
  const db = await readDb();
  if (db.users.some((user) => user.email === email)) {
    return json(res, 409, { error: "ACCOUNT_EXISTS" });
  }
  const salt = randomToken(16);
  const derived = await hashPassword(password, salt);
  const user = {
    id: crypto.randomUUID(),
    email,
    salt,
    iterations: derived.iterations,
    hash: derived.hash,
    createdAt: new Date().toISOString(),
  };
  db.users.push(user);
  await writeDb(db);
  const token = createSessionToken(user.id);
  return json(res, 201, { user: sanitizeUser(user), token });
};

