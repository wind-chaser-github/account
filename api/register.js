const crypto = require("node:crypto");
const {
  json,
  parseBody,
  readUserByEmail,
  writeUser,
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
  const existingUser = await readUserByEmail(email);
  if (existingUser) {
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
  await writeUser(user);
  const token = createSessionToken(user.id, user.email);
  return json(res, 201, { user: sanitizeUser(user), token });
};
