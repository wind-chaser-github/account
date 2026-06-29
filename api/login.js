const {
  json,
  parseBody,
  readUserByEmail,
  verifyPassword,
  createSessionToken,
  sanitizeUser,
} = require("./_lib");

module.exports = async function login(req, res) {
  if (req.method !== "POST") {
    return json(res, 405, { error: "METHOD_NOT_ALLOWED" });
  }
  const body = await parseBody(req);
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  const user = await readUserByEmail(email);
  if (!user) {
    return json(res, 401, { error: "INVALID_CREDENTIALS" });
  }
  const ok = await verifyPassword(password, user);
  if (!ok) {
    return json(res, 401, { error: "INVALID_CREDENTIALS" });
  }
  const token = createSessionToken(user.id, user.email);
  return json(res, 200, { user: sanitizeUser(user), token });
};
