const { json, authenticate, sanitizeUser } = require("./_lib");

module.exports = async function me(req, res) {
  if (req.method !== "GET") {
    return json(res, 405, { error: "METHOD_NOT_ALLOWED" });
  }
  const user = authenticate(req);
  if (!user) {
    return json(res, 401, { error: "UNAUTHENTICATED" });
  }
  return json(res, 200, { user: sanitizeUser(user) });
};
