const { json } = require("./_lib");

module.exports = async function logout(req, res) {
  if (req.method !== "POST") {
    return json(res, 405, { error: "METHOD_NOT_ALLOWED" });
  }
  return json(res, 200, { ok: true });
};

