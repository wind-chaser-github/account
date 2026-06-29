const {
  json,
  parseBody,
  readDb,
  writeDb,
  authenticate,
  sanitizeVault,
} = require("./_lib");

module.exports = async function vault(req, res) {
  const db = await readDb();
  const user = authenticate(req, db);
  if (!user) {
    return json(res, 401, { error: "UNAUTHENTICATED" });
  }

  if (req.method === "GET") {
    const vaultRecord = db.vaults[user.id] || null;
    return json(res, 200, { exists: Boolean(vaultRecord), vault: sanitizeVault(vaultRecord) });
  }

  if (req.method === "PUT") {
    const body = await parseBody(req);
    const envelope = body.vault || body.envelope || null;
    if (!envelope || !envelope.ciphertext || !envelope.salt || !envelope.iv) {
      return json(res, 400, { error: "INVALID_VAULT_ENVELOPE" });
    }
    db.vaults[user.id] = {
      userId: user.id,
      version: Number(envelope.version || 1),
      salt: String(envelope.salt),
      iv: String(envelope.iv),
      iterations: Number(envelope.iterations || 310000),
      ciphertext: String(envelope.ciphertext),
      updatedAt: new Date().toISOString(),
    };
    await writeDb(db);
    return json(res, 200, { ok: true, vault: sanitizeVault(db.vaults[user.id]) });
  }

  return json(res, 405, { error: "METHOD_NOT_ALLOWED" });
};

