const {
  json,
  parseBody,
  authenticate,
  readRecentVaults,
  sanitizeVault,
  writeVault,
} = require("./_lib");

module.exports = async function vault(req, res) {
  const user = authenticate(req);
  if (!user) {
    return json(res, 401, { error: "UNAUTHENTICATED" });
  }

  if (req.method === "GET") {
    const vaultRecords = await readRecentVaults(user.id);
    const vaultRecord = vaultRecords[0] || null;
    return json(res, 200, {
      exists: Boolean(vaultRecord),
      vault: sanitizeVault(vaultRecord),
      vaults: vaultRecords.map(sanitizeVault),
    });
  }

  if (req.method === "PUT") {
    const body = await parseBody(req);
    const envelope = body.vault || body.envelope || null;
    if (!envelope || !envelope.ciphertext || !envelope.salt || !envelope.iv) {
      return json(res, 400, { error: "INVALID_VAULT_ENVELOPE" });
    }
    const vaultRecord = {
      userId: user.id,
      version: Number(envelope.version || 1),
      salt: String(envelope.salt),
      iv: String(envelope.iv),
      iterations: Number(envelope.iterations || 310000),
      ciphertext: String(envelope.ciphertext),
      updatedAt: new Date().toISOString(),
    };
    await writeVault(user.id, vaultRecord);
    return json(res, 200, { ok: true, vault: sanitizeVault(vaultRecord) });
  }

  return json(res, 405, { error: "METHOD_NOT_ALLOWED" });
};
