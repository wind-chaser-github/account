const {
  json,
  parseBody,
  authenticate,
  listVaultMetadata,
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
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const vaultRecords = await readRecentVaults(user.id);
    const vaultRecord = vaultRecords[0] || null;
    if (url.searchParams.get("debug") === "1") {
      return json(res, 200, {
        exists: Boolean(vaultRecord),
        count: vaultRecords.length,
        latest: vaultRecord
          ? {
              updatedAt: vaultRecord.updatedAt,
              iterations: vaultRecord.iterations,
              saltLength: String(vaultRecord.salt || "").length,
              ivLength: String(vaultRecord.iv || "").length,
              ciphertextLength: String(vaultRecord.ciphertext || "").length,
            }
          : null,
        blobs: await listVaultMetadata(user.id),
      });
    }
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
