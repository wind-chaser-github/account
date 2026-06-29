# Encrypted Vault

Zero-knowledge credential vault prototype.

## Run

```bash
node server.js
```

Open `http://localhost:3000`.

## Deploy on Vercel

This repo is now Vercel-ready:

- Static UI lives at the repository root.
- API routes live in `api/*.js`.
- Vault data is stored in Vercel Blob as encrypted JSON.

Set these environment variables in Vercel:

- `BLOB_READ_WRITE_TOKEN`
- `AUTH_SECRET`

Then deploy the repo directly. Vercel will serve the static files and mount the API routes automatically.

## Security model

- Server stores login password hashes only.
- Vault records are encrypted in the browser before sync.
- The server never receives the vault passphrase.
