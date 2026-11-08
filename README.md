# GideonDev Portal

One server for every project: license keys, device activation, release/update
checks, and a public project list for the portfolio site. Flask + Postgres (Neon),
runs on Render.

## What it does
- **Projects** are rows, not code. Add a project in the admin page and it gets its own
  page for releases, license keys and devices.
- **Licenses:** per-project keys, term in months, configurable device limit, revoke, and
  "reset devices" for when a customer changes computers. Keys are stored hashed plus an
  encrypted copy so the admin page can show them.
- **Updates:** publish a release (version, https download link, SHA-256, notes,
  mandatory flag, stable/beta channel). Withdraw a bad release with one click.
- **Signed offline tokens (optional):** `/api/v1/verify` can return an Ed25519-signed
  token so apps keep working for `OFFLINE_GRACE_DAYS` if the free server is asleep.
- **Compatible with the old license server.** `POST /api/verify` behaves exactly as
  before, and the migration upgrades the existing `licenses` table in place.

## API
| Call | Purpose |
|---|---|
| `POST /api/verify` | Legacy. `{key, product, device_id}` |
| `POST /api/v1/verify` | `{key, project, device_id}`; returns `valid`, `expires_at`, `devices_used`, `max_devices`, `token`, `offline_until` |
| `GET /api/v1/public-key` | Ed25519 public key (base64) for checking tokens |
| `GET /api/v1/projects/<slug>/latest?current=1.0.0&channel=stable` | Update check: `update_available`, `latest`, `mandatory` |
| `GET /api/v1/projects` | Public projects + latest stable release (CORS-enabled for your portfolio) |
| `GET /api/v1/projects/<slug>` | Public project detail + release history |

`project` is the slug (lowercase). Legacy product names map to slugs automatically
(`GatePassKiosk` -> `gatepasskiosk`).

## Environment variables
| Name | Notes |
|---|---|
| `DATABASE_URL` | Neon connection string with TLS |
| `SESSION_SECRET` | Random string (Render can generate it) |
| `ADMIN_PASSWORD` | Long and unique; login is throttled to 5 failures / 15 min / IP |
| `KEY_ENCRYPTION_SECRET` | Fernet key. **Keep the same value as the old server.** Never rotate without re-encrypting |
| `SIGNING_PRIVATE_KEY` | Optional. `python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"` |
| `CORS_ORIGINS` | Comma-separated, default `https://gideonshaz.github.io` |
| `OFFLINE_GRACE_DAYS` | Default 7 |

## Run locally / test
```
pip install -r requirements.txt pytest
# needs a throwaway Postgres; tests drop and recreate the public schema!
export DATABASE_URL=postgresql://postgres@127.0.0.1:5433/portal_test
pytest
```

## Cutover from the old license server (no client rebuild)
1. Migration is additive and keeps old columns up to date, so the old server can keep
   running against the same database during testing.
2. In Render, point the existing `monday-license-manager` service at this repo (or deploy
   this repo and switch the apps' `ServerUrl`). Keeping the service keeps the URL the
   Windows clients already use.
3. Copy `KEY_ENCRYPTION_SECRET` and `ADMIN_PASSWORD` from the old service. Add
   `SIGNING_PRIVATE_KEY` when you are ready for offline tokens.
4. Confirm `/health`, log in, and check that existing keys appear under their projects.

## Known limits
- Download links are plain URLs, so anyone who has one can download. Use a host that
  supports private/expiring links if installers must be license-gated.
- Pre-release suffixes (`1.2.0-beta.1`) compare equal to `1.2.0`; use the beta channel.
- Free Render sleeps when idle and free Neon scales to zero; the first call can be slow.
