"""Ordered, idempotent schema migrations.

001 recreates the legacy `licenses` table exactly as the old Monday License
Manager defined it, so this app can run against the existing Neon database (or
a fresh one). 002 adds the portal tables and upgrades legacy rows in place.
Old columns (`product`, `device_id`) are kept up to date so the old app can
still read the same database if you ever need to roll back.
"""

MIGRATIONS = [
    ("001_legacy_licenses", """
        CREATE TABLE IF NOT EXISTS licenses (
          id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          key_hash CHAR(64) UNIQUE NOT NULL,
          key_ciphertext TEXT NOT NULL,
          product TEXT NOT NULL,
          months INTEGER NOT NULL,
          duration TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          activated_at TIMESTAMPTZ,
          expires_at TIMESTAMPTZ,
          device_id TEXT,
          revoked_at TIMESTAMPTZ
        )
    """),
    ("002_portal", """
        CREATE TABLE IF NOT EXISTS projects (
          id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          slug TEXT UNIQUE NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,48}$'),
          name TEXT NOT NULL,
          description TEXT NOT NULL DEFAULT '',
          repo_url TEXT NOT NULL DEFAULT '',
          is_public BOOLEAN NOT NULL DEFAULT false,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );

        INSERT INTO projects (slug, name) VALUES
          ('gatepasskiosk', 'GatePassKiosk'),
          ('gatepasssecurity', 'GatePassSecurity'),
          ('gatepasshrdashboard', 'GatePassHRDashboard')
        ON CONFLICT (slug) DO NOTHING;

        -- any other legacy product names become projects too
        INSERT INTO projects (slug, name)
          SELECT DISTINCT lower(product), product FROM licenses
          WHERE lower(product) ~ '^[a-z0-9][a-z0-9-]{1,48}$'
        ON CONFLICT (slug) DO NOTHING;

        ALTER TABLE licenses ADD COLUMN IF NOT EXISTS project_id BIGINT REFERENCES projects(id);
        ALTER TABLE licenses ADD COLUMN IF NOT EXISTS max_devices INTEGER NOT NULL DEFAULT 1;

        UPDATE licenses l SET project_id = p.id
          FROM projects p WHERE p.slug = lower(l.product) AND l.project_id IS NULL;

        CREATE TABLE IF NOT EXISTS activations (
          id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          license_id BIGINT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
          device_id TEXT NOT NULL,
          first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
          last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
          UNIQUE (license_id, device_id)
        );

        INSERT INTO activations (license_id, device_id, first_seen, last_seen)
          SELECT id, device_id, COALESCE(activated_at, now()), COALESCE(activated_at, now())
          FROM licenses WHERE device_id IS NOT NULL
        ON CONFLICT (license_id, device_id) DO NOTHING;

        CREATE TABLE IF NOT EXISTS releases (
          id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          project_id BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
          version TEXT NOT NULL,
          channel TEXT NOT NULL DEFAULT 'stable' CHECK (channel IN ('stable', 'beta')),
          download_url TEXT NOT NULL,
          sha256 TEXT NOT NULL DEFAULT '',
          size_bytes BIGINT,
          notes TEXT NOT NULL DEFAULT '',
          mandatory BOOLEAN NOT NULL DEFAULT false,
          yanked BOOLEAN NOT NULL DEFAULT false,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
          UNIQUE (project_id, version)
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
          id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          ip TEXT NOT NULL,
          at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS login_attempts_ip_at ON login_attempts (ip, at);
        CREATE INDEX IF NOT EXISTS licenses_project ON licenses (project_id);
    """),
    ("003_license_name", """
        ALTER TABLE licenses ADD COLUMN IF NOT EXISTS assigned_to TEXT NOT NULL DEFAULT '';
    """),
    ("004_github_releases", """
        ALTER TABLE projects ADD COLUMN IF NOT EXISTS github_repo TEXT NOT NULL DEFAULT '';
        ALTER TABLE projects ADD COLUMN IF NOT EXISTS github_tag_prefix TEXT NOT NULL DEFAULT '';
        ALTER TABLE projects ADD COLUMN IF NOT EXISTS gh_last_sync_at TIMESTAMPTZ;
        ALTER TABLE projects ADD COLUMN IF NOT EXISTS gh_sync_ok BOOLEAN;
        ALTER TABLE projects ADD COLUMN IF NOT EXISTS gh_sync_message TEXT NOT NULL DEFAULT '';
        CREATE TABLE IF NOT EXISTS github_releases (
            id SERIAL PRIMARY KEY,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            gh_id BIGINT NOT NULL,
            repo TEXT NOT NULL,
            tag TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            version TEXT NOT NULL,
            body TEXT NOT NULL DEFAULT '',
            prerelease BOOLEAN NOT NULL DEFAULT false,
            published_at TIMESTAMPTZ,
            html_url TEXT NOT NULL DEFAULT '',
            assets JSONB NOT NULL DEFAULT '[]',
            first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_synced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            removed_at TIMESTAMPTZ,
            UNIQUE (project_id, gh_id)
        );
    """),
]
