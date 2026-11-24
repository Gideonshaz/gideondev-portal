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
    ("005_github_app", """
        CREATE TABLE IF NOT EXISTS github_app (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            app_id BIGINT NOT NULL,
            slug TEXT NOT NULL,
            html_url TEXT NOT NULL DEFAULT '',
            pem_enc TEXT NOT NULL,
            webhook_secret_enc TEXT NOT NULL,
            installation_id BIGINT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    """),
    ("006_github_drafts", """
        CREATE TABLE IF NOT EXISTS github_drafts (
            id SERIAL PRIMARY KEY,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            gh_id BIGINT NOT NULL,
            tag TEXT NOT NULL,
            version TEXT NOT NULL,
            prerelease BOOLEAN NOT NULL DEFAULT false,
            package_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft',
            checks JSONB NOT NULL DEFAULT '[]',
            last_error TEXT NOT NULL DEFAULT '',
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (project_id, gh_id)
        );
    """),
    ("007_team_accounts", """
        CREATE TABLE IF NOT EXISTS team_users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            project_ids INTEGER[] NOT NULL DEFAULT '{}',
            active BOOLEAN NOT NULL DEFAULT true,
            session_version INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_login_at TIMESTAMPTZ
        );
        ALTER TABLE licenses ADD COLUMN IF NOT EXISTS created_by TEXT NOT NULL DEFAULT '';
    """),
    # Affiliate LIVE GMV Max scheduler. New tables only; nothing above is touched.
    # The CHECK pins the only approved campaign at the database level, so a bug or a
    # tampered client still cannot store a schedule for any other campaign.
    ("008_affiliate_scheduler", """
        CREATE TABLE IF NOT EXISTS sched_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            live_enabled BOOLEAN NOT NULL DEFAULT false,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        INSERT INTO sched_settings (id) VALUES (1) ON CONFLICT DO NOTHING;

        CREATE TABLE IF NOT EXISTS sched_schedules (
            id SERIAL PRIMARY KEY,
            advertiser_id TEXT NOT NULL,
            campaign_id TEXT NOT NULL,
            campaign_name TEXT NOT NULL,
            schedule_type TEXT NOT NULL CHECK (schedule_type IN ('once', 'weekly')),
            live_date DATE,
            weekdays SMALLINT[] NOT NULL DEFAULT '{}',
            live_start TIME NOT NULL,
            live_end TIME NOT NULL,
            lead_minutes INTEGER NOT NULL DEFAULT 10 CHECK (lead_minutes BETWEEN 0 AND 120),
            timezone TEXT NOT NULL DEFAULT 'Asia/Kuala_Lumpur' CHECK (timezone = 'Asia/Kuala_Lumpur'),
            active BOOLEAN NOT NULL DEFAULT true,
            label TEXT NOT NULL DEFAULT '',
            last_execution_at TIMESTAMPTZ,
            last_result TEXT NOT NULL DEFAULT '',
            effective_from TIMESTAMPTZ NOT NULL DEFAULT now(),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            deleted_at TIMESTAMPTZ,
            CONSTRAINT sched_only_approved CHECK (
                advertiser_id = '7657848009081946119'
                AND campaign_id = '1881634554090609' AND campaign_name = 'tashafrh'),
            CONSTRAINT sched_shape CHECK (
                (schedule_type = 'once' AND live_date IS NOT NULL)
                OR (schedule_type = 'weekly' AND cardinality(weekdays) > 0)),
            CONSTRAINT sched_not_zero_length CHECK (live_start <> live_end)
        );

        CREATE TABLE IF NOT EXISTS sched_executions (
            id SERIAL PRIMARY KEY,
            operation_id TEXT NOT NULL UNIQUE,
            schedule_id INTEGER NOT NULL REFERENCES sched_schedules(id),
            campaign_id TEXT NOT NULL,
            operation TEXT NOT NULL CHECK (operation IN ('ENABLE', 'DISABLE')),
            due_at TIMESTAMPTZ NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('claimed', 'succeeded', 'dry_run', 'failed',
                                                   'rejected', 'missed', 'skipped_overlap')),
            mode TEXT NOT NULL DEFAULT '',
            attempts INTEGER NOT NULL DEFAULT 0,
            claim_token TEXT NOT NULL DEFAULT '',
            message TEXT NOT NULL DEFAULT '',
            run_id TEXT NOT NULL DEFAULT '',
            claimed_at TIMESTAMPTZ,
            finished_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS sched_exec_schedule ON sched_executions (schedule_id, id DESC);

        CREATE TABLE IF NOT EXISTS sched_devices (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            token_hash CHAR(64) NOT NULL UNIQUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_seen TIMESTAMPTZ,
            revoked_at TIMESTAMPTZ
        );

        CREATE TABLE IF NOT EXISTS sched_tiktok_auth (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            mcp_url TEXT NOT NULL,
            client_id TEXT NOT NULL,
            client_secret_enc TEXT NOT NULL DEFAULT '',
            token_endpoint TEXT NOT NULL,
            resource TEXT NOT NULL,
            access_token_enc TEXT NOT NULL,
            access_expires_at TIMESTAMPTZ,
            refresh_token_enc TEXT NOT NULL DEFAULT '',
            authorized_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_refresh_at TIMESTAMPTZ,
            needs_reauth BOOLEAN NOT NULL DEFAULT false,
            last_error TEXT NOT NULL DEFAULT '',
            verified_at TIMESTAMPTZ,
            verify_result TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS sched_oauth_pending (
            state CHAR(43) PRIMARY KEY,
            verifier_enc TEXT NOT NULL,
            client_id TEXT NOT NULL,
            client_secret_enc TEXT NOT NULL DEFAULT '',
            redirect_uri TEXT NOT NULL,
            token_endpoint TEXT NOT NULL,
            resource TEXT NOT NULL,
            mcp_url TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    """),
    # Read-only LIVE stats the scheduler run reports for the app (latest snapshot per campaign).
    ("009_scheduler_live_stats", """
        CREATE TABLE IF NOT EXISTS sched_live_stats (
            campaign_id TEXT PRIMARY KEY,
            stats JSONB,
            error TEXT NOT NULL DEFAULT '',
            fetched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            ok_at TIMESTAMPTZ
        );
    """),
    # Second approved affiliate: nazifaiskandar. DB lock widened to exactly these two.
    ("010_approve_nazifaiskandar", """
        ALTER TABLE sched_schedules DROP CONSTRAINT IF EXISTS sched_only_approved;
        ALTER TABLE sched_schedules ADD CONSTRAINT sched_only_approved CHECK (
            advertiser_id = '7657848009081946119'
            AND ((campaign_id = '1881634554090609' AND campaign_name = 'tashafrh')
              OR (campaign_id = '1882182698757202' AND campaign_name = 'nazifaiskandar')));
    """),
    # Daily LIVE GMV Max history for the app (one row per approved campaign per Malaysia day).
    ("011_scheduler_live_daily", """
        CREATE TABLE IF NOT EXISTS sched_live_daily (
            campaign_id TEXT NOT NULL CHECK (campaign_id IN ('1881634554090609', '1882182698757202')),
            day DATE NOT NULL,
            cost NUMERIC(12, 2) NOT NULL DEFAULT 0,
            gmv NUMERIC(12, 2) NOT NULL DEFAULT 0,
            orders INTEGER NOT NULL DEFAULT 0,
            live_views INTEGER,
            views_10s INTEGER,
            follows INTEGER,
            live_minutes INTEGER NOT NULL DEFAULT 0,
            sessions INTEGER NOT NULL DEFAULT 0,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            PRIMARY KEY (campaign_id, day)
        );
    """),
]
