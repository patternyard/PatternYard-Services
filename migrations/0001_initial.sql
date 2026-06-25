BEGIN;

CREATE EXTENSION IF NOT EXISTS citext;
CREATE SCHEMA IF NOT EXISTS app;
CREATE SCHEMA IF NOT EXISTS migration;

CREATE TABLE IF NOT EXISTS app.users (
    id text PRIMARY KEY,
    username citext NOT NULL,
    display_username text NOT NULL,
    password_hash text NOT NULL DEFAULT '',
    admin boolean NOT NULL DEFAULT false,
    moderator boolean NOT NULL DEFAULT false,
    permanently_banned boolean NOT NULL DEFAULT false,
    unban_at timestamptz,
    ban_reason text NOT NULL DEFAULT '',
    rank integer NOT NULL DEFAULT 0,
    badges text[] NOT NULL DEFAULT '{}',
    following_count integer NOT NULL DEFAULT 0 CHECK (following_count >= 0),
    follower_count integer NOT NULL DEFAULT 0 CHECK (follower_count >= 0),
    bio text NOT NULL DEFAULT '',
    featured_project_id text,
    featured_project_title text,
    cubes bigint NOT NULL DEFAULT 0,
    first_login_at timestamptz NOT NULL,
    last_login_at timestamptz,
    last_upload_at timestamptz,
    email_verified boolean NOT NULL DEFAULT false,
    birthday_entered boolean NOT NULL DEFAULT false,
    country_entered boolean NOT NULL DEFAULT false,
    last_privacy_policy_read_at timestamptz,
    last_terms_read_at timestamptz,
    last_guidelines_read_at timestamptz,
    private_profile boolean NOT NULL DEFAULT false,
    allow_following_view boolean NOT NULL DEFAULT false,
    is_studio boolean NOT NULL DEFAULT false,
    on_watchlist boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_username_unique UNIQUE (username)
);

CREATE TABLE IF NOT EXISTS app.user_private_details (
    user_id text PRIMARY KEY REFERENCES app.users(id) ON DELETE CASCADE,
    email citext,
    birth_date date,
    country_code text,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT user_private_country_code CHECK (
        country_code IS NULL OR country_code ~ '^[A-Z]{2}$'
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS user_private_email_unique
    ON app.user_private_details (email)
    WHERE email IS NOT NULL;

CREATE TABLE IF NOT EXISTS app.sessions (
    token_hash bytea PRIMARY KEY,
    user_id text NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz,
    revoked_at timestamptz,
    migrated_from_legacy boolean NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON app.sessions (user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON app.sessions (expires_at);

CREATE TABLE IF NOT EXISTS app.oauth_identities (
    provider text NOT NULL,
    provider_subject text NOT NULL,
    user_id text NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, provider_subject),
    UNIQUE (user_id, provider)
);

CREATE TABLE IF NOT EXISTS app.password_reset_challenges (
    token_hash bytea PRIMARY KEY,
    user_id text NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);

CREATE INDEX IF NOT EXISTS password_reset_expires_idx
    ON app.password_reset_challenges (expires_at);

CREATE TABLE IF NOT EXISTS app.email_delivery_log (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id text REFERENCES app.users(id) ON DELETE SET NULL,
    purpose text NOT NULL,
    recipient_hash bytea,
    created_at timestamptz NOT NULL,
    provider_message_id text
);

CREATE INDEX IF NOT EXISTS email_delivery_user_purpose_idx
    ON app.email_delivery_log (user_id, purpose, created_at DESC);

CREATE TABLE IF NOT EXISTS app.projects (
    id text PRIMARY KEY,
    author_id text NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
    title text NOT NULL,
    instructions text NOT NULL DEFAULT '',
    notes text NOT NULL DEFAULT '',
    remix_of_id text REFERENCES app.projects(id) ON DELETE SET NULL,
    featured boolean NOT NULL DEFAULT false,
    views bigint NOT NULL DEFAULT 0 CHECK (views >= 0),
    loves bigint NOT NULL DEFAULT 0 CHECK (loves >= 0),
    votes bigint NOT NULL DEFAULT 0 CHECK (votes >= 0),
    impressions bigint NOT NULL DEFAULT 0 CHECK (impressions >= 0),
    rating text NOT NULL DEFAULT '',
    is_public boolean NOT NULL DEFAULT true,
    soft_rejected boolean NOT NULL DEFAULT false,
    hard_rejected boolean NOT NULL DEFAULT false,
    hard_rejected_at timestamptz,
    no_feature boolean NOT NULL DEFAULT false,
    moderation_message text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS projects_author_updated_idx
    ON app.projects (author_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS projects_public_updated_idx
    ON app.projects (updated_at DESC)
    WHERE is_public AND NOT soft_rejected AND NOT hard_rejected;
CREATE INDEX IF NOT EXISTS projects_remix_idx
    ON app.projects (remix_of_id, updated_at DESC)
    WHERE is_public AND NOT soft_rejected;
CREATE INDEX IF NOT EXISTS projects_search_idx
    ON app.projects USING gin (to_tsvector('simple', title));

CREATE TABLE IF NOT EXISTS app.project_blobs (
    project_id text NOT NULL REFERENCES app.projects(id) ON DELETE CASCADE,
    kind text NOT NULL,
    asset_name text NOT NULL DEFAULT '',
    blob_path text NOT NULL,
    content_type text,
    byte_size bigint CHECK (byte_size IS NULL OR byte_size >= 0),
    checksum text,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, kind, asset_name),
    CONSTRAINT project_blobs_kind CHECK (kind IN ('project', 'thumbnail', 'asset'))
);

CREATE TABLE IF NOT EXISTS app.project_interactions (
    project_id text NOT NULL REFERENCES app.projects(id) ON DELETE CASCADE,
    user_id text NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
    kind text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, user_id, kind),
    CONSTRAINT project_interactions_kind CHECK (kind IN ('love', 'vote', 'view', 'show_more', 'show_less'))
);

CREATE INDEX IF NOT EXISTS project_interactions_user_idx
    ON app.project_interactions (user_id, kind, created_at DESC);

CREATE TABLE IF NOT EXISTS app.follows (
    follower_id text NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
    target_id text NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
    active boolean NOT NULL DEFAULT true,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (follower_id, target_id),
    CONSTRAINT follows_not_self CHECK (follower_id <> target_id)
);

CREATE INDEX IF NOT EXISTS follows_target_active_idx
    ON app.follows (target_id)
    WHERE active;

CREATE TABLE IF NOT EXISTS app.blocks (
    blocker_id text NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
    blocked_id text NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (blocker_id, blocked_id),
    CONSTRAINT blocks_not_self CHECK (blocker_id <> blocked_id)
);

CREATE TABLE IF NOT EXISTS app.reports (
    id text PRIMARY KEY,
    report_type smallint NOT NULL,
    reportee_id text NOT NULL,
    reporter_id text NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
    reason text NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT reports_type CHECK (report_type IN (0, 1)),
    UNIQUE (reporter_id, reportee_id)
);

CREATE INDEX IF NOT EXISTS reports_type_created_idx
    ON app.reports (report_type, created_at DESC);
CREATE INDEX IF NOT EXISTS reports_reportee_created_idx
    ON app.reports (reportee_id, created_at DESC);

CREATE TABLE IF NOT EXISTS app.messages (
    id text PRIMARY KEY,
    receiver_id text NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
    message text NOT NULL,
    disputable boolean NOT NULL DEFAULT false,
    project_id text REFERENCES app.projects(id) ON DELETE SET NULL,
    is_read boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS messages_receiver_created_idx
    ON app.messages (receiver_id, created_at DESC);
CREATE INDEX IF NOT EXISTS messages_receiver_unread_idx
    ON app.messages (receiver_id, created_at DESC)
    WHERE NOT is_read;

CREATE TABLE IF NOT EXISTS app.account_customizations (
    user_id text PRIMARY KEY REFERENCES app.users(id) ON DELETE CASCADE,
    disabled boolean NOT NULL DEFAULT false,
    settings jsonb NOT NULL DEFAULT '{}',
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT account_customizations_object CHECK (jsonb_typeof(settings) = 'object')
);

CREATE TABLE IF NOT EXISTS app.logged_ips (
    user_id text NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
    ip inet NOT NULL,
    first_seen_at timestamptz,
    last_seen_at timestamptz,
    PRIMARY KEY (user_id, ip)
);

CREATE INDEX IF NOT EXISTS logged_ips_ip_idx ON app.logged_ips (ip);

CREATE TABLE IF NOT EXISTS app.banned_ips (
    ip inet PRIMARY KEY,
    reason text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by_user_id text REFERENCES app.users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS app.user_feed (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id text NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
    activity_type text NOT NULL,
    target_id text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS user_feed_user_created_idx
    ON app.user_feed (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS user_feed_expires_idx
    ON app.user_feed (created_at);

CREATE TABLE IF NOT EXISTS app.runtime_config (
    key text PRIMARY KEY,
    value jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app.moderation_lists (
    key text PRIMARY KEY,
    items text[] NOT NULL DEFAULT '{}',
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app.policy_versions (
    policy text PRIMARY KEY,
    published_at timestamptz NOT NULL,
    version text,
    CONSTRAINT policy_versions_policy CHECK (policy IN ('privacy', 'terms', 'guidelines'))
);

CREATE TABLE IF NOT EXISTS app.tag_weights (
    tag text PRIMARY KEY,
    weight double precision NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app.storage_values (
    namespace text NOT NULL,
    project_id text NOT NULL,
    key text NOT NULL,
    value text NOT NULL,
    byte_size integer NOT NULL CHECK (byte_size >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (namespace, project_id, key)
);

CREATE INDEX IF NOT EXISTS storage_values_project_idx
    ON app.storage_values (project_id, namespace);

CREATE TABLE IF NOT EXISTS migration.checkpoints (
    collection text PRIMARY KEY,
    last_source_id text,
    source_count bigint NOT NULL DEFAULT 0,
    migrated_count bigint NOT NULL DEFAULT 0,
    rejected_count bigint NOT NULL DEFAULT 0,
    checksum text,
    updated_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);

CREATE TABLE IF NOT EXISTS migration.rejections (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    collection text NOT NULL,
    source_id_hash text NOT NULL,
    reason_code text NOT NULL,
    safe_details jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    CONSTRAINT migration_rejections_safe_details CHECK (jsonb_typeof(safe_details) = 'object')
);

CREATE INDEX IF NOT EXISTS migration_rejections_unresolved_idx
    ON migration.rejections (collection, created_at)
    WHERE resolved_at IS NULL;

COMMIT;
