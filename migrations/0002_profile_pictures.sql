BEGIN;

CREATE TABLE IF NOT EXISTS app.profile_pictures (
    user_id text PRIMARY KEY REFERENCES app.users(id) ON DELETE CASCADE,
    blob_url text NOT NULL,
    blob_pathname text NOT NULL,
    content_type text NOT NULL DEFAULT 'image/png',
    etag text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT profile_pictures_content_type_check CHECK (content_type = 'image/png'),
    CONSTRAINT profile_pictures_private_blob_url_check CHECK (
        blob_url ~ '^https://[^/]+\.private\.blob\.vercel-storage\.com/'
    ),
    CONSTRAINT profile_pictures_pathname_check CHECK (
        blob_pathname ~ '^profile-pictures/[A-Za-z0-9_-]+\.png$'
    )
);

COMMIT;
