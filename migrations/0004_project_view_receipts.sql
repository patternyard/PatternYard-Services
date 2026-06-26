CREATE TABLE IF NOT EXISTS app.project_view_receipts (
    project_id text NOT NULL REFERENCES app.projects(id) ON DELETE CASCADE,
    viewer_hash bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (project_id, viewer_hash)
);

CREATE INDEX IF NOT EXISTS project_view_receipts_expires_idx
    ON app.project_view_receipts (expires_at);
