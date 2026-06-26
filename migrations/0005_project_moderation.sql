ALTER TABLE app.messages
    ADD COLUMN IF NOT EXISTS dispute text;

CREATE INDEX IF NOT EXISTS messages_disputes_idx
    ON app.messages (created_at DESC)
    WHERE dispute IS NOT NULL;
