BEGIN;

ALTER TABLE app.password_reset_challenges
    ADD COLUMN IF NOT EXISTS purpose text NOT NULL DEFAULT 'password_reset';

ALTER TABLE app.password_reset_challenges
    DROP CONSTRAINT IF EXISTS password_reset_challenges_purpose_check;

ALTER TABLE app.password_reset_challenges
    ADD CONSTRAINT password_reset_challenges_purpose_check
    CHECK (purpose IN ('password_reset', 'email_verification'));

CREATE INDEX IF NOT EXISTS password_reset_user_purpose_idx
    ON app.password_reset_challenges (user_id, purpose, created_at DESC);

ALTER TABLE app.email_delivery_log
    ADD COLUMN IF NOT EXISTS requester_hash bytea;

CREATE INDEX IF NOT EXISTS email_delivery_requester_idx
    ON app.email_delivery_log (requester_hash, created_at DESC)
    WHERE requester_hash IS NOT NULL;

COMMIT;
