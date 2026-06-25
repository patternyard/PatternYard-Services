use sha2::{Digest, Sha256};
use sqlx::PgPool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthenticatedUser {
    pub id: String,
    pub username: String,
    pub admin: bool,
    pub moderator: bool,
}

pub(crate) fn hash_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

pub async fn authenticate_token(
    pool: &PgPool,
    token: &str,
) -> Result<Option<AuthenticatedUser>, sqlx::Error> {
    if token.is_empty() || token == "undefined" {
        return Ok(None);
    }

    let token_hash = hash_token(token);

    sqlx::query_as::<_, AuthenticatedUser>(
        "SELECT u.id, u.username::text AS username, u.admin, u.moderator \
         FROM app.sessions s \
         JOIN app.users u ON u.id = s.user_id \
         WHERE s.token_hash = $1 \
           AND s.revoked_at IS NULL \
           AND (s.expires_at IS NULL OR s.expires_at > now()) \
           AND NOT u.permanently_banned \
           AND (u.unban_at IS NULL OR u.unban_at <= now())",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_hash_matches_migrator_algorithm() {
        assert_eq!(
            hash_token("secret-token"),
            vec![
                147, 11, 189, 197, 27, 106, 237, 92, 42, 86, 120, 253, 110, 40, 222, 231, 160, 94,
                138, 75, 100, 60, 252, 11, 68, 39, 195, 239, 184, 108, 13, 148,
            ]
        );
    }
}
