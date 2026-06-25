use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Row};
use std::env;
use std::str::FromStr;
use std::time::Duration;

#[derive(Clone, Default)]
pub struct Database {
    pool: Option<PgPool>,
}

impl Database {
    pub fn from_env() -> Self {
        let Some(url) = env::var("DATABASE_URL").ok().filter(|url| !url.is_empty()) else {
            return Self::default();
        };

        let options = match PgConnectOptions::from_str(&url) {
            Ok(options) => options,
            Err(error) => {
                tracing::error!(%error, "DATABASE_URL is invalid");
                return Self::default();
            }
        };

        let pool = PgPoolOptions::new()
            .max_connections(4)
            .min_connections(0)
            .acquire_timeout(Duration::from_secs(5))
            .idle_timeout(Duration::from_secs(30))
            .connect_lazy_with(options);

        Self { pool: Some(pool) }
    }

    pub fn pool(&self) -> Option<&PgPool> {
        self.pool.as_ref()
    }

    pub async fn is_ready(&self) -> bool {
        let Some(pool) = self.pool() else {
            return false;
        };

        sqlx::query("SELECT 1 AS ready")
            .fetch_one(pool)
            .await
            .and_then(|row| row.try_get::<i32, _>("ready"))
            .is_ok_and(|ready| ready == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reports_not_ready_without_a_pool() {
        assert!(!Database::default().is_ready().await);
    }
}
