use crate::auth::authenticate_token;
use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use std::collections::BTreeMap;

const LIST_KEYS: [&str; 8] = [
    "illegalWords",
    "illegalWebsites",
    "spacedOutWordsOnly",
    "potentiallyUnsafeWords",
    "potentiallyUnsafeWordsSpacedOut",
    "legalExtensions",
    "unsafeUsernames",
    "potentiallyUnsafeUsernames",
];

#[derive(Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

#[derive(Deserialize)]
struct SetListsBody {
    token: Option<String>,
    #[serde(rename = "json")]
    lists: Value,
}

#[derive(Serialize)]
struct SuccessResponse {
    success: bool,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new()
        .route("/api/v1/misc/getProfanityList", get(get_lists))
        .route("/api/v1/misc/setProfanityList", post(set_lists))
}

async fn get_lists(State(database): State<Database>, Query(query): Query<TokenQuery>) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = authenticate_admin(pool, query.token).await {
        return response;
    }

    match sqlx::query_as::<_, (String, Vec<String>)>(
        "SELECT key, items FROM app.moderation_lists \
         WHERE key IN (\
             'illegalWords', 'illegalWebsites', 'spacedOutWordsOnly', \
             'potentiallyUnsafeWords', 'potentiallyUnsafeWordsSpacedOut', \
             'legalExtensions', 'unsafeUsernames', 'potentiallyUnsafeUsernames'\
         )",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => {
            let mut lists = empty_lists();
            for (key, items) in rows {
                lists.insert(key, items);
            }
            Json(lists).into_response()
        }
        Err(error) => query_failed(error),
    }
}

async fn set_lists(State(database): State<Database>, Json(body): Json<SetListsBody>) -> Response {
    let Some(pool) = database.pool() else {
        return database_unavailable();
    };
    if let Err(response) = authenticate_admin(pool, body.token).await {
        return response;
    }
    let lists = match parse_lists(&body.lists) {
        Ok(lists) => lists,
        Err(message) => return api_error(StatusCode::BAD_REQUEST, message),
    };

    let mut transaction = match pool.begin().await {
        Ok(transaction) => transaction,
        Err(error) => return query_failed(error),
    };
    for (key, items) in lists {
        if let Err(error) = sqlx::query(
            "INSERT INTO app.moderation_lists (key, items, updated_at) \
             VALUES ($1, $2, now()) \
             ON CONFLICT (key) DO UPDATE \
             SET items = EXCLUDED.items, updated_at = EXCLUDED.updated_at",
        )
        .bind(key)
        .bind(items)
        .execute(&mut *transaction)
        .await
        {
            return query_failed(error);
        }
    }

    match transaction.commit().await {
        Ok(()) => Json(SuccessResponse { success: true }).into_response(),
        Err(error) => query_failed(error),
    }
}

async fn authenticate_admin(pool: &PgPool, token: Option<String>) -> Result<(), Response> {
    let token = token.unwrap_or_else(|| "undefined".to_owned());
    match authenticate_token(pool, &token).await {
        Ok(Some(user)) if user.admin => Ok(()),
        Ok(Some(_)) => Err(api_error(
            StatusCode::FORBIDDEN,
            "FeatureDisabledForThisAccount",
        )),
        Ok(None) => Err(api_error(StatusCode::UNAUTHORIZED, "Reauthenticate")),
        Err(error) => Err(query_failed(error)),
    }
}

fn empty_lists() -> BTreeMap<String, Vec<String>> {
    LIST_KEYS
        .iter()
        .map(|key| ((*key).to_owned(), Vec::new()))
        .collect()
}

fn parse_lists(value: &Value) -> Result<BTreeMap<String, Vec<String>>, &'static str> {
    let object = value.as_object().ok_or("Invalid Words")?;
    let mut parsed = BTreeMap::new();

    for (key, value) in object {
        let words = value.as_array().ok_or("Invalid inner words object")?;
        let mut parsed_words = Vec::with_capacity(words.len());
        for word in words {
            let word = word.as_str().ok_or("Invalid word")?;
            parsed_words.push(word.to_owned());
        }
        if !LIST_KEYS.contains(&key.as_str()) {
            return Err("Invalid key");
        }
        parsed.insert(key.clone(), parsed_words);
    }

    Ok(parsed)
}

fn database_unavailable() -> Response {
    api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable")
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "moderation list query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_response_preserves_all_legacy_keys() {
        let lists = empty_lists();

        assert_eq!(lists.len(), LIST_KEYS.len());
        for key in LIST_KEYS {
            assert_eq!(lists.get(key), Some(&Vec::new()));
        }
    }

    #[test]
    fn list_updates_validate_the_legacy_shape() {
        assert!(
            parse_lists(&serde_json::json!({
                "illegalWords": ["example"],
                "legalExtensions": []
            }))
            .is_ok()
        );
        assert_eq!(
            parse_lists(&serde_json::json!([])).unwrap_err(),
            "Invalid Words"
        );
        assert_eq!(
            parse_lists(&serde_json::json!({ "illegalWords": "example" })).unwrap_err(),
            "Invalid inner words object"
        );
        assert_eq!(
            parse_lists(&serde_json::json!({ "illegalWords": [1] })).unwrap_err(),
            "Invalid word"
        );
        assert_eq!(
            parse_lists(&serde_json::json!({ "other": [] })).unwrap_err(),
            "Invalid key"
        );
    }
}
