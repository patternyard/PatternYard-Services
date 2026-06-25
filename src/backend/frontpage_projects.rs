use crate::auth::authenticate_token;
use crate::db::Database;
use axum::extract::{Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::time::{SystemTime, UNIX_EPOCH};

const TAGS: [&str; 16] = [
    "games",
    "animation",
    "art",
    "platformer",
    "music",
    "rpg",
    "story",
    "minigames",
    "online",
    "remake",
    "physics",
    "contest",
    "horror",
    "tutorial",
    "3d",
    "2d",
];

#[derive(Deserialize, Default)]
struct FrontpageQuery {
    token: Option<String>,
}

#[derive(serde::Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn router() -> Router<Database> {
    Router::new().route("/api/v1/projects/frontpage", get(frontpage))
}

async fn frontpage(
    State(database): State<Database>,
    Query(query): Query<FrontpageQuery>,
) -> Response {
    let Some(pool) = database.pool() else {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable");
    };
    let user = match authenticate_token(pool, query.token.as_deref().unwrap_or("undefined")).await {
        Ok(user) => user,
        Err(error) => return query_failed(error),
    };
    let selected_tag = selected_tag();
    let mut page = match fetch_frontpage(pool, &selected_tag).await {
        Ok(page) => page,
        Err(error) => return query_failed(error),
    };

    if let Some(user) = user {
        match blocked_users(pool, &user.id).await {
            Ok(blocked) => page["blocked"] = json!(blocked),
            Err(error) => return query_failed(error),
        }
    }

    let ids = project_ids(&page);
    if let Err(error) = add_impressions(pool, &ids).await {
        tracing::error!(%error, "frontpage impression update failed");
    }

    let mut response = Json(page).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=90"),
    );
    response
}

async fn fetch_frontpage(pool: &PgPool, selected_tag: &str) -> Result<Value, sqlx::Error> {
    sqlx::query_scalar::<_, Value>(
        "WITH visible AS (\
             SELECT p.*, jsonb_build_object('id', u.id, 'username', u.username) AS author, \
                    ('donator' = ANY(u.badges)) AS from_donator \
             FROM app.projects p JOIN app.users u ON u.id = p.author_id \
             WHERE p.is_public AND NOT p.soft_rejected AND NOT p.hard_rejected\
         ), shaped AS (\
             SELECT p.*, jsonb_build_object(\
                 'id', p.id, 'title', p.title, 'author', p.author, \
                 'instructions', p.instructions, 'notes', p.notes, 'rating', p.rating, \
                 'public', p.is_public, 'featured', p.featured, \
                 'softRejected', p.soft_rejected, 'hardReject', p.hard_rejected, \
                 'noFeature', p.no_feature, 'modMessage', p.moderation_message, \
                 'loves', p.loves, 'votes', p.votes, 'views', p.views, \
                 'impressions', p.impressions, \
                 'date', floor(extract(epoch FROM p.created_at) * 1000)::bigint, \
                 'lastUpdate', floor(extract(epoch FROM p.updated_at) * 1000)::bigint, \
                 'remix', p.remix_of_id, 'fromDonator', p.from_donator\
             ) AS project \
             FROM visible p\
         ) \
         SELECT jsonb_build_object(\
             'featured', COALESCE((\
                 SELECT jsonb_agg(project ORDER BY created_at DESC, id) FROM (\
                     SELECT project, created_at, id FROM shaped WHERE featured \
                     ORDER BY created_at DESC, id LIMIT 20\
                 ) featured_projects\
             ), '[]'::jsonb), \
             'voted', COALESCE((\
                 SELECT jsonb_agg(project ORDER BY votes DESC, id) FROM (\
                     SELECT project, votes, id FROM shaped WHERE NOT featured AND NOT no_feature \
                     ORDER BY votes DESC, id LIMIT 20\
                 ) voted_projects\
             ), '[]'::jsonb), \
             'tagged', COALESCE((\
                 SELECT jsonb_agg(project ORDER BY updated_at DESC, id) FROM (\
                     SELECT project, updated_at, id FROM shaped \
                     WHERE title ILIKE $1 OR instructions ILIKE $1 OR notes ILIKE $1 \
                     ORDER BY updated_at DESC, id LIMIT 20\
                 ) tagged_projects\
             ), '[]'::jsonb), \
             'latest', COALESCE((\
                 SELECT jsonb_agg(project ORDER BY updated_at DESC, id) FROM (\
                     SELECT project, updated_at, id FROM shaped \
                     ORDER BY updated_at DESC, id LIMIT 40\
                 ) latest_projects\
             ), '[]'::jsonb), \
             'selectedTag', $2\
         )",
    )
    .bind(format!("%{selected_tag}%"))
    .bind(selected_tag)
    .fetch_one(pool)
    .await
}

async fn blocked_users(pool: &PgPool, user_id: &str) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT blocked_id FROM app.blocks WHERE blocker_id = $1 ORDER BY blocked_id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

fn selected_tag() -> String {
    let bucket = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 300;
    format!("#{}", TAGS[(bucket as usize) % TAGS.len()])
}

fn project_ids(page: &Value) -> Vec<&str> {
    ["featured", "voted", "tagged", "latest"]
        .into_iter()
        .filter_map(|key| page.get(key).and_then(Value::as_array))
        .flatten()
        .filter_map(|project| project.get("id").and_then(Value::as_str))
        .collect()
}

async fn add_impressions(pool: &PgPool, project_ids: &[&str]) -> Result<(), sqlx::Error> {
    if !project_ids.is_empty() {
        sqlx::query("UPDATE app.projects SET impressions = impressions + 1 WHERE id = ANY($1)")
            .bind(project_ids)
            .execute(pool)
            .await?;
    }
    Ok(())
}

fn query_failed(error: sqlx::Error) -> Response {
    tracing::error!(%error, "frontpage project query failed");
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

fn api_error(status: StatusCode, error: &'static str) -> Response {
    (status, Json(ErrorBody { error })).into_response()
}

#[cfg(test)]
mod tests {
    use super::project_ids;
    use serde_json::json;

    #[test]
    fn collects_project_ids_from_all_frontpage_sections() {
        let page = json!({
            "featured": [{ "id": "one" }],
            "voted": [{ "id": "two" }],
            "tagged": [],
            "latest": [{ "id": "three" }]
        });
        assert_eq!(project_ids(&page), vec!["one", "two", "three"]);
    }
}
