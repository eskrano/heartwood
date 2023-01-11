use std::iter::repeat_with;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::{post, put};
use axum::{Json, Router};
use radicle::crypto::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::api::auth::{AuthState, DateTime, Session};
use crate::api::axum_extra::Path;
use crate::api::error::Error;
use crate::api::Context;

pub const UNAUTHORIZED_SESSIONS_EXPIRATION: Duration = Duration::seconds(60);
pub const AUTHORIZED_SESSIONS_EXPIRATION: Duration = Duration::weeks(1);

pub fn router(ctx: Context) -> Router {
    Router::new()
        .route("/sessions", post(session_create_handler))
        .route("/sessions/:id", put(session_signin_handler))
        .with_state(ctx)
}

#[derive(Debug, Deserialize, Serialize)]
struct ChallengeRequest {
    sig: Signature,
    pk: PublicKey,
}

/// Create session.
/// `POST /sessions`
async fn session_create_handler(State(ctx): State<Context>) -> impl IntoResponse {
    let rng = fastrand::Rng::new();
    let session_id = repeat_with(|| rng.alphanumeric())
        .take(32)
        .collect::<String>();
    let signer = ctx.profile.signer().map_err(Error::from)?;
    let expiration_time = OffsetDateTime::now_utc()
        .checked_add(UNAUTHORIZED_SESSIONS_EXPIRATION)
        .unwrap();
    let auth_state = AuthState::Unauthorized {
        public_key: *signer.public_key(),
        expiration_time: DateTime(expiration_time),
    };
    let mut sessions = ctx.sessions.write().await;
    sessions.insert(session_id.clone(), auth_state);

    Ok::<_, Error>(session_id)
}

/// Update session.
/// `PUT /sessions/:id`
async fn session_signin_handler(
    State(ctx): State<Context>,
    Path(session_id): Path<String>,
    Json(request): Json<ChallengeRequest>,
) -> impl IntoResponse {
    let mut sessions = ctx.sessions.write().await;
    let session = sessions.get(&session_id).ok_or(Error::NotFound)?;
    if let AuthState::Unauthorized {
        public_key,
        expiration_time,
    } = session
    {
        if public_key != &request.pk {
            return Err(Error::Auth("Invalid public key"));
        }
        if expiration_time <= &DateTime(OffsetDateTime::now_utc()) {
            return Err(Error::Auth("Session expired"));
        }
        let payload = format!("{}:{}", session_id, request.pk);
        request
            .pk
            .verify(payload.as_bytes(), &request.sig)
            .map_err(Error::from)?;
        let expiration_time = OffsetDateTime::now_utc()
            .checked_add(AUTHORIZED_SESSIONS_EXPIRATION)
            .unwrap();
        let session = Session {
            public_key: request.pk.to_string(),
            issued_at: DateTime(OffsetDateTime::now_utc()),
            expiration_time: DateTime(expiration_time),
        };
        sessions.insert(session_id.clone(), AuthState::Authorized(session));

        return Ok::<_, Error>(());
    }

    Err(Error::Auth("Session already authorized"))
}
