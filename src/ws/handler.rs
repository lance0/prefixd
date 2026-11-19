use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::StatusCode,
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::broadcast;

use super::WsMessage;
use crate::AppState;
use crate::auth::AuthSession;
use crate::config::AuthMode;

/// WebSocket endpoint handler
/// Requires authenticated session (cookie-based) unless auth_mode is none
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    auth_session: AuthSession,
    session: tower_sessions::Session,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_disabled = matches!(state.settings.http.auth.mode, AuthMode::None);

    if !auth_disabled && auth_session.user.is_none() {
        tracing::debug!("WebSocket connection rejected: no authenticated session");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let username = auth_session
        .user
        .as_ref()
        .map(|u| u.username.clone())
        .unwrap_or_else(|| "anonymous".to_string());

    tracing::info!(username = %username, "WebSocket connection established");

    let deadline = if auth_session
        .user
        .as_ref()
        .is_some_and(|op| op.password_hash.expose_secret().starts_with("oidc:"))
    {
        Some(
            session
                .get::<i64>("oidc.deadline")
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .ok_or(StatusCode::UNAUTHORIZED)?,
        )
    } else {
        None
    };
    Ok(ws.on_upgrade(move |socket| async move {
        let connection = handle_socket(socket, state, username);
        if let Some(end) = deadline {
            let seconds = end.saturating_sub(chrono::Utc::now().timestamp()).max(0) as u64;
            let _ = tokio::time::timeout(std::time::Duration::from_secs(seconds), connection).await;
        } else {
            connection.await;
        }
    }))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>, username: String) {
    let mut rx = state.ws_broadcast.subscribe();
    let (mut sender, mut receiver) = socket.split();

    // Send task: forward broadcast messages to client
    let send_task = async move {
        loop {
            match rx.recv().await {
                Ok(msg) => {
                    let json = match serde_json::to_string(&msg) {
                        Ok(j) => j,
                        Err(e) => {
                            tracing::error!(error = %e, "failed to serialize WS message");
                            continue;
                        }
                    };
                    if sender.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(missed = n, "WebSocket client lagged, sending resync");
                    let resync = serde_json::to_string(&WsMessage::ResyncRequired {})
                        .unwrap_or_else(|_| r#"{"type":"resync_required"}"#.to_string());
                    if sender.send(Message::Text(resync.into())).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::debug!("WebSocket broadcast channel closed");
                    break;
                }
            }
        }
    };

    // Recv task: handle client messages (ping/pong handled automatically by axum)
    let recv_task = async move {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Close(_)) => {
                    tracing::debug!("WebSocket client sent close");
                    break;
                }
                Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {
                    // Handled automatically by axum
                }
                Ok(Message::Text(_)) | Ok(Message::Binary(_)) => {
                    // We don't expect client messages, ignore
                }
                Err(e) => {
                    tracing::debug!(error = %e, "WebSocket receive error");
                    break;
                }
            }
        }
    };

    // Wait for either task to complete
    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }

    tracing::info!(username = %username, "WebSocket connection closed");
}
