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

/// WebSocket endpoint handler
/// Requires authenticated session (cookie-based)
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    auth_session: AuthSession,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, StatusCode> {
    // Require authenticated session for WebSocket
    if auth_session.user.is_none() {
        tracing::debug!("WebSocket connection rejected: no authenticated session");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let username = auth_session
        .user
        .as_ref()
        .map(|u| u.username.clone())
        .unwrap_or_default();

    tracing::info!(username = %username, "WebSocket connection established");

    Ok(ws.on_upgrade(move |socket| handle_socket(socket, state, username)))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>, username: String) {
    let mut rx = state.ws_broadcast.subscribe();
    let (mut sender, mut receiver) = socket.split();

    // Send task: forward broadcast messages to client
    let send_task = tokio::spawn(async move {
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
    });

    // Recv task: handle client messages (ping/pong handled automatically by axum)
    let recv_task = tokio::spawn(async move {
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
    });

    // Wait for either task to complete
    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }

    tracing::info!(username = %username, "WebSocket connection closed");
}
