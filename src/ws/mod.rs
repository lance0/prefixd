mod handler;
mod messages;

pub use handler::ws_handler;
pub use messages::WsMessage;

use tokio::sync::broadcast;

/// Create the WebSocket broadcast channel
pub fn create_broadcast() -> broadcast::Sender<WsMessage> {
    broadcast::channel(1024).0
}
