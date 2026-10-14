//! Streamable HTTP & Server-Sent Events (SSE) remote MCP transport.
//! Implements remote JSON-RPC communication according to the Model Context Protocol specification.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Json, Response};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{info, warn};

use crate::mcp::McpDispatcher;
use crate::mcp::protocol::{JsonRpcRequest, PARSE_ERROR};
use crate::transport::TransportType;

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Shared state for the HTTP and SSE transport layer.
#[derive(Clone)]
pub struct HttpTransportState {
    pub dispatcher: McpDispatcher,
    pub sessions: Arc<RwLock<HashMap<String, tokio::sync::mpsc::Sender<String>>>>,
    _forwarder: Arc<AbortOnDrop>,
}

impl HttpTransportState {
    pub fn new(dispatcher: McpDispatcher) -> Self {
        let sessions = Arc::new(RwLock::new(HashMap::new()));
        let forwarder = start_sse_event_forwarder(&dispatcher, sessions.clone());
        Self {
            dispatcher,
            sessions,
            _forwarder: Arc::new(AbortOnDrop(forwarder)),
        }
    }
}

/// Background task that consumes events from EventBus and forwards them to active SSE sessions.
/// Enforces per-session resource subscription routing and non-blocking delivery.
fn start_sse_event_forwarder(
    dispatcher: &McpDispatcher,
    sessions: Arc<RwLock<HashMap<String, tokio::sync::mpsc::Sender<String>>>>,
) -> tokio::task::JoinHandle<()> {
    let mut event_rx = dispatcher.event_bus.subscribe();
    let sub_manager = dispatcher.subscription_manager.clone();
    let bus = dispatcher.event_bus.clone();

    tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            match &event {
                crate::events::ServerEvent::ResourceUpdated { uri } => {
                    let subscribers = sub_manager.get_subscribers(uri).await;
                    if subscribers.is_empty() {
                        continue;
                    }
                    let notif = event.to_jsonrpc_notification();
                    let Ok(serialized) = serde_json::to_string(&notif) else {
                        continue;
                    };

                    let sessions_guard = sessions.read().await;
                    for sid in subscribers {
                        if sid == "stdio" {
                            continue;
                        }
                        if let Some(tx) = sessions_guard.get(&sid)
                            && let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) =
                                tx.try_send(serialized.clone())
                        {
                            bus.record_dropped();
                            warn!(session = %sid, "SSE event dropped: client buffer full");
                        }
                    }
                }
                _ => {
                    let notif = event.to_jsonrpc_notification();
                    let Ok(serialized) = serde_json::to_string(&notif) else {
                        continue;
                    };

                    let sessions_guard = sessions.read().await;
                    for (sid, tx) in sessions_guard.iter() {
                        if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) =
                            tx.try_send(serialized.clone())
                        {
                            bus.record_dropped();
                            warn!(session = %sid, "SSE event dropped: client buffer full");
                        }
                    }
                }
            }
        }
    })
}

/// Validates whether an incoming HTTP request satisfies configured Bearer authentication.
fn check_auth(
    headers: &HeaderMap,
    query: &HashMap<String, String>,
    dispatcher: &McpDispatcher,
) -> bool {
    // 1. Check standard Authorization header
    let auth_header = headers.get("authorization").and_then(|h| h.to_str().ok());
    if dispatcher.config.security.is_authorized(auth_header) {
        return true;
    }

    // 2. Fallback: check query parameter ?token=... (frequently used by browser EventSource clients)
    if let Some(token) = query.get("token") {
        return dispatcher.config.security.is_authorized(Some(token));
    }

    false
}

/// JSON-RPC Unauthorized Error Response Helper.
fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": serde_json::Value::Null,
            "error": {
                "code": -32000,
                "message": "Unauthorized: invalid or missing Bearer token"
            }
        })),
    )
        .into_response()
}

/// Health check and daemon status endpoint.
pub async fn handle_health(State(state): State<HttpTransportState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "vibe-daemon",
        "version": env!("CARGO_PKG_VERSION"),
        "transport": "http/sse",
        "registered_tools": state.dispatcher.tool_registry.len(),
    }))
}

/// Handles incoming JSON-RPC POST requests for both direct HTTP and SSE sessions.
pub async fn handle_post_message(
    State(state): State<HttpTransportState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
    body: String,
) -> Response {
    // 1. Verify authentication
    if !check_auth(&headers, &query, &state.dispatcher) {
        warn!("Unauthorized HTTP POST request rejected");
        return unauthorized_response();
    }

    let trimmed = body.trim();
    if trimmed.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": serde_json::Value::Null,
                "error": {
                    "code": PARSE_ERROR,
                    "message": "Request body cannot be empty"
                }
            })),
        )
            .into_response();
    }

    // 2. Parse JSON-RPC request
    let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
        Ok(req) => req,
        Err(err) => {
            warn!(error = %err, raw_body = %trimmed, "Failed to parse HTTP JSON-RPC request");
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": serde_json::Value::Null,
                    "error": {
                        "code": PARSE_ERROR,
                        "message": format!("Parse error: {err}")
                    }
                })),
            )
                .into_response();
        }
    };

    // Record client info if available
    if let Some(user_agent) = headers.get("user-agent").and_then(|u| u.to_str().ok())
        && let Ok(mut lock) = state.dispatcher.connected_client.write()
    {
        *lock = Some(user_agent.to_string());
    }

    // 3. Process request through MCP Dispatcher
    let session_id_opt = query.get("sessionId").map(|s| s.as_str());
    let response_opt = state
        .dispatcher
        .handle_request_with_session(request, session_id_opt)
        .await;

    // 4. If request is associated with an active SSE session, broadcast message to the stream
    if let Some(session_id) = query.get("sessionId") {
        let sessions = state.sessions.read().await;
        if let Some(tx) = sessions.get(session_id)
            && let Some(ref resp) = response_opt
            && let Ok(serialized) = serde_json::to_string(resp)
        {
            let _ = tx.send(serialized).await;
        }
    }

    // 5. Return HTTP response
    match response_opt {
        Some(resp) => (StatusCode::OK, Json(resp)).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

/// RAII Guard for cleaning up sessions and resource subscriptions when an SSE stream disconnects.
struct SessionGuard {
    session_id: String,
    sessions: Arc<RwLock<HashMap<String, tokio::sync::mpsc::Sender<String>>>>,
    subscription_manager: Arc<crate::resources::SubscriptionManager>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let session_id = self.session_id.clone();
        let sessions = self.sessions.clone();
        let subscription_manager = self.subscription_manager.clone();
        tokio::spawn(async move {
            let mut s = sessions.write().await;
            s.remove(&session_id);
            drop(s);
            subscription_manager.cleanup_session(&session_id).await;
            info!(session = %session_id, "SSE client disconnected, session & subscriptions cleaned up");
        });
    }
}

/// Server-Sent Events (SSE) streaming endpoint (`/sse`).
/// Establishes an SSE event stream and returns an endpoint URI with a unique sessionId.
pub async fn handle_sse(
    State(state): State<HttpTransportState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    // 1. Verify authentication
    if !check_auth(&headers, &query, &state.dispatcher) {
        warn!("Unauthorized SSE connection request rejected");
        return unauthorized_response();
    }

    let session_idx = SESSION_COUNTER.fetch_add(1, Ordering::SeqCst);
    let session_id = format!(
        "sess_{}_{:06x}",
        chrono::Utc::now().timestamp(),
        session_idx
    );
    info!(session = %session_id, "New SSE client connected");

    let (tx, rx) = tokio::sync::mpsc::channel::<String>(128);

    // Register active session
    {
        let mut sessions = state.sessions.write().await;
        sessions.insert(session_id.clone(), tx);
    }

    // 2. Initial event notifying client of message posting endpoint (MCP SSE Spec)
    let endpoint_url = format!("/message?sessionId={session_id}");
    let initial_event = Event::default().event("endpoint").data(endpoint_url);
    let initial_stream = tokio_stream::once(Ok::<_, Infallible>(initial_event));

    // 3. Stream of subsequent JSON-RPC messages routed to this session
    let rx_stream = ReceiverStream::new(rx)
        .map(|msg| Ok::<_, Infallible>(Event::default().event("message").data(msg)));

    let combined_stream = initial_stream.chain(rx_stream);

    let guard = Arc::new(SessionGuard {
        session_id: session_id.clone(),
        sessions: state.sessions.clone(),
        subscription_manager: state.dispatcher.subscription_manager.clone(),
    });

    let guarded_stream = combined_stream.map(move |item| {
        let _g = &guard;
        item
    });

    Sse::new(guarded_stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// Creates an Axum router configured with all MCP HTTP and SSE endpoints.
pub fn create_http_router(state: HttpTransportState) -> axum::Router {
    axum::Router::new()
        .route("/health", axum::routing::get(handle_health))
        .route(
            "/",
            axum::routing::get(handle_health).post(handle_post_message),
        )
        .route("/message", axum::routing::post(handle_post_message))
        .route("/sse", axum::routing::get(handle_sse))
        .with_state(state)
}

/// Binds and starts the HTTP / SSE remote transport server.
pub async fn run_http(
    dispatcher: McpDispatcher,
    host: &str,
    port: u16,
    transport_type: TransportType,
) -> anyhow::Result<()> {
    let state = HttpTransportState::new(dispatcher);
    let app = create_http_router(state.clone());
    let addr = format!("{host}:{port}");

    info!(
        address = %addr,
        transport = %transport_type,
        "Binding remote MCP transport server"
    );

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    let serve_res = axum::serve(listener, app).await;
    state.dispatcher.audit_logger.flush().await;
    serve_res?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use std::time::Duration;
    use tower::util::ServiceExt;

    #[tokio::test]
    async fn test_http_health_endpoint() {
        let dispatcher = McpDispatcher::new();
        let state = HttpTransportState::new(dispatcher);
        let app = create_http_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_http_post_initialize_request() {
        let dispatcher = McpDispatcher::new();
        let state = HttpTransportState::new(dispatcher);
        let app = create_http_router(state);

        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test-client", "version": "1.0" }
            }
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json_resp["id"], 1);
        assert_eq!(json_resp["result"]["serverInfo"]["name"], "vibe-daemon");
    }

    #[tokio::test]
    async fn test_http_post_tools_list_request() {
        let dispatcher = McpDispatcher::new();
        let state = HttpTransportState::new(dispatcher);
        let app = create_http_router(state);

        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/message")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json_resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json_resp["id"], 2);
        let tools = json_resp["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 33);
    }

    #[tokio::test]
    async fn test_http_bearer_auth_protection() {
        let mut config = crate::config::Config::default();
        config.security.auth_token = Some("secret-token-xyz".to_string());
        let dispatcher = McpDispatcher::with_config(config);
        let state = HttpTransportState::new(dispatcher);
        let app = create_http_router(state);

        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        });

        // 1. Without auth header -> 401 Unauthorized
        let unauth_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauth_res.status(), StatusCode::UNAUTHORIZED);

        // 2. With invalid bearer header -> 401 Unauthorized
        let wrong_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header("authorization", "Bearer wrong-token")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_res.status(), StatusCode::UNAUTHORIZED);

        // 3. With valid bearer header -> 200 OK
        let auth_res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header("authorization", "Bearer secret-token-xyz")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(auth_res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_sse_endpoint_establishes_connection() {
        let dispatcher = McpDispatcher::new();
        let state = HttpTransportState::new(dispatcher);
        let app = create_http_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/sse")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(content_type.contains("text/event-stream"));
    }

    #[tokio::test]
    async fn test_sse_server_initiated_notifications_with_session_isolation() {
        let dispatcher = McpDispatcher::new();
        let state = HttpTransportState::new(dispatcher);

        let (tx1, mut rx1) = tokio::sync::mpsc::channel::<String>(16);
        let (tx2, mut rx2) = tokio::sync::mpsc::channel::<String>(16);

        let sid1 = "session_iso_1";
        let sid2 = "session_iso_2";

        // Register active sessions
        {
            let mut sessions = state.sessions.write().await;
            sessions.insert(sid1.to_string(), tx1);
            sessions.insert(sid2.to_string(), tx2);
        }

        // Session 1 subscribes to system://status
        state
            .dispatcher
            .subscription_manager
            .subscribe(sid1, "system://status")
            .await
            .unwrap();

        // Session 2 subscribes to config://nginx/nginx.conf
        state
            .dispatcher
            .subscription_manager
            .subscribe(sid2, "config://nginx/nginx.conf")
            .await
            .unwrap();

        // 1. Emit ResourceUpdated for system://status -> only Session 1 should receive it
        state
            .dispatcher
            .event_bus
            .publish_immediate(crate::events::ServerEvent::ResourceUpdated {
                uri: "system://status".to_string(),
            });

        let msg1 = tokio::time::timeout(Duration::from_millis(1000), rx1.recv())
            .await
            .expect("Session 1 must receive resource update")
            .expect("Message received");

        let val1: serde_json::Value = serde_json::from_str(&msg1).unwrap();
        assert!(val1.get("id").is_none());
        assert_eq!(val1["method"], "notifications/resources/updated");
        assert_eq!(val1["params"]["uri"], "system://status");

        // Session 2 must NOT receive system://status update
        let no_msg2 = tokio::time::timeout(Duration::from_millis(100), rx2.recv()).await;
        assert!(
            no_msg2.is_err(),
            "Session 2 must not receive system://status notification"
        );

        // 2. Emit ResourceUpdated for config://nginx/nginx.conf -> only Session 2 should receive it
        state
            .dispatcher
            .event_bus
            .publish_immediate(crate::events::ServerEvent::ResourceUpdated {
                uri: "config://nginx/nginx.conf".to_string(),
            });

        let msg2 = tokio::time::timeout(Duration::from_millis(1000), rx2.recv())
            .await
            .expect("Session 2 must receive config update")
            .expect("Message received");

        let val2: serde_json::Value = serde_json::from_str(&msg2).unwrap();
        assert!(val2.get("id").is_none());
        assert_eq!(val2["method"], "notifications/resources/updated");
        assert_eq!(val2["params"]["uri"], "config://nginx/nginx.conf");

        // Session 1 must NOT receive config update
        let no_msg1 = tokio::time::timeout(Duration::from_millis(100), rx1.recv()).await;
        assert!(
            no_msg1.is_err(),
            "Session 1 must not receive config notification"
        );

        // 3. Emit broadcast TaskCompleted event -> both sessions should receive it
        state
            .dispatcher
            .event_bus
            .publish_immediate(crate::events::ServerEvent::TaskCompleted {
                task_id: "task-test-99".to_string(),
                status: crate::tasks::TaskStatus::Success,
            });

        let bcast1 = tokio::time::timeout(Duration::from_millis(1000), rx1.recv())
            .await
            .expect("Session 1 receives broadcast")
            .expect("Message received");
        let bcast2 = tokio::time::timeout(Duration::from_millis(1000), rx2.recv())
            .await
            .expect("Session 2 receives broadcast")
            .expect("Message received");

        let val_bcast1: serde_json::Value = serde_json::from_str(&bcast1).unwrap();
        let val_bcast2: serde_json::Value = serde_json::from_str(&bcast2).unwrap();

        assert_eq!(val_bcast1["method"], "notifications/tasks/completed");
        assert_eq!(val_bcast1["params"]["taskId"], "task-test-99");
        assert_eq!(val_bcast2["method"], "notifications/tasks/completed");
        assert_eq!(val_bcast2["params"]["taskId"], "task-test-99");

        // 4. Cleanup session
        state
            .dispatcher
            .subscription_manager
            .cleanup_session(sid1)
            .await;
        assert!(
            !state
                .dispatcher
                .subscription_manager
                .is_subscribed(sid1, "system://status")
                .await
        );
    }
}
