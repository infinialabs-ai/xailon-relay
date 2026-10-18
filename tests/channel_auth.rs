use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use relay::{ClientFrame, ServerFrame, auth};
use serde_json::json;
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

struct RelayServer(Child);

impl RelayServer {
    fn spawn(port: u16, database: &std::path::Path, extra: &[&str]) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_relay"))
            .args([
                "--bind",
                &format!("127.0.0.1:{port}"),
                "--database",
                database.to_str().unwrap(),
            ])
            .args(extra)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self(child)
    }
}

impl Drop for RelayServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn open(
    port: u16,
    id: &str,
    endpoint: &str,
    device: &str,
    token: Option<[u8; 32]>,
) -> Socket {
    let auth = if token.is_some() { "&auth=1" } else { "" };
    let url =
        format!("ws://127.0.0.1:{port}/ws?id={id}&endpoint={endpoint}&device_id={device}{auth}");
    for _ in 0..200 {
        if let Ok((mut socket, _)) = connect_async(&url).await {
            if let Some(token) = token {
                let frame = ClientFrame::Auth {
                    token: base64_token(&token),
                };
                socket
                    .send(Message::Text(serde_json::to_string(&frame).unwrap().into()))
                    .await
                    .unwrap();
            }
            return socket;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("relay did not start");
}

fn base64_token(token: &[u8; 32]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token)
}

async fn next(socket: &mut Socket) -> Option<ServerFrame> {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("timed out waiting for a frame")?;
        match message.ok()? {
            Message::Text(text) => return Some(serde_json::from_str(&text).unwrap()),
            Message::Close(_) => return None,
            _ => continue,
        }
    }
}

async fn expect_ready(socket: &mut Socket) {
    assert!(matches!(
        next(socket).await,
        Some(ServerFrame::Ready { .. })
    ));
}

async fn expect_error(socket: &mut Socket, prefix: &str) {
    match next(socket).await {
        Some(ServerFrame::Error { message }) => {
            assert!(message.starts_with(prefix), "{message}");
        }
        other => panic!("expected {prefix}, got {other:?}"),
    }
    assert!(next(socket).await.is_none(), "socket should close");
}

#[tokio::test]
async fn self_certifying_channel_requires_its_token() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let _relay = RelayServer::spawn(port, &dir.path().join("relay.sqlite3"), &[]);
    let token = [7; 32];
    let id = auth::channel_id(&token);

    let mut host = open(port, &id, "1", "host", Some(token)).await;
    expect_ready(&mut host).await;

    // Knowing the id is not enough: no token, or a different one, is refused
    // before the socket can preempt the host or acknowledge its backlog.
    let mut thief = open(port, &id, "1", "host", None).await;
    expect_error(&mut thief, "relay_auth_required").await;
    let mut thief = open(port, &id, "1", "host", Some([8; 32])).await;
    expect_error(&mut thief, "relay_auth_failed").await;

    let mut phone = open(port, &id, "2", "phone", Some(token)).await;
    expect_ready(&mut phone).await;
    let frame = ClientFrame::Message {
        message_id: "m1".into(),
        payload: json!({"hello": 1}),
        target_device_id: None,
        ephemeral: false,
    };
    phone
        .send(Message::Text(serde_json::to_string(&frame).unwrap().into()))
        .await
        .unwrap();
    assert!(matches!(
        next(&mut phone).await,
        Some(ServerFrame::Stored { .. })
    ));
    match next(&mut host).await {
        Some(ServerFrame::Message { payload, .. }) => assert_eq!(payload, json!({"hello": 1})),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn first_authenticated_connection_claims_a_legacy_id() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let _relay = RelayServer::spawn(port, &dir.path().join("relay.sqlite3"), &[]);
    let id = "legacy-channel-id";

    // Unclaimed legacy ids keep working without auth.
    let mut old = open(port, id, "2", "old", None).await;
    expect_ready(&mut old).await;
    drop(old);

    let mut owner = open(port, id, "1", "host", Some([1; 32])).await;
    expect_ready(&mut owner).await;

    let mut other = open(port, id, "2", "phone", None).await;
    expect_error(&mut other, "relay_auth_required").await;
    let mut other = open(port, id, "2", "phone", Some([2; 32])).await;
    expect_error(&mut other, "relay_auth_failed").await;
    let mut phone = open(port, id, "2", "phone", Some([1; 32])).await;
    expect_ready(&mut phone).await;
}

#[tokio::test]
async fn malformed_auth_frames_and_late_auth_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let _relay = RelayServer::spawn(port, &dir.path().join("relay.sqlite3"), &[]);

    let url = format!("ws://127.0.0.1:{port}/ws?id=x&endpoint=1&device_id=d&auth=1");
    let mut socket = loop {
        if let Ok((socket, _)) = connect_async(&url).await {
            break socket;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    socket
        .send(Message::Text(r#"{"type":"auth","token":"short"}"#.into()))
        .await
        .unwrap();
    expect_error(&mut socket, "relay_auth_failed").await;

    let mut socket = open(port, "y", "1", "d", None).await;
    expect_ready(&mut socket).await;
    let frame = ClientFrame::Auth {
        token: base64_token(&[3; 32]),
    };
    socket
        .send(Message::Text(serde_json::to_string(&frame).unwrap().into()))
        .await
        .unwrap();
    assert!(matches!(
        next(&mut socket).await,
        Some(ServerFrame::Error { .. })
    ));
}

#[tokio::test]
async fn require_auth_refuses_unauthenticated_channels() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let _relay = RelayServer::spawn(port, &dir.path().join("relay.sqlite3"), &["--require-auth"]);
    let mut socket = open(port, "anything", "1", "d", None).await;
    expect_error(&mut socket, "relay_auth_required").await;
    let mut socket = open(port, "anything", "1", "d", Some([5; 32])).await;
    expect_ready(&mut socket).await;
}

#[tokio::test]
async fn connections_are_rate_limited_per_ip() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let _relay = RelayServer::spawn(
        port,
        &dir.path().join("relay.sqlite3"),
        &["--max-connections-per-minute", "3"],
    );
    let url = format!("ws://127.0.0.1:{port}/ws?id=z&endpoint=1&device_id=d");
    // Wait for the server without spending the budget.
    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut accepted = 0;
    for _ in 0..5 {
        if connect_async(&url).await.is_ok() {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 3);
}

#[derive(Default)]
struct Events {
    connected: std::sync::atomic::AtomicUsize,
    payloads: std::sync::Mutex<Vec<serde_json::Value>>,
    errors: std::sync::Mutex<Vec<String>>,
}

impl relay_client::ClientHandler for Events {
    fn on_payload(&self, payload: serde_json::Value) {
        self.payloads.lock().unwrap().push(payload);
    }
    fn on_connected(&self) {
        self.connected
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    fn on_disconnected(&self, error: Option<String>) {
        if let Some(error) = error {
            self.errors.lock().unwrap().push(error);
        }
    }
}

#[tokio::test]
async fn rust_client_authenticates_with_its_token() {
    use relay_client::{Client, Endpoint, memory::MemoryStore, transport::endpoint_url};
    use std::sync::{Arc, atomic::Ordering};

    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let _relay = RelayServer::spawn(port, &dir.path().join("relay.sqlite3"), &[]);
    let token = [9; 32];
    let id = relay_client::auth::channel_id(&token);
    assert_eq!(id, auth::channel_id(&token));
    let base = format!("ws://127.0.0.1:{port}/ws");

    let events = Arc::new(Events::default());
    let host = Client::new(
        endpoint_url(&base, &id, Endpoint::One, "host"),
        Arc::new(MemoryStore::new()),
        events.clone(),
    )
    .with_auth_token(token);
    tokio::spawn(host.clone().into_task());

    let mut phone = open(port, &id, "2", "phone", Some(token)).await;
    expect_ready(&mut phone).await;
    for _ in 0..250 {
        if events.connected.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(events.connected.load(Ordering::SeqCst), 1);
    host.send(json!({"from": "host"})).await.unwrap();
    assert!(matches!(
        next(&mut phone).await,
        Some(ServerFrame::Message { .. })
    ));

    // A client with the wrong token never connects and sees the reason.
    let wrong = Arc::new(Events::default());
    let intruder = Client::new(
        endpoint_url(&base, &id, Endpoint::Two, "phone"),
        Arc::new(MemoryStore::new()),
        wrong.clone(),
    )
    .with_auth_token([1; 32]);
    tokio::spawn(intruder.clone().into_task());
    for _ in 0..250 {
        if !wrong.errors.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    intruder.close();
    assert_eq!(wrong.connected.load(Ordering::SeqCst), 0);
    let errors = wrong.errors.lock().unwrap();
    assert!(errors[0].contains("relay_auth_failed"), "{errors:?}");
}
