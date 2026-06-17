//! The blind relay: stores opaque, encrypted, expiring blobs keyed by a routing hash
//! and forwards them on request. It never links any crypto/identity crate, so it is
//! structurally incapable of reading what it relays. It also never logs anything
//! per-connection — no peer address, no routing key, no blob size or timing beyond
//! what the protocol itself requires to operate.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_ADDR: &str = "127.0.0.1:7878";
const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;
const MAX_TTL_SECS: u64 = 7 * 24 * 60 * 60;

#[derive(Debug, Error)]
enum RelayError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed request: {0}")]
    Malformed(String),
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum Request {
    Push {
        routing_key: String,
        blob: String,
        #[serde(default)]
        ttl_secs: Option<u64>,
    },
    Pull {
        routing_key: String,
    },
}

#[derive(Serialize, Deserialize, Default)]
struct Response {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    blob: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

struct Entry {
    blob: Vec<u8>,
    expires_at: Instant,
}

type SharedStore = Arc<Mutex<HashMap<String, Entry>>>;

fn main() {
    if let Err(err) = run() {
        eprintln!("sympoden-relay: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), RelayError> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_ADDR.to_string());
    let listener = TcpListener::bind(&addr)?;
    eprintln!("sympoden-relay listening on {addr}");

    let store: SharedStore = Arc::new(Mutex::new(HashMap::new()));

    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        let store = Arc::clone(&store);
        thread::spawn(move || {
            let _ = handle_connection(stream, &store);
        });
    }

    Ok(())
}

fn handle_connection(mut stream: TcpStream, store: &SharedStore) -> Result<(), RelayError> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    let response = match serde_json::from_str::<Request>(line.trim_end()) {
        Ok(request) => handle_request(request, store),
        Err(e) => Response {
            ok: false,
            blob: None,
            error: Some(format!("malformed request: {e}")),
        },
    };

    let mut serialized =
        serde_json::to_vec(&response).map_err(|e| RelayError::Malformed(e.to_string()))?;
    serialized.push(b'\n');
    stream.write_all(&serialized)?;
    Ok(())
}

fn handle_request(request: Request, store: &SharedStore) -> Response {
    match request {
        Request::Push {
            routing_key,
            blob,
            ttl_secs,
        } => handle_push(routing_key, blob, ttl_secs, store),
        Request::Pull { routing_key } => handle_pull(routing_key, store),
    }
}

/// One blob waiting per routing key. A push to a key that's already holding an
/// undelivered, unexpired blob is rejected rather than silently overwriting (and
/// destroying) it - the client decides what to do (e.g. wait for the recipient to
/// pull, then retry). The relay never queues multiple blobs per key.
const OCCUPIED_ERROR: &str = "occupied";

fn handle_push(
    routing_key: String,
    blob: String,
    ttl_secs: Option<u64>,
    store: &SharedStore,
) -> Response {
    let Ok(blob_bytes) = BASE64.decode(&blob) else {
        return Response {
            ok: false,
            blob: None,
            error: Some("blob is not valid base64".to_string()),
        };
    };

    let ttl = ttl_secs.unwrap_or(DEFAULT_TTL_SECS).min(MAX_TTL_SECS);
    let entry = Entry {
        blob: blob_bytes,
        expires_at: Instant::now() + Duration::from_secs(ttl),
    };

    let Ok(mut guard) = store.lock() else {
        return Response {
            ok: false,
            blob: None,
            error: Some("internal error".to_string()),
        };
    };

    let occupied =
        matches!(guard.get(&routing_key), Some(existing) if existing.expires_at > Instant::now());
    if occupied {
        return Response {
            ok: false,
            blob: None,
            error: Some(OCCUPIED_ERROR.to_string()),
        };
    }

    guard.insert(routing_key, entry);

    Response {
        ok: true,
        blob: None,
        error: None,
    }
}

fn handle_pull(routing_key: String, store: &SharedStore) -> Response {
    let Ok(mut guard) = store.lock() else {
        return Response {
            ok: false,
            blob: None,
            error: Some("internal error".to_string()),
        };
    };

    let still_valid =
        matches!(guard.get(&routing_key), Some(entry) if entry.expires_at > Instant::now());
    let blob = if still_valid {
        guard.remove(&routing_key).map(|e| e.blob)
    } else {
        guard.remove(&routing_key);
        None
    };

    Response {
        ok: true,
        blob: blob.map(|b| BASE64.encode(b)),
        error: None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;

    fn start_test_relay() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let store: SharedStore = Arc::new(Mutex::new(HashMap::new()));

        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let store = Arc::clone(&store);
                thread::spawn(move || {
                    let _ = handle_connection(stream, &store);
                });
            }
        });

        addr
    }

    fn request(addr: std::net::SocketAddr, body: &str) -> Response {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.write_all(body.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    #[test]
    fn push_then_pull_returns_the_blob() {
        let addr = start_test_relay();
        let blob = BASE64.encode(b"opaque ciphertext");

        let push_resp = request(
            addr,
            &format!(r#"{{"op":"push","routing_key":"abc123","blob":"{blob}","ttl_secs":60}}"#),
        );
        assert!(push_resp.ok);

        let pull_resp = request(addr, r#"{"op":"pull","routing_key":"abc123"}"#);
        assert!(pull_resp.ok);
        assert_eq!(pull_resp.blob, Some(blob));
    }

    #[test]
    fn second_push_to_an_occupied_key_is_rejected_not_overwritten() {
        let addr = start_test_relay();
        let first_blob = BASE64.encode(b"first note");
        let second_blob = BASE64.encode(b"second note");

        let first_push = request(
            addr,
            &format!(r#"{{"op":"push","routing_key":"k9","blob":"{first_blob}"}}"#),
        );
        assert!(first_push.ok);

        let second_push = request(
            addr,
            &format!(r#"{{"op":"push","routing_key":"k9","blob":"{second_blob}"}}"#),
        );
        assert!(!second_push.ok);
        assert_eq!(second_push.error, Some(OCCUPIED_ERROR.to_string()));

        // The first blob must still be exactly what was pushed - never overwritten.
        let pull_resp = request(addr, r#"{"op":"pull","routing_key":"k9"}"#);
        assert_eq!(pull_resp.blob, Some(first_blob));

        // Now that the slot is free, the second note can be pushed and delivered.
        let retry_push = request(
            addr,
            &format!(r#"{{"op":"push","routing_key":"k9","blob":"{second_blob}"}}"#),
        );
        assert!(retry_push.ok);
        let second_pull = request(addr, r#"{"op":"pull","routing_key":"k9"}"#);
        assert_eq!(second_pull.blob, Some(second_blob));
    }

    #[test]
    fn pull_deletes_after_delivery() {
        let addr = start_test_relay();
        let blob = BASE64.encode(b"once only");

        request(
            addr,
            &format!(r#"{{"op":"push","routing_key":"k1","blob":"{blob}"}}"#),
        );
        let first = request(addr, r#"{"op":"pull","routing_key":"k1"}"#);
        assert!(first.blob.is_some());

        let second = request(addr, r#"{"op":"pull","routing_key":"k1"}"#);
        assert!(second.ok);
        assert_eq!(second.blob, None);
    }

    #[test]
    fn pull_on_unknown_key_returns_no_blob_not_an_error() {
        let addr = start_test_relay();
        let resp = request(addr, r#"{"op":"pull","routing_key":"nonexistent"}"#);

        assert!(resp.ok);
        assert_eq!(resp.blob, None);
    }

    #[test]
    fn expired_entry_is_not_returned() {
        let addr = start_test_relay();
        let blob = BASE64.encode(b"expires fast");

        request(
            addr,
            &format!(r#"{{"op":"push","routing_key":"k2","blob":"{blob}","ttl_secs":0}}"#),
        );
        thread::sleep(Duration::from_millis(50));

        let resp = request(addr, r#"{"op":"pull","routing_key":"k2"}"#);
        assert!(resp.ok);
        assert_eq!(resp.blob, None);
    }

    #[test]
    fn malformed_request_returns_clean_error_not_a_crash() {
        let addr = start_test_relay();
        let resp = request(addr, "not json at all");

        assert!(!resp.ok);
        assert!(resp.error.is_some());
    }

    #[test]
    fn relay_never_stores_or_returns_anything_resembling_plaintext_metadata() {
        // The relay's Response/Entry types only ever carry base64 blob bytes and a
        // routing key string supplied by the client — there is no field for, and no
        // code path that reads, a peer address, a plaintext body, or any identity.
        let addr = start_test_relay();
        let blob = BASE64.encode(b"the eagle has landed");

        request(
            addr,
            &format!(r#"{{"op":"push","routing_key":"k3","blob":"{blob}"}}"#),
        );
        let resp = request(addr, r#"{"op":"pull","routing_key":"k3"}"#);

        // What comes back is exactly the same base64 ciphertext we put in - the relay
        // round-trips opaque bytes, it does not parse or re-derive anything from them.
        assert_eq!(resp.blob, Some(blob));
    }
}
