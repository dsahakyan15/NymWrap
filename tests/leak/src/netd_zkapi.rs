//! Actual HTTP bytes to a synthetic loopback peer; no public Tor/Nym/clientd.
use super::*;
use base64ct::{Base64, Encoding};
use nw_shield::{ConversationVault, Secret, SecretKind, Shield};
use std::collections::BTreeMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CANARY: &str = "zkapi_synthetic_canary_51716";
fn canary_encodings() -> [String; 6] {
    [
        CANARY.into(),
        Base64::encode_string(CANARY.as_bytes()),
        CANARY.bytes().map(|b| format!("{b:02x}")).collect(),
        CANARY.bytes().map(|b| format!("%{b:02X}")).collect(),
        CANARY
            .chars()
            .map(|c| format!("\\u{:04x}", c as u32))
            .collect(),
        CANARY
            .chars()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(" "),
    ]
}
fn shield() -> Shield {
    Shield::new(vec![
        Secret::new(SecretKind::Secret, CANARY.into(), false).unwrap(),
    ])
    .unwrap()
}
fn request() -> Request {
    let prepared = shield()
        .prepare(
            &format!("Explain pottery for {CANARY}"),
            &mut ConversationVault::default(),
            |s| Ok(s.into()),
        )
        .unwrap();
    let shaped = nw_net::ShapedRequest::new(&prepared).unwrap();
    Request {
        conversation: "a".repeat(32),
        body: shaped.bytes().to_vec(),
        authorization: "synthetic-local-client-token-51716".into(),
    }
}
async fn local_exchange(
    status: &str,
    headers: &str,
    body: &[u8],
) -> (Result<String, &'static str>, String, Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let response = [
        format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
            body.len()
        )
        .into_bytes(),
        body.to_vec(),
    ]
    .concat();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            assert!(head.len() < 16384);
            head.push(stream.read_u8().await.unwrap());
        }
        let head = String::from_utf8(head).unwrap();
        let headers: BTreeMap<_, _> = head
            .lines()
            .skip(1)
            .filter_map(|s| s.split_once(':'))
            .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
            .collect();
        let length: usize = headers["content-length"].parse().unwrap();
        assert!(nw_net::BYTE_BUCKETS.contains(&length));
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await.unwrap();
        let _ = stream.write_all(&response).await;
        (head, body)
    });
    let stream = TcpStream::connect(address).await.unwrap();
    let answer = tokio::time::timeout(
        Duration::from_secs(5),
        exchange(stream, &address.to_string(), &request()),
    )
    .await
    .unwrap();
    let (head, body) = server.await.unwrap();
    (answer, head, body)
}
const ANSWER: &[u8] =
    br#"{"choices":[{"message":{"role":"assistant","content":"<script>data only</script>"}}]}"#;

#[tokio::test]
async fn zkapi_local_protocol_has_only_checked_chat_and_allowlisted_headers() {
    let (answer, head, body) = local_exchange(
        "200 OK",
        "Content-Type: application/json\r\nX-OA-Verification-Status: verified\r\n",
        ANSWER,
    )
    .await;
    assert_eq!(answer.unwrap(), "<script>data only</script>");
    assert!(head.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
    let names: Vec<_> = head
        .lines()
        .skip(1)
        .filter_map(|s| s.split_once(':'))
        .map(|(k, _)| k.to_ascii_lowercase())
        .collect();
    assert_eq!(
        names,
        [
            "host",
            "content-type",
            "accept",
            "accept-encoding",
            "connection",
            "authorization",
            "content-length"
        ]
    );
    assert!(head.contains("Bearer synthetic-local-client-token-51716"));
    assert_eq!(body, request().body);
    let text = std::str::from_utf8(&body).unwrap();
    for marker in canary_encodings() {
        assert!(!head.contains(&marker));
        assert!(!text.contains(&marker));
    }
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body.as_object().unwrap().len(), 5);
    assert_eq!(body["stream"], false);
    assert_eq!(body["temperature"], 0);
    assert!(body.get("user").is_none());
}

#[tokio::test]
async fn zkapi_unavailable_redirect_unverified_tools_and_malformed_answers_fail_closed() {
    let verified = "Content-Type: application/json\r\nX-OA-Verification-Status: verified\r\n";
    for (status, headers, body) in [
        ("503 Unavailable", verified, ANSWER),
        (
            "302 Found",
            "Location: https://provider.example.test\r\n",
            ANSWER,
        ),
        ("200 OK", "Content-Type: application/json\r\n", ANSWER),
        (
            "200 OK",
            "Content-Type: application/json\r\nX-OA-Verification-Status: verifier-unavailable\r\nX-OA-Verification-Detail: trusted_station_fallback\r\n",
            ANSWER,
        ),
        (
            "200 OK",
            "Content-Type: application/json\r\nX-OA-Verification-Status: verified\r\nX-OA-Verification-Status: verifier-unavailable\r\n",
            ANSWER,
        ),
        (
            "200 OK",
            "Content-Type: application/json\r\nX-OA-Verification-Status: verified\r\nX-OA-Verification-Detail: trusted_station_fallback\r\n",
            ANSWER,
        ),
        (
            "200 OK",
            "Content-Type: text/html\r\nX-OA-Verification-Status: verified\r\n",
            ANSWER,
        ),
        ("200 OK", verified, b"not JSON"),
        (
            "200 OK",
            verified,
            br#"{"choices":[{"message":{"role":"assistant","content":"x","tool_calls":[]}}]}"#,
        ),
    ] {
        assert!(local_exchange(status, headers, body).await.0.is_err());
    }
    let (stream, peer) = tokio::io::duplex(64);
    drop(peer);
    assert!(
        exchange(stream, "127.0.0.1:8080", &request())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn zkapi_rejects_endpoint_and_metadata_before_writing_any_bytes() {
    for authority in [
        "example.test:80",
        "192.0.2.1:80",
        "127.0.0.1:0",
        "127.0.0.1:80/path",
    ] {
        let (stream, mut peer) = tokio::io::duplex(65536);
        assert_eq!(
            exchange(stream, authority, &request()).await.unwrap_err(),
            "invalid_zkapi_endpoint"
        );
        assert_eq!(
            peer.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
    let mut request = request();
    let mut value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    value["user"] = CANARY.into();
    request.body = serde_json::to_vec(&value).unwrap();
    request.body.resize(2048, b' ');
    let (stream, mut peer) = tokio::io::duplex(65536);
    assert_eq!(
        exchange(stream, "127.0.0.1:8080", &request)
            .await
            .unwrap_err(),
        "invalid_request"
    );
    assert_eq!(
        peer.read_u8().await.unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
}

#[test]
fn zkapi_final_model_output_is_leakchecked_before_a_request_can_be_shaped() {
    for output in canary_encodings() {
        let result = shield().prepare("Explain pottery", &mut ConversationVault::default(), |_| {
            Ok(output.clone())
        });
        assert!(
            result.is_err(),
            "last model output must not become an outbound request"
        );
    }
}
