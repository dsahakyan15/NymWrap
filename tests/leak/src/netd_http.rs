//! Compiled by nw-netd's test target: capture its real HTTP serializer in memory.
use crate::{Provider, http_exchange, validate};
use base64ct::Encoding;
use nw_net::wire::Request;
use std::collections::BTreeMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Captured {
    raw_head: String,
    first_line: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}
async fn exchange(
    request: &Request,
    response: Vec<u8>,
) -> (Result<String, &'static str>, Captured) {
    let (client, mut server) = tokio::io::duplex(65536);
    let reading = tokio::spawn(async move {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            assert!(head.len() < 16384);
            head.push(server.read_u8().await.unwrap());
        }
        let head = String::from_utf8(head).unwrap();
        let mut lines = head.split("\r\n");
        let first_line = lines.next().unwrap().to_owned();
        let mut headers = BTreeMap::new();
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').unwrap();
            assert!(
                headers
                    .insert(name.to_ascii_lowercase(), value.trim().to_owned())
                    .is_none()
            );
        }
        let length: usize = headers["content-length"].parse().unwrap();
        assert!(nw_net::BYTE_BUCKETS.contains(&length));
        let mut body = vec![0; length];
        server.read_exact(&mut body).await.unwrap();
        // A rejected/oversized response may intentionally close before this completes.
        let _ = server.write_all(&response).await;
        Captured {
            raw_head: head,
            first_line,
            headers,
            body,
        }
    });
    let provider = Provider::new("API.Example.Test".into(), "/v1/chat/completions".into()).unwrap();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        http_exchange(client, &provider, request),
    )
    .await
    .unwrap();
    (result, reading.await.unwrap())
}
#[tokio::test]
async fn provider_headers_match_cross_platform_golden_bytes() {
    let (_, captured) = exchange(
        &request(32),
        response(
            "200 OK",
            "Content-Type: application/json\r\n",
            br#"{"choices":[{"message":{"role":"assistant","content":"synthetic"}}]}"#,
        ),
    )
    .await;
    let hex: String = captured
        .raw_head
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if std::env::var_os("NW_UPDATE_PROTOCOL_GOLDEN").is_some() {
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/leak/fixtures/provider-http-v1.hex"
            ),
            format!("{hex}\n"),
        )
        .unwrap();
        return;
    }
    assert_eq!(hex, include_str!("../fixtures/provider-http-v1.hex").trim());
}
fn response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}
fn request(length: usize) -> Request {
    let canary = "SYNTHETIC_HTTP_WIRE_CANARY_51846_SecretOnly";
    let shield = nw_shield::Shield::new(vec![
        nw_shield::Secret::new(nw_shield::SecretKind::Secret, canary.into(), false).unwrap(),
    ])
    .unwrap();
    let prepared = shield
        .prepare(
            &format!("Explain pottery for {canary}. {}", "x".repeat(length)),
            &mut nw_shield::ConversationVault::default(),
            |text| Ok(serde_json::json!([{"role":"user","content":text}]).to_string()),
        )
        .unwrap();
    let shaped = nw_net::ShapedRequest::history(&prepared, "synthetic", 16).unwrap();
    Request {
        conversation: "a".repeat(32),
        body: shaped.bytes().to_vec(),
        authorization: "synthetic-provider-token".into(),
    }
}
#[tokio::test]
async fn serialized_http_keeps_canaries_out_and_uses_exact_body_buckets_and_header_allowlist() {
    let canary = "SYNTHETIC_HTTP_WIRE_CANARY_51846_SecretOnly";
    for (index, length) in [32, 2200, 4400, 8500, 17000].into_iter().enumerate() {
        let request = request(length);
        validate(&request).unwrap();
        let (answer, captured) = exchange(
            &request,
            response(
                "200 OK",
                "Content-Type: application/json\r\n",
                br#"{"choices":[{"message":{"role":"assistant","content":"synthetic answer"}}]}"#,
            ),
        )
        .await;
        assert_eq!(answer.unwrap(), "synthetic answer");
        assert_eq!(captured.first_line, "POST /v1/chat/completions HTTP/1.1");
        assert_eq!(
            captured.headers,
            BTreeMap::from([
                ("accept".into(), "application/json".into()),
                ("accept-encoding".into(), "identity".into()),
                (
                    "authorization".into(),
                    "Bearer synthetic-provider-token".into()
                ),
                ("connection".into(), "close".into()),
                (
                    "content-length".into(),
                    nw_net::BYTE_BUCKETS[index].to_string()
                ),
                ("content-type".into(), "application/json".into()),
                ("host".into(), "api.example.test".into()),
            ])
        );
        assert_eq!(captured.body, request.body);
        let text = std::str::from_utf8(&captured.body).unwrap();
        for forbidden in [
            canary.to_owned(),
            base64ct::Base64::encode_string(canary.as_bytes()),
            canary.bytes().map(|b| format!("{b:02x}")).collect(),
        ] {
            assert!(!text.contains(&forbidden));
        }
        assert!(!text.contains(&request.conversation));
        let json: serde_json::Value = serde_json::from_slice(&captured.body).unwrap();
        assert_eq!(json["temperature"], 0);
        assert_eq!(json["stream"], false);
    }
}
#[tokio::test]
async fn actual_http_response_path_rejects_redirect_compression_tools_and_oversized_content() {
    let request = request(32);
    for bytes in [
        response("302 Found", "Location: https://evil.test/\r\n", b""),
        response(
            "200 OK",
            "Content-Type: application/json\r\nContent-Encoding: gzip\r\n",
            b"{}",
        ),
        response(
            "200 OK",
            "Content-Type: text/html\r\n",
            b"<script>data</script>",
        ),
        response(
            "200 OK",
            "Content-Type: application/json\r\n",
            br#"{"choices":[{"message":{"role":"assistant","content":"x","tool_calls":[]}}]}"#,
        ),
        response(
            "200 OK",
            "Content-Type: application/json\r\n",
            &vec![b'x'; 1024 * 1024 + 1],
        ),
    ] {
        assert!(exchange(&request, bytes).await.0.is_err());
    }
}
#[tokio::test]
async fn hard_identifiers_never_reach_production_http_bytes() {
    use nw_shield::{ConversationVault, Secret, SecretKind, Shield};
    let device = "SYNTHETIC_DEVICE_HTTP_CANARY_6319";
    let shield = Shield::new(vec![
        Secret::new(SecretKind::Device, device.into(), false).unwrap(),
    ])
    .unwrap();
    let facts = [
        device,
        "40.1772, 44.5035",
        "aa:bb:cc:dd:ee:ff",
        "490154203237518",
        "/home/synthetic-path-http/project",
        "Asia/Yerevan",
        "2026-11-23T12:34:56+04:00",
        "12345678-1234-4321-8000-123456789abc",
    ];
    for fact in facts {
        let prepared = shield
            .prepare(
                &format!("Explain pottery for {fact}"),
                &mut ConversationVault::default(),
                |text| Ok(serde_json::json!([{"role":"user","content":text}]).to_string()),
            )
            .unwrap();
        let body = nw_net::ShapedRequest::history(&prepared, "synthetic", 16).unwrap();
        let request = Request {
            conversation: "a".repeat(32),
            body: body.bytes().to_vec(),
            authorization: "synthetic-provider-token".into(),
        };
        let (_, captured) = exchange(
            &request,
            response(
                "200 OK",
                "Content-Type: application/json\r\n",
                br#"{"choices":[{"message":{"role":"assistant","content":"synthetic"}}]}"#,
            ),
        )
        .await;
        let mut wire = captured.raw_head.into_bytes();
        wire.extend_from_slice(&captured.body);
        for needle in [
            fact.to_owned(),
            base64ct::Base64::encode_string(fact.as_bytes()),
            fact.bytes().map(|b| format!("{b:02x}")).collect(),
        ] {
            assert!(!String::from_utf8_lossy(&wire).contains(&needle));
        }
    }
}
