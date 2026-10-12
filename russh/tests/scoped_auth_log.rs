use std::borrow::Cow;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, KeyboardInteractiveAuthResponse};
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::{Disconnect, server};

const PASSWORD: &str = "scoped-password-9cQ72!";
const REJECTED: &str = "scoped-rejected-3vA51!";
const ANSWER: &str = "scoped-answer-6xB83!";

struct Capture(Mutex<Vec<String>>);

static LOG: Capture = Capture(Mutex::new(Vec::new()));

impl log::Log for Capture {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.target().starts_with("russh")
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            self.0.lock().unwrap().push(record.args().to_string());
        }
    }

    fn flush(&self) {}
}

struct Client {
    expected: PublicKey,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
        Ok(*key == self.expected)
    }
}

struct Server {
    rounds: usize,
}

impl server::Handler for Server {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        _: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        Ok(if password == PASSWORD {
            server::Auth::Accept
        } else {
            server::Auth::reject()
        })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _: &str,
        _: &str,
        response: Option<server::Response<'a>>,
    ) -> Result<server::Auth, Self::Error> {
        if let Some(mut response) = response {
            if response.next().as_deref() != Some(ANSWER.as_bytes()) || response.next().is_some() {
                return Ok(server::Auth::reject());
            }
            self.rounds += 1;
            if self.rounds == 2 {
                return Ok(server::Auth::Accept);
            }
        }
        Ok(server::Auth::Partial {
            name: Cow::Borrowed("fixture"),
            instructions: Cow::Borrowed(""),
            prompts: Cow::Owned(vec![(Cow::Borrowed("response"), false)]),
        })
    }
}

async fn authentication(keyboard: bool) {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let expected = key.public_key().clone();
    let config = Arc::new(server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..server::Config::default()
    });
    let (client_stream, server_stream) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        server::run_stream(config, server_stream, Server { rounds: 0 })
            .await
            .unwrap()
            .await
    });
    let mut client = client::connect_stream(
        Arc::new(client::Config::default()),
        client_stream,
        Client { expected },
    )
    .await
    .unwrap();
    if keyboard {
        let response = client
            .authenticate_keyboard_interactive_start("fixture", None)
            .await
            .unwrap();
        assert!(matches!(
            response,
            KeyboardInteractiveAuthResponse::InfoRequest { .. }
        ));
        let response = client
            .authenticate_keyboard_interactive_respond(vec![ANSWER.into()])
            .await
            .unwrap();
        assert!(matches!(
            response,
            KeyboardInteractiveAuthResponse::InfoRequest { .. }
        ));
        let response = client
            .authenticate_keyboard_interactive_respond(vec![ANSWER.into()])
            .await
            .unwrap();
        assert!(matches!(response, KeyboardInteractiveAuthResponse::Success));
    } else {
        assert!(
            !client
                .authenticate_password("fixture", REJECTED)
                .await
                .unwrap()
                .success()
        );
        assert!(
            client
                .authenticate_password("fixture", PASSWORD)
                .await
                .unwrap()
                .success()
        );
    }
    client
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
    assert!(matches!(
        client.await,
        Ok(()) | Err(russh::Error::Disconnect)
    ));
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn authentication_secrets_are_not_emitted_at_trace_level() {
    log::set_logger(&LOG).unwrap();
    log::set_max_level(log::LevelFilter::Trace);
    tokio::time::timeout(Duration::from_secs(15), async {
        authentication(false).await;
        authentication(true).await;
    })
    .await
    .unwrap();
    let records = LOG.0.lock().unwrap();
    assert!(!records.is_empty());
    for secret in [PASSWORD, REJECTED, ANSWER] {
        // 检查明文与 Vec<u8> 的实际 Debug 表示，不绑定日志措辞。
        let decimal = secret
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        assert!(
            records
                .iter()
                .all(|record| !record.contains(secret) && !record.contains(&decimal))
        );
    }
}
