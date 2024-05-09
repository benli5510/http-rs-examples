// use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use tokio::net::TcpListener;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use httpsig_hyper::{prelude::*, *};

type BoxBody = http_body_util::combinators::BoxBody<bytes::Bytes, HyperDigestError>;
// type SignatureName = String;

#[path = "support/mod.rs"]
mod support;
use support::TokioIo;

type Counter = i32;

const EDDSA_SECRET_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDSHAE++q1BP7T8tk+mJtS+hLf81B0o6CFyWgucDFN/C
-----END PRIVATE KEY-----
"##;
/* const EDDSA_PUBLIC_KEY: &str = r##"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA1ixMQcxO46PLlgQfYS46ivFd+n0CcDHSKUnuhm3i1O0=
-----END PUBLIC KEY-----
"##; */
/* const HMACSHA256_SECRET_KEY: &str =
   r##"uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="##;
*/
const COVERED_COMPONENTS: &[&str] = &[
    "@status",
    "\"@method\";req",
    "date",
    "content-type",
    "\"content-digest\";req",
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: SocketAddr = ([127, 0, 0, 1], 3000).into();

    let listener = TcpListener::bind(addr).await?;
    println!("Listening on http://{}", addr);

    let svc = Svc {
        counter: Arc::new(Mutex::new(0)),
    };

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let svc_clone = svc.clone();
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new().serve_connection(io, svc_clone).await {
                println!("Failed to serve connection: {:?}", err);
            }
        });
    }
}

#[derive(Debug, Clone)]
struct Svc {
    counter: Arc<Mutex<Counter>>,
}

async fn build_response(s: String) -> Response<BoxBody> {
    // let body = Full::new(&b"{\"hello\": \"world!!\"}"[..]);
    let body = Full::new(s.as_bytes());
    let res = Response::builder()
        .status(200)
        .header("date", "Sun, 09 May 2021 18:30:00 GMT")
        .header("content-type", "application/json")
        .header("content-type", "application/json-patch+json")
        .body(body)
        .unwrap();
    res.set_content_digest(&ContentDigestType::Sha256)
        .await
        .unwrap()
}

/// Sender function that generates a request with a signature
async fn sender_ed25519(res: &mut Response<BoxBody>, received_req: &Request<IncomingBody>) {
    println!("Signing with ED25519 with key id");
    // build signature params that indicates objects to be signed
    let covered_components = COVERED_COMPONENTS
        .iter()
        .map(|v| message_component::HttpMessageComponentId::try_from(*v))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut signature_params = HttpSignatureParams::try_new(&covered_components).unwrap();

    // set signing/verifying key information, alg and keyid with ed25519
    let secret_key = SecretKey::from_pem(EDDSA_SECRET_KEY).unwrap();
    signature_params.set_key_info(&secret_key);

    // set signature with custom signature name
    res.set_message_signature(
        &signature_params,
        &secret_key,
        Some("siged25519"),
        Some(received_req),
    )
    .await
    .unwrap();
}

async fn mk_response(
    req: Request<IncomingBody>,
    s: String,
) -> Result<Response<BoxBody>, hyper::Error> {
    // Ok(Response::builder().body(Full::new(Bytes::from(s))).unwrap())

    let mut res = build_response(s).await;
    sender_ed25519(&mut res, &req).await;

    Ok(res)
}

impl Service<Request<IncomingBody>> for Svc {
    type Response = Response<BoxBody>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<IncomingBody>) -> Self::Future {
        if req.uri().path() != "/favicon.ico" {
            *self.counter.lock().expect("lock poisoned") += 1;
        }

        let res = match req.uri().path() {
            "/" => mk_response(req, format!("home! counter = {:?}", self.counter)),
            "/posts" => mk_response(
                req,
                format!("posts, of course! counter = {:?}", self.counter),
            ),
            "/authors" => mk_response(
                req,
                format!("authors extraordinare! counter = {:?}", self.counter),
            ),
            _ => mk_response(req, "oh no! not found".into()),
        };

        Box::pin(res)
    }
}
