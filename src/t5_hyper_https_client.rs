// #![deny(warnings)]
#![warn(rust_2018_idioms)]
use std::env;

use bytes::Bytes;
use http::Method;
use http_body_util::{BodyExt, Full};
// use hyper::{body::HttpBody as _, client::Client};
use hyper::Request;
// use hyper_tls::HttpsConnector;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use tokio::io::{self, AsyncWriteExt as _};
// use tokio::net::TcpStream;

#[path = "support/mod.rs"]
mod support;
// use support::TokioIo;

// A simple type alias so as to DRY.
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();

    // Some simple CLI args requirements...
    let url = match env::args().nth(1) {
        Some(url) => url,
        None => {
            println!("Usage: client <url>");
            return Ok(());
        }
    };
    println!("url = {}", url);

    // HTTPS requires picking a TLS implementation, so give a better
    // warning if the user tries to request an 'https' URL.
    let url = url.parse::<hyper::Uri>().unwrap();
    if url.scheme_str() != Some("https") {
        println!("This example only works with 'https' URLs.");
        return Ok(());
    }

    fetch_url(url).await
}

#[test]
fn test_uri_parse() {
    let url = "https://example.com";
    let uri = url.parse::<hyper::Uri>().unwrap();
    println!("--- uri: {:?}", uri.host());
}

async fn fetch_url(url: hyper::Uri) -> Result<()> {
    // let host = url.host().expect("uri has no host");
    // let port = url.port_u16().unwrap_or(80);
    // let addr = format!("{}:{}", host, port);
    // let stream = TcpStream::connect(addr).await?;
    // let io = TokioIo::new(stream);

    // let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    // let https = HttpsConnector::new();
    // let client = Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(https);
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    // tokio::task::spawn(async move {
    //     if let Err(err) = conn.await {
    //         println!("Connection failed: {:?}", err);
    //     }
    // });

    let authority = url.authority().unwrap().clone();

    let path = url.path();
    let req = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(hyper::header::HOST, authority.as_str())
        // .body(Empty::<Bytes>::new())?;
        .body(Full::from("Hallo!"))?;

    let mut res = client.request(req).await?;

    println!("Response: {}", res.status());
    println!("Headers: {:#?}\n", res.headers());

    // Stream the body, writing each chunk to stdout as we get it
    // (instead of buffering and printing at the end).
    while let Some(next) = res.frame().await {
        let frame = next?;
        if let Some(chunk) = frame.data_ref() {
            io::stdout().write_all(chunk).await?;
        }
    }

    println!("\n\nDone!");

    Ok(())
}
