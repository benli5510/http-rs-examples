use bytes::Bytes;
// use http_body_util::to_bytes;
use http_body_util::{BodyExt, Empty};
use hyper_tls::HttpsConnector;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use tokio::io::{self, AsyncWriteExt as _};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let https = HttpsConnector::new();
    let client = Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(https);

    let mut res = client.get("https://example.com".parse()?).await?;
    assert_eq!(res.status(), 200);
    println!("res {:?}", res);
    while let Some(next) = res.frame().await {
        let frame = next?;
        if let Some(chunk) = frame.data_ref() {
            io::stdout().write_all(chunk).await?;
        }
    }
    Ok(())
}
