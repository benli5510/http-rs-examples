use http::Request;
use http_body_util::Full;
use httpsig_hyper::{prelude::*, *};

type BoxBody = http_body_util::combinators::BoxBody<bytes::Bytes, HyperDigestError>;
type SignatureName = String;

const RSA_SECRET_KEY: &str = r##"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCS3yJC+6wxpYQ0
jnTzMDaZ0vvgCtrGIcWsB6ysM2FtebSZp3tncFsn0cdkLAElRp7vBnYZ0ppqklv9
w9DD81DXe5fwG2fCGwcm5EftiJbDitqiBQJPtUNI1pD/P1TvViOCJzU96Ff2/T2l
6vCCWsSHqw6m+/AMbRpmT8B4tOkVhXD07B3jB6T/fNg/HhruqNieBcvgO018yr5J
S8+yeaKwyvhkIKR6XW1zeUcQOkSC238bHPG7h6GTas8bb+XqOGxJVnBacNuqBU32
NcUhmLbmTDFAMFXmEq/5dOrMVbsLBs3RTSFHfbN3Wuk1GsqtcBgK3rhYPpDCdwGo
wp8ZT/NvAgMBAAECggEAQqpkv1nETd6u1TpKbG5YglcJvCbBKgj/VDhBkQJbeVky
eEJU2d1eiwMGCfqNZJGbJ6zbo5n8PF6FwfiFhMQnUEAJ9dNCtBEXnHgnC/MhV83p
snwqkeqZiXDXbPyevWpwgK3yVVDmyLYnKu4q0EiKB3jGFFasHb/SKVmO6FtZp0nz
9WN5g6HMPoeCzXobbeO5HtarMpDcBgVpGzsxdHSSdqT+jXM8HXFa+JGKZKE6vLk2
styzxfFSmjV9XqeOjYGMiQ/hSf+D2moP8qkO+/CHiVeLLRIp22U32c1mbXm7zKA3
tuytFWoi2oeI+dP0z/gLTPT0Rv30v291f5zOodnR6QKBgQC32bZyZ4VP5FlhK1pT
KYAtODWWq7kad7TK7MY9OVG3fuYg/K6kkHocr88Ofy6UIBRCOzkdyLdW0cpPU708
Fzv3rcP7wPnbkWLo1LRe2cClUZiejDPAOahGnaxLQkY18icLw9iwx7T6JB5CnWqc
rhpWUSk5L4+G/sGdVSJHJwrutwKBgQDMgmSyZ6YMJL2JHXA8hBf6go3YGx3l+TXZ
4gDShB6T71Qkc7S/7aCeA75MbV6RZrUM2FtA1gN8wW2gH6QOv2uJ0ejc6TdWEYSj
MrMhia2RvkrcvMvJSlXKPxGB+97X5PoSTwcEXwmJM0WSEadsDvtDyeTry1SoiH6s
Ntz9lZ/pCQKBgGnX+0ON+Z/vFM3uSYgLInHmJGPj5SMpu3oAKnjg4PzFH/PpxRmU
29hcFtZ/ve8lMMSYl99fyL1A9joJOa64qZuD/IqZpL8Vyl3E5zqcHl6OxVCx4rFO
AGT3LVP+ibFRAc2yKLRNpRFFbe5n9hLR4PPEsfjsOrM7Q3gypRNVlOOtAoGBALl3
y7DMNRewPj/adc48Ea77tX32YbANyZu2zf4dGcoZ81o3oQWqkM6dIHkZevkshyeG
E4QCUxlSJoRgDZ3eVb2go6msy6V/r6V9tlzFCqcxR51Wjw4XHySS++LBNIDhRTVT
fE6njfNij0aAQjDKiW8Z60U4mqdZWl/+RX6osmRZAoGAepdZtvE9dzEYkJztSq2g
vwDHjgB3Bh3ukyFKdKMVxioQ+QGB7a5vJXuNBeDJVH1ujM5qKlqZ6I8x7FlyTl08
3t8hXF339tiy7G7KhDi1XKjudkglbDe81iOfKtTQ/3P1L5Qnn5zQLAzDaJ3yVwMr
q4CF04xmoXhTFlkEDV42CeU=
-----END PRIVATE KEY-----
"##;
const RSA_PUBLIC_KEY: &str = r##"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkt8iQvusMaWENI508zA2
mdL74AraxiHFrAesrDNhbXm0mad7Z3BbJ9HHZCwBJUae7wZ2GdKaapJb/cPQw/NQ
13uX8BtnwhsHJuRH7YiWw4raogUCT7VDSNaQ/z9U71Yjgic1PehX9v09perwglrE
h6sOpvvwDG0aZk/AeLTpFYVw9Owd4wek/3zYPx4a7qjYngXL4DtNfMq+SUvPsnmi
sMr4ZCCkel1tc3lHEDpEgtt/Gxzxu4ehk2rPG2/l6jhsSVZwWnDbqgVN9jXFIZi2
5kwxQDBV5hKv+XTqzFW7CwbN0U0hR32zd1rpNRrKrXAYCt64WD6QwncBqMKfGU/z
bwIDAQAB
-----END PUBLIC KEY-----
"##;
const HMACSHA256_SECRET_KEY: &str =
    r##"uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="##;

const COVERED_COMPONENTS: &[&str] = &["@method", "date", "content-type", "content-digest"];

async fn build_request() -> Request<BoxBody> {
    let body = Full::new(&b"{\"hello\": \"world\"}"[..]);
    let req = Request::builder()
    .method("GET")
    .uri("https://example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something")
    .header("date", "Sun, 09 May 2021 18:30:00 GMT")
    .header("content-type", "application/json")
    .header("content-type", "application/json-patch+json")
    .body(body)
    .unwrap();
    req.set_content_digest(&ContentDigestType::Sha256)
        .await
        .unwrap()
}

/// Sender function that generates a request with a signature
async fn sender_rsa(req: &mut Request<BoxBody>) {
    println!("Signing with RSA with key id");
    // build signature params that indicates objects to be signed
    let covered_components = COVERED_COMPONENTS
        .iter()
        .map(|v| message_component::HttpMessageComponentId::try_from(*v))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut signature_params = HttpSignatureParams::try_new(&covered_components).unwrap();

    // set signing/verifying key information, alg and keyid with RSA
    let secret_key = SecretKey::from_pem(RSA_SECRET_KEY).unwrap();
    signature_params.set_key_info(&secret_key);

    // set signature with custom signature name
    req.set_message_signature(&signature_params, &secret_key, Some("siged25519"))
        .await
        .unwrap();
}

/// Sender function that generates a request with a signature
async fn sender_hs256(req: &mut Request<BoxBody>) {
    println!("Signing with HS256 with key id and random nonce");
    // build signature params that indicates objects to be signed
    let covered_components = COVERED_COMPONENTS
        .iter()
        .map(|v| message_component::HttpMessageComponentId::try_from(*v))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut signature_params = HttpSignatureParams::try_new(&covered_components).unwrap();

    // set signing/verifying key information, alg and keyid and random noce with hmac-sha256
    let shared_key = SharedKey::from_base64(HMACSHA256_SECRET_KEY).unwrap();
    signature_params.set_key_info(&shared_key);
    signature_params.set_random_nonce();

    req.set_message_signature(&signature_params, &shared_key, Some("sighs256"))
        .await
        .unwrap();
}

/// Receiver function that verifies a request with a signature of ed25519
async fn receiver_rsa<B>(req: &Request<B>) -> HyperSigResult<SignatureName>
where
    B: http_body::Body + Send + Sync,
{
    println!("Verifying ED25519 signature");
    let public_key = PublicKey::from_pem(RSA_PUBLIC_KEY).unwrap();
    let key_id = public_key.key_id();

    // verify signature with checking key_id
    req.verify_message_signature(&public_key, Some(&key_id))
        .await
}

/// Receiver function that verifies a request with a signature of hmac-sha256
async fn receiver_hmac_sha256<B>(req: &Request<B>) -> HyperSigResult<SignatureName>
where
    B: http_body::Body + Send + Sync,
{
    println!("Verifying HMAC-SHA256 signature");
    let shared_key = SharedKey::from_base64(HMACSHA256_SECRET_KEY).unwrap();
    let key_id = VerifyingKey::key_id(&shared_key);

    // verify signature with checking key_id
    req.verify_message_signature(&shared_key, Some(&key_id))
        .await
}

async fn scenario_multiple_signatures() {
    println!("--------------  Scenario: Multiple signatures  --------------");

    let mut request_from_sender = build_request().await;
    println!(
        "Request header before signing:\n{:#?}",
        request_from_sender.headers()
    );

    // sender signs a signature of ed25519 and hmac-sha256
    sender_rsa(&mut request_from_sender).await;
    sender_hs256(&mut request_from_sender).await;

    println!(
        "Request header separately signed by ED25519 and HS256:\n{:#?}",
        request_from_sender.headers()
    );

    let signature_inputs = request_from_sender
        .headers()
        .get_all("signature-input")
        .iter()
        .map(|v| v.to_str())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let signatures = request_from_sender
        .headers()
        .get_all("signature")
        .iter()
        .map(|v| v.to_str())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(signature_inputs
        .iter()
        .any(|v| v.starts_with(r##"siged25519=("##)));
    assert!(signature_inputs
        .iter()
        .any(|v| v.starts_with(r##"sighs256=("##)));
    assert!(signatures
        .iter()
        .any(|v| v.starts_with(r##"siged25519=:"##)));
    assert!(signatures.iter().any(|v| v.starts_with(r##"sighs256=:"##)));

    // receiver verifies the request with signatures
    // every signature is independent and verified separately
    let verification_res_ed25519 = receiver_rsa(&request_from_sender).await;
    assert!(verification_res_ed25519.is_ok());
    println!("ED25519 signature is verified");
    let verification_res_hs256 = receiver_hmac_sha256(&request_from_sender).await;
    assert!(verification_res_hs256.is_ok());
    println!("HMAC-SHA256 signature is verified");

    // if needed, content-digest can be verified separately
    let verified_request = request_from_sender.verify_content_digest().await;
    assert!(verified_request.is_ok());
    println!("Content-Digest header is verified");
}

async fn scenario_single_signature_ed25519() {
    println!("--------------  Scenario: Single signature with Ed25519  --------------");

    let mut request_from_sender = build_request().await;
    println!(
        "Request header before signing:\n{:#?}",
        request_from_sender.headers()
    );

    // sender signs a signature of ed25519
    sender_rsa(&mut request_from_sender).await;

    println!(
        "Request header signed by ED25519:\n{:#?}",
        request_from_sender.headers()
    );

    let signature_inputs = request_from_sender
        .headers()
        .get_all("signature-input")
        .iter()
        .map(|v| v.to_str())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let signatures = request_from_sender
        .headers()
        .get_all("signature")
        .iter()
        .map(|v| v.to_str())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(signature_inputs
        .iter()
        .any(|v| v.starts_with(r##"siged25519=("##)));
    assert!(signatures
        .iter()
        .any(|v| v.starts_with(r##"siged25519=:"##)));

    // receiver verifies the request with signatures
    // every signature is independent and verified separately
    let verification_res_ed25519 = receiver_rsa(&request_from_sender).await;
    assert!(verification_res_ed25519.is_ok());
    println!("ED25519 signature is verified");

    // if needed, content-digest can be verified separately
    let verified_request = request_from_sender.verify_content_digest().await;
    assert!(verified_request.is_ok());
    println!("Content-Digest header is verified");
}

#[tokio::main]
async fn main() {
    scenario_single_signature_ed25519().await;
    println!("-------------------------------------------------------------");
    scenario_multiple_signatures().await;
    println!("-------------------------------------------------------------");
}
