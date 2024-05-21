use std::fs::File;
use std::io::Read;

use bytes::Bytes;
use http::header::COOKIE;
use http::Method;
use http_body_util::combinators::BoxBody;
// use http_body_util::to_bytes;
use http_body_util::{BodyExt, Empty, Full};
use httpsig_hyper::{ContentDigest, ContentDigestType, HyperDigestError, ResponseContentDigest};
use hyper::body::Incoming;
use hyper_tls::HttpsConnector;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::pkey_ctx::PkeyCtx;
use openssl::rsa::{Padding, Rsa};
use openssl::sign::Verifier;
use openssl::x509::X509;
use regex::Regex;
// use rsa::signature::Signer;
use openssl::sign::Signer;
use sfv::FromStr;
use tokio::io::{self, AsyncWriteExt as _};

type NewResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
use tokio::net::TcpStream;
#[path = "support/mod.rs"]
mod support;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hyper::{Request, Response};
use support::TokioIo;

// use hyper::body::to_bytes;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let https = HttpsConnector::new();
    // https.
    let client = Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(https);

    let url_str = "https://test.alux.fun";
    let url = url_str.parse::<hyper::Uri>().unwrap();
    if url.scheme_str() != Some("https") {
        println!("This example only works with 'https' URLs.");
        return Ok(());
    }
    let authority = url.authority().unwrap().clone();
    println!("authority: {:?}", authority);

    let path = url.path();
    println!("path: {:?}", path);
    let mut req = Request::builder()
        .method(Method::GET)
        .uri("https://test.alux.fun/api/v3/avgPrice?symbol=BTCUSDT")
        .header(hyper::header::HOST, authority.as_str())
        .body(Empty::<Bytes>::new())?;
    // .body(Full::from("Hallo!"))?;
    req.headers_mut()
        .insert(COOKIE, "x_proxy_target=api.binance.com".parse().unwrap());

    let mut res = client.request(req.clone()).await?;
    assert_eq!(res.status(), 200);
    // println!("res {:?}", res);
    println!("Response: {}", res.status());
    println!("Headers: {:#?}\n", res.headers());

    // --- verify content digest
    let r = verify_content_d(res).await;
    println!("--- return {:?}", r);
    // let verified = res.verify_content_digest().await;
    // let verified = verified.unwrap();
    // verify(&req, &verified).await;

    // let server_cert = verified.peer_certificate().ok_or("No certificate found")?;

    // let ssl_info = verified
    //     .extensions()
    //     .get::<hyper::client::connect::Connection>()
    //     .unwrap()
    //     .ssl();

    // while let Some(next) = res.frame().await {
    //     let frame = next?;
    //     if let Some(chunk) = frame.data_ref() {
    //         io::stdout().write_all(chunk).await?;
    //     }
    // }

    Ok(())
}

async fn extract_content_digest(
    header_map: &http::HeaderMap,
) -> Result<(ContentDigestType, Vec<u8>), String> {
    let content_digest_header = header_map
        .get("content-digest")
        .ok_or(HyperDigestError::NoDigestHeader(
            "No content-digest header".to_string(),
        ))
        .unwrap()
        .to_str()
        .unwrap();
    let indexmap = sfv::Parser::parse_dictionary(content_digest_header.as_bytes())
        .map_err(|e| HyperDigestError::InvalidHeaderValue(e.to_string()))
        .unwrap();
    if indexmap.len() != 1 {
        return Err("Content-Digest header should have only one value".to_string());
    };
    let (cd_type, cd) = indexmap.iter().next().unwrap();
    let cd_type = ContentDigestType::from_str(cd_type)
        .map_err(|e| {
            HyperDigestError::InvalidHeaderValue(format!("Invalid Content-Digest type: {e}"))
        })
        .unwrap();
    if !matches!(
        cd,
        sfv::ListEntry::Item(sfv::Item {
            bare_item: sfv::BareItem::ByteSeq(_),
            ..
        })
    ) {
        return Err("Invalid Content-Digest value".to_string());
    }

    let cd = match cd {
        sfv::ListEntry::Item(sfv::Item {
            bare_item: sfv::BareItem::ByteSeq(cd),
            ..
        }) => cd,
        _ => unreachable!(),
    };
    Ok((cd_type, cd.to_owned()))
}

fn derive_digest(body_bytes: &Bytes, cd_type: &ContentDigestType) -> Vec<u8> {
    match cd_type {
        ContentDigestType::Sha256 => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(body_bytes);
            hasher.finalize().to_vec()
        }

        ContentDigestType::Sha512 => {
            let mut hasher = sha2::Sha512::new();
            hasher.update(body_bytes);
            hasher.finalize().to_vec()
        }
    }
}

async fn verify_content_d(res: Response<Incoming>) -> Result<(), String> {
    let header_map = res.headers();
    let (cd_type, expected_digest) = extract_content_digest(header_map).await?;
    println!("--- _expected_digest {:?}", expected_digest);
    println!("--- cd_type {}", cd_type);
    let (header, body) = res.into_parts();
    let body_bytes = body
        .into_bytes()
        .await
        .map_err(|_e| "Failed to get body bytes".to_string())?;
    println!("--- body {:?}", body_bytes);
    let digest = derive_digest(&body_bytes, &cd_type);
    println!("--- digest {:?}", digest);

    println!("{:?} - {:?}", digest, expected_digest);
    let var_name = matches!(digest, expected_digest);
    println!("--- matches {}", var_name);
    if var_name {
        let new_body = Full::new(body_bytes)
            .map_err(|never| match never {})
            .boxed();
        let res = Response::from_parts(header, new_body);
        Ok(())
    } else {
        Err("Content-Digest verification failed".to_string())
    }
}

async fn verify(
    req: &Request<Empty<Bytes>>,
    res: &Response<BoxBody<Bytes, HyperDigestError>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let signature_inputs = res
        .headers()
        .get_all("signature-input")
        .iter()
        .map(|v| v.to_str())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    println!("signature-input: {:?}", signature_inputs);
    println!("signature-input: {:?}", signature_inputs.len());

    let re = Regex::new(r"created=(\d+)").unwrap();
    let timestamp = if let Some(captures) = re.captures(signature_inputs[0]) {
        if let Some(created) = captures.get(1) {
            created.as_str()
        } else {
            ""
        }
    } else {
        ""
    };

    let signature = res
        .headers()
        .get("signature")
        .map(|v| v.to_str().unwrap_or(""))
        .unwrap_or("");
    println!("signature: {:?}", signature);
    let re = Regex::new(r"sig=:(.*):").unwrap();
    let signature = if let Some(captures) = re.captures(signature) {
        if let Some(created) = captures.get(1) {
            created.as_str()
        } else {
            ""
        }
    } else {
        ""
    };
    println!("signature: {:?}", signature);
    // let signature = base64::decode(signature).unwrap();
    let signature = STANDARD.decode(signature).unwrap();
    println!("signature: {:?}", signature);

    let digests = res
        .headers()
        .get_all("content-digest")
        .iter()
        .map(|v| v.to_str())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    println!("content-digest: {:?}", digests);

    let content_type = res
        .headers()
        .get_all("content-type")
        .iter()
        .map(|v| v.to_str())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    println!("content_type: {:?}", content_type[0]);

    // let authority = res
    //     .headers()
    //     .get("authority")
    //     .map(|v| v.to_str().unwrap_or(""))
    //     .unwrap_or("");
    // println!("auth: {:?}", authority);

    /*
    local sig_input = 'sig=("@status" "@method" "content-digest" "content-type");alg="' .. alg .. '";created=' .. timestamp .. ';keyid="' .. keyid .. '"'
             */
    let message = format!(
        "sig=({} {} {});alg={};created={};keyid={}",
        // res.status(),
        200,
        // req.method(),
        // "",
        digests[0],
        content_type[0],
        "rsa-pss-sha512",
        timestamp,
        "RSA (X.509 preloaded)"
    );
    println!("message {}", message);

    // ----- check digest

    // ----- check signature
    let public_key = get_pubkey()?;
    let mut verifier = Verifier::new(MessageDigest::sha512(), &public_key)?;
    verifier.update(message.as_bytes())?;
    match verifier.verify(&signature) {
        Ok(valid) => {
            if valid {
                println!("verify sign ok");
            } else {
                println!("verify sign failed");
            }
        }
        Err(e) => {
            println!("failure: {}", e);
        }
    }

    Ok(())
}

/* fn verify_content_digest2(res: &Response<Incoming>) -> Result<bool, String> {
    let header_map = res.headers();

    // let (cd_type, _expected_digest) = extract_content_digest(header_map).await?;
    let content_digest_header = header_map
        .get("content-digest")
        .ok_or("No content-digest header".to_string())?;

    let indexmap = sfv::Parser::parse_dictionary(content_digest_header.as_bytes())
        .map_err(|e| (e.to_string()))?;
    if indexmap.len() != 1 {
        return Err("Content-Digest header should have only one value".to_string());
    };
    let (cd_type, cd) = indexmap.iter().next().unwrap();

    if !matches!(
        cd,
        sfv::ListEntry::Item(sfv::Item {
            bare_item: sfv::BareItem::ByteSeq(_),
            ..
        })
    ) {
        return Err("Invalid Content-Digest value".to_string());
    }

    let cd = match cd {
        sfv::ListEntry::Item(sfv::Item {
            bare_item: sfv::BareItem::ByteSeq(cd),
            ..
        }) => cd,
        _ => unreachable!(),
    };

    /* let body_bytes = res.body
    .into_bytes()
    .await
    .map_err(|_e| "Failed to get body bytes".to_string())?;
    // let body_bytes = Bytes::new();

    // let digest = derive_digest(&body_bytes, &cd_type);
    match cd_type {
      "sha-256".to_string() => {
        let mut hasher = sha2::Sha256::new();
        hasher.update(body_bytes);
        hasher.finalize().to_vec()
      }

      "sha-512" => {
        let mut hasher = sha2::Sha512::new();
        hasher.update(body_bytes);
        hasher.finalize().to_vec()
      }
    }

    if matches!(digest, _expected_digest) {
        let new_body = Full::new(body_bytes)
            .map_err(|never| match never {})
            .boxed();
        let res = Response::from_parts(header, new_body);
        Ok(res)
    } else {
        Err(            "Content-Digest verification failed".to_string()
        )
    } */
    Ok(true)
}
 */
/* async fn verify_content_digest(res: &Response<Incoming>) -> bool {
    let verified = res.verify_content_digest().await;
    let verified = verified.unwrap();
    // assert!(verified.is_ok());

    let digests = verified
        .headers()
        .get_all("content-digest")
        .iter()
        .map(|v| v.to_str())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    // 获取响应体
    res.body().as_bytes()
    let body_bytes = to_bytes(res.into_body()).await?;
    let body = body_bytes.to_vec();

    // 计算响应体的 SHA-256 摘要
    let mut hasher = Hasher::new(MessageDigest::sha256())?;
    hasher.update(&body)?;
    let computed_digest = hasher.finish()?;

    // 将计算得到的摘要转换为十六进制字符串
    let computed_digest_hex = hex::encode(computed_digest);

    // 提取 Content-Digest 头中的哈希值
    let expected_digest = content_digest
        .split('=')
        .nth(1)
        .ok_or("Invalid Content-Digest header format")?;

    // 验证摘要
    if computed_digest_hex == expected_digest {
        println!("Content-Digest 验证成功");
    } else {
        println!("Content-Digest 验证失败");
    }
}
 */

fn get_pubkey() -> Result<PKey<Public>, Box<dyn std::error::Error>> {
    let mut file = File::open("src/cert/cert.pem")?;
    let mut cert_data = Vec::new();
    file.read_to_end(&mut cert_data)?;

    // 加载证书
    let cert = X509::from_pem(&cert_data)?;

    // 提取公钥
    let public_key = cert.public_key()?;
    // let rsa = public_key.rsa()?;

    Ok(public_key)
}

fn get_pubkey2() -> Result<PKey<Public>, Box<dyn std::error::Error>> {
    let mut file = File::open("src/cert/cert2.pem")?;
    let mut cert_data = Vec::new();
    file.read_to_end(&mut cert_data)?;

    // 加载证书
    let cert = X509::from_pem(&cert_data)?;

    // 提取公钥
    let public_key = cert.public_key()?;
    // let rsa = public_key.rsa()?;

    Ok(public_key)
}

#[test]
fn test_get_pk_from_pem_file() {
    let public_key = get_pubkey().unwrap();

    let public_key2 = get_pubkey2().unwrap();
    assert!(public_key.public_eq(&public_key2));
    // println!("public_key: {:?}", public_key.bits());
}

fn get_privkey() -> Result<PKey<Private>, Box<dyn std::error::Error>> {
    let mut file = File::open("src/cert/privkey.pem")?;
    let mut sk_data = Vec::new();
    file.read_to_end(&mut sk_data)?;

    let private_key = Rsa::private_key_from_pem(&sk_data)?;
    let private_key = PKey::from_rsa(private_key)?;
    // let rsa = public_key.rsa()?;

    Ok(private_key)
}

use hex_literal::hex;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};
#[test]
fn test_hmac() {
    // Create alias for HMAC-SHA256
    // type HmacSha256 = Hmac<Sha256>;
    let input = b"sig=(200 sha-512=:keYwxw5Z4P2muqeocDSvex6gcBOSd1Ke0XD9hdmz89mkHJfhypS5XIZ9/x8pRiL+VfQAPkPj1WWE0DHlWhVyRA==: application/json;charset=UTF-8);alg=rsa-pss-sha512;created=1716131615;keyid=RSA (X.509 preloaded)";

    let mut mac = Hmac::<Sha512>::new_from_slice(b"").expect("HMAC can take key of any size");
    mac.update(input);

    // `result` has type `CtOutput` which is a thin wrapper around array of
    // bytes for providing constant time equality check
    let result = mac.finalize();
    // To get underlying array use `into_bytes`, but be careful, since
    // incorrect use of the code value may permit timing attacks which defeats
    // the security provided by the `CtOutput`
    let code_bytes = result.into_bytes();
    let output: String = code_bytes
        .iter()
        .map(|&byte| format!("{:02x}", byte))
        .collect();
    println!("digest {:02x?}", output);
    //     let expected = hex!(
    //         "
    //     97d2a569059bbcd8ead4444ff99071f4
    //     c01d005bcefe0d3567e1be628e5fdcd9
    // "
    //     );
    //     assert_eq!(code_bytes[..], expected[..]);

    let private_key = get_privkey().unwrap();

    let mut signer = Signer::new(MessageDigest::sha512(), &private_key).unwrap();
    let _ = signer.update(input);
    let signature = signer.sign_to_vec().unwrap();
    println!("Signature: {:02x?}", signature);

    /* let mut signer = Signer::new(MessageDigest::null(), &private_key).unwrap();
    // signer.set_rsa_padding(Padding::PKCS1);
    signer.update(&code_bytes).unwrap();
    let signature = signer.sign_to_vec().unwrap(); */

    // let signature_base64 = base64::encode(&signature);
    let signature_base64 = STANDARD.encode(&signature);
    println!("Signature: {:?}", signature_base64);

    let public_key = get_pubkey().unwrap();
    let mut verifier = Verifier::new(MessageDigest::sha512(), &public_key).unwrap();
    verifier.update(input).unwrap();
    match verifier.verify(&signature) {
        Ok(valid) => {
            if valid {
                println!("签名验证成功");
            } else {
                println!("签名验证失败");
            }
        }
        Err(e) => {
            println!("验证过程中出错: {}", e);
        }
    }
}
