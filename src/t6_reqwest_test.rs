use std::sync::Arc;

use rustls::client::{danger::ServerCertVerifier, ResolvesClientCert, WebPkiServerVerifier};

#[derive(Debug)]
struct CustomServerVerifier(Arc<WebPkiServerVerifier>);
impl ServerCertVerifier for CustomServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.0
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

#[tokio::test]
async fn use_preconfigured_rustls_default() {
    extern crate rustls;
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
    };
    let server_verifier = Arc::new(CustomServerVerifier(
        WebPkiServerVerifier::builder(Arc::new(root_store))
            .build()
            .unwrap(),
    ));
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(server_verifier)
        .with_no_client_auth();
    let res = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .use_preconfigured_tls(config)
        .https_only(true)
        .build()
        .expect("client builder")
        .get("https://www.baidu.com")
        .send()
        .await;
    let body = res.unwrap().bytes().await.unwrap().to_vec();
    let content = String::from_utf8(body);
    println!("content: {}", content.unwrap());
}

fn main() {
    println!("he")
}
