extern crate alloc;

use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::crypto::aws_lc_rs::ALL_CIPHER_SUITES;
use rustls::crypto::{aws_lc_rs as provider, CryptoProvider};

mod danger {
    use std::cell::RefCell;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use std::sync::{Arc, RwLock};

    use pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::client::danger::HandshakeSignatureValid;
    use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
    use rustls::lock::Mutex;
    // use rustls::webpki::verify::{
    //     verify_server_cert_signed_by_trust_anchor_impl, verify_tls12_signature,
    //     verify_tls13_signature, ParsedCertificate,
    // };
    use rustls::DigitallySignedStruct;

    #[derive(Debug)]
    pub struct MyCertificateVerification {
        pub provider: CryptoProvider,
        // pub stores: Mutex<Vec<Vec<u8>>>,
    }

    impl MyCertificateVerification {
        pub fn new(provider: CryptoProvider) -> Self {
            Self {
                provider,
                // stores: Vec::new(),
            }
        }

        pub fn push() {}
    }

    impl rustls::client::danger::ServerCertVerifier for MyCertificateVerification {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            server_name: &ServerName<'_>,
            ocsp: &[u8],
            now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            println!("---- 22 verify_server_cert: 11{end_entity:?}, 22{intermediates:?}, {server_name:?}, {ocsp:?}, {now:?}");

            let b64 = base64::encode(end_entity);
            let filename = format!("cert.pem");
            let path = Path::new(&filename);
            let mut file = File::create(path).unwrap();
            file.write_all(b"-----BEGIN CERTIFICATE-----\n").unwrap();
            file.write_all(b64.as_bytes()).unwrap();
            file.write_all(b"\n-----END CERTIFICATE-----").unwrap();
            println!("Certificate  written to {}", filename);

            Ok(rustls::client::danger::ServerCertVerified::assertion())
            // let cert = ParsedCertificate::try_from(end_entity)?;

            // let crl_refs = self.crls.iter().collect::<Vec<_>>();

            // let revocation = if self.crls.is_empty() {
            //     None
            // } else {
            //     // Note: unwrap here is safe because RevocationOptionsBuilder only errors when given
            //     //       empty CRLs.
            //     Some(
            //         webpki::RevocationOptionsBuilder::new(crl_refs.as_slice())
            //             // Note: safe to unwrap here - new is only fallible if no CRLs are provided
            //             //       and we verify this above.
            //             .unwrap()
            //             .with_depth(self.revocation_check_depth)
            //             .with_status_policy(self.unknown_revocation_policy)
            //             .build(),
            //     )
            // };

            // // Note: we use the crate-internal `_impl` fn here in order to provide revocation
            // // checking information, if applicable.
            // verify_server_cert_signed_by_trust_anchor_impl(
            //     &cert,
            //     &self.roots,
            //     intermediates,
            //     revocation,
            //     now,
            //     self.supported.all,
            // )?;

            // if !ocsp_response.is_empty() {
            //     trace!("Unvalidated OCSP response: {:?}", ocsp_response.to_vec());
            // }

            // verify_server_name(&cert, server_name)?;
            // Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            println!("---- 22 verify_tls12_signature");
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            println!("---- 22 verify_tls13_signature: {message:?}, {cert:?}, {dss:?}");

            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            println!("---- 22 supported_verify_schemes");
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}

#[tokio::main]
async fn main() {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // let cipher_suites = provider::DEFAULT_CIPHER_SUITES.to_vec();
    let crypto_provider = CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        ..provider::default_provider()
    };
    let protocol_versions = rustls::DEFAULT_VERSIONS.to_vec();

    let mut config = rustls::ClientConfig::builder_with_protocol_versions(&protocol_versions)
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config
        .dangerous()
        .set_certificate_verifier(Arc::new(danger::MyCertificateVerification::new(
            crypto_provider,
        )));
    // To extract session key
    config.enable_secret_extraction = true;

    let host_name = "test.alux.fun";

    let res = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .use_preconfigured_tls(config)
        .https_only(true)
        .build()
        .expect("client builder")
        .get(host_name)
        .send()
        .await;

    println!("res: {:?}", res);
}
