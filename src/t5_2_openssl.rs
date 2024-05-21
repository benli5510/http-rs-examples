use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use openssl::x509::X509;
use std::fs::File;
use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ----------------------- Sign -------------------------------------
    // 读取私钥文件
    let mut file = File::open("src/cert/privkey.pem")?;
    let mut key_data = Vec::new();
    file.read_to_end(&mut key_data)?;

    // 加载私钥
    let rsa = Rsa::private_key_from_pem(&key_data)?;
    let private_key = PKey::from_rsa(rsa)?;

    // 要签名的消息
    let message = b"message to sign";

    // 创建签名器
    let mut signer = Signer::new(MessageDigest::sha256(), &private_key)?;
    signer.update(message)?;

    // 生成签名
    let signature = signer.sign_to_vec()?;

    println!("签名: {:?}", signature);

    // ----------------------- Verify -------------------------------------
    // 读取证书文件
    let mut file = File::open("src/cert/cert.pem")?;
    let mut cert_data = Vec::new();
    file.read_to_end(&mut cert_data)?;

    // 加载证书
    let cert = X509::from_pem(&cert_data)?;

    // 提取公钥
    let public_key = cert.public_key()?;
    // let rsa = public_key.rsa()?;

    // 要验证的消息和签名

    // 创建验证器
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key)?;
    verifier.update(message)?;

    // 验证签名
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

    Ok(())
}
