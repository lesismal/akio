//! Prints a PEM certificate signing request for the names given, with a new P-256 key (the
//! key's PEM goes to stderr): `cargo run -p akio-x509 --example csr -- example.com www.example.com`.

use akio_crypto::pkey::PrivateKey;
use akio_x509::CsrParams;

fn main() {
    let names: Vec<String> = std::env::args().skip(1).collect();
    let key = PrivateKey::P256(akio_crypto::p256::SecretKey::generate().expect("random"));
    let csr = CsrParams::new(&names).sign(&key).expect("sign");
    print!("{}", csr.to_pem());
    eprint!(
        "{}",
        akio_crypto::pem::encode("PRIVATE KEY", &key.to_pkcs8_der())
    );
}
