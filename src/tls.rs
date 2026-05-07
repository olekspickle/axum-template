use hyper_util::{rt, server::conn::auto::Builder, service::TowerToHyperService};
use std::sync::Arc;

pub async fn run_with_tls(addr: std::net::SocketAddr, router: axum::Router) -> anyhow::Result<()> {
    let tls_config = load_tls_config();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(address = %addr, "listening (HTTPS)");

    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let svc = router.into_service();
                    let hyper_svc = TowerToHyperService::new(svc);

                    // start main hyper service
                    if let Err(e) = Builder::new(rt::TokioExecutor::new())
                        .serve_connection(io, hyper_svc)
                        .await
                    {
                        tracing::error!(error = %e, "TLS connection error");
                    }
                }
                Err(e) => tracing::error!(error = %e, "TLS handshake failed"),
            }
        });
    }
}

/// use openssl to generate ssl certs
/// openssl req -newkey rsa:2048 -new -nodes -keyout key.pem -out csr.pem
///
/// or for dev purposes
///
/// openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem -addext "subjectAltName = DNS:mydnsname.com"
fn load_tls_config() -> rustls::ServerConfig {
    use rustls::ServerConfig;
    use rustls::pki_types::CertificateDer;
    use rustls_pemfile::{certs, private_key};

    let cert_file =
        &mut std::io::BufReader::new(std::fs::File::open("cert.pem").expect("cert.pem not found"));
    let key_file =
        &mut std::io::BufReader::new(std::fs::File::open("key.pem").expect("key.pem not found"));

    let cert_chain: Vec<CertificateDer> = certs(cert_file)
        .collect::<Result<_, _>>()
        .expect("failed to parse cert.pem");
    let key = private_key(key_file)
        .expect("failed to parse key.pem")
        .expect("no private key found");

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .expect("invalid TLS cert/key")
}
