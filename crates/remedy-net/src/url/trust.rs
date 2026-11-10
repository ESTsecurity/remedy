//! 믿을 인증서 — OS 저장소 ∪ 내장 Mozilla 목록(`webpki-roots`) ∪ `--cacert`. 검증은 로컬(webpki)이다.
//!
//! **검증을 끄는 길이 없다.** `--cacert` 는 그 실행에만 믿을 CA 를 *더한다*(기본 목록을 바꾸지 않는다).
//! OS 검증기를 쓰지 않는 까닭은 워크스페이스 `Cargo.toml` 의 통신 절 — Windows 에서 폐기 확인 · 중간
//! 인증서를 온라인으로 가져와, 사용자가 적지 않은 주소로 요청이 나간다.

use remedy_sdk::i18n::Lang;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

/// `--cacert` 파일의 상한.
const MAX_CA_BYTES: u64 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaError {
    Open,
    NotFile,
    TooLarge,
    NoPem,
    Rejected,
    Config,
}

impl CaError {
    pub(crate) fn message(self, lang: Lang) -> &'static str {
        match self {
            CaError::Open => lang.t(
                "CA 인증서 파일을 열지 못했습니다.",
                "could not open the CA certificate file.",
            ),
            CaError::NotFile => lang.t(
                "CA 인증서 경로가 일반 파일이 아닙니다.",
                "the CA certificate path is not a regular file.",
            ),
            CaError::TooLarge => lang.t(
                "CA 인증서 파일이 1 MiB 를 넘습니다.",
                "the CA certificate file is larger than 1 MiB.",
            ),
            CaError::NoPem => lang.t(
                "CA 인증서 파일에서 PEM 인증서를 찾지 못했습니다.",
                "no PEM certificate was found in the CA certificate file.",
            ),
            CaError::Rejected => lang.t(
                "CA 인증서 파일의 인증서를 신뢰 목록에 넣지 못했습니다.",
                "the certificate in the CA certificate file could not be added to the trust list.",
            ),
            CaError::Config => lang.t(
                "TLS 설정을 만들지 못했습니다.",
                "could not build the TLS configuration.",
            ),
        }
    }
}

/// `--cacert` 의 PEM 인증서들. 인증서가 아닌 블록(개인키 등)은 읽지 않는다.
pub(crate) fn load_ca(path: &Path) -> Result<Vec<CertificateDer<'static>>, CaError> {
    let meta = std::fs::metadata(path).map_err(|_| CaError::Open)?;
    if !meta.is_file() {
        return Err(CaError::NotFile);
    }
    if meta.len() > MAX_CA_BYTES {
        return Err(CaError::TooLarge);
    }
    let mut raw = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| CaError::Open)?
        .take(MAX_CA_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|_| CaError::Open)?;
    if raw.len() as u64 > MAX_CA_BYTES {
        return Err(CaError::TooLarge);
    }
    let certs: Vec<_> = CertificateDer::pem_slice_iter(&raw)
        .collect::<Result<_, _>>()
        .map_err(|_| CaError::NoPem)?;
    if certs.is_empty() {
        return Err(CaError::NoPem);
    }
    Ok(certs)
}

/// TLS 1.2 · 1.3, 세션 재개 없음(연결마다 새로), ALPN 없음(HTTP/1.1 만).
pub(crate) fn client_config(
    extra: &[CertificateDer<'static>],
) -> Result<Arc<ClientConfig>, CaError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // OS 저장소에 읽지 못한 인증서가 섞여도 나머지는 쓴다 — 내장 목록이 바닥을 받친다.
    let native = rustls_native_certs::load_native_certs();
    roots.add_parsable_certificates(native.certs);
    for cert in extra {
        roots.add(cert.clone()).map_err(|_| CaError::Rejected)?;
    }
    client_config_with(roots)
}

pub(crate) fn client_config_with(roots: RootCertStore) -> Result<Arc<ClientConfig>, CaError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| CaError::Config)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}
