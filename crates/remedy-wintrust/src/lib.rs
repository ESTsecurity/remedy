//! remedy-wintrust — Windows 코드 서명 검증 (설계-03 §3 2층).
//!
//! # 저장소에서 `unsafe` 를 쓰는 두 크레이트 중 하나다 (다른 하나는 `remedy-winmods`)
//!
//! 다른 크레이트는 전부 `#![forbid(unsafe_code)]` 이고 Windows API 는 안전
//! 래퍼(`winreg` · `windows-permissions`)로만 닿는다. **여기만 예외인 이유를
//! 적어 둔다.**
//!
//! ## 순수 Rust 로는 정상 시스템 파일이 "서명 없음" 이 된다
//!
//! 2026-08-25 실측이다. `kernel32.dll` · `ntdll.dll` · `explorer.exe` ·
//! `notepad.exe` 는 전부 **`SignatureType: Catalog`** 다 — 파일 안에 인증서가
//! 없고, `.cat` 카탈로그가 해시 목록을 담고 그 카탈로그가 서명된다. 파일 내장
//! 서명(`Authenticode`)을 갖는 것은 `node.exe` 같은 서드파티 쪽이었다.
//!
//! PE 인증서 테이블만 읽는 순수 Rust 구현(`cross-authenticode` ·
//! `authenticode`)은 카탈로그를 볼 수 없다. 그러면 `System32` 의 정상 파일이
//! 전부 `trusted: false` 가 되고, **2층이 보호해야 할 바로 그 파일들을 보호하지
//! 못한다.** 그 실패 방향이 이 도구가 존재하는 이유(설계-03 §0 의 2022년 오진
//! 사고)와 정면으로 닿는다.
//!
//! ## 그리고 체인 검증을 직접 구현하지 않는다
//!
//! `cross-authenticode` 의 `verify()` 는 이름과 달리 **PE 해시가 서명 안의
//! 해시와 같은지만** 본다 — 서명 자체도, 체인이 신뢰 루트에 닿는지도 확인하지
//! 않는다. 완전한 검증을 순수 Rust 로 하려면 X.509 경로 검증(유효기간·기본
//! 제약·키 사용·EKU·경로 길이)을 우리가 짜야 하고, **그것을 잘못 짜면 정확히
//! 오진이 된다.** OS 는 그것을 이미 정확히 한다.
//!
//! ## 그래서 `unsafe` 를 이 크레이트 하나에 가둔다
//!
//! `remedy-platform` 전체의 `forbid` 를 푸는 대신 크레이트를 나눈 것은
//! `remedy-yara` 와 같은 판단이다 — *"한 크레이트에 가두면 대응도 교체도 한
//! 곳에서 끝난다"* (설계-04 §1). `remedy-winmods`(실린 모듈)를 뺀 나머지 크레이트는 `forbid` 를
//! 유지한다 — `xtask arch` 가 그 목록을 본다.
//!
//! # 폐기 확인은 하지 않는다
//!
//! `WTD_REVOKE_NONE` 으로 고정한다. 폐기 목록 확인은 네트워크이고 **설계-01 D8
//! 이 그것을 막는다.** 감염 호스트의 네트워크를 신뢰할 수 없으므로 못 하는 것을
//! 못 한다고 적는다 (설계-09 P10).

/// 검증 결과. **이 값이 있다는 것은 "확인했다" 는 뜻이다.**
///
/// 서명이 없는 파일도 여기 담긴다(`trusted: false`). 확인하지 *못한* 것은
/// `Err` 로 나가며, 그 둘을 섞으면 설계-03 §3 이 금지한 일이 일어난다 —
/// *"서명을 확인하지 못한 것을 '서명 없음' 으로 읽지 않는다"*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// 유효한 서명이 신뢰 루트까지 닿는가. **파싱 성공이 아니라 신뢰 판정이다.**
    pub trusted: bool,
    /// 서명 주체의 X.500 이름 전체. 예: `CN=OpenJS Foundation, O=OpenJS Foundation, L=…`
    ///
    /// **단순 표시 이름을 쓰지 않는 이유**: `kernel32.dll` 의 단순 이름은
    /// `Microsoft Windows`(CN)이고 `Microsoft Corporation` 은 O 다. 설계 초안이
    /// `subject == "Microsoft Corporation"` 이라고 적었던 것이 정확히 이 혼동이다
    /// (설계-03 §3 P9 후속). 전체 DN 을 주면 작성자가 무엇을 비교하는지 보인다.
    pub subject: Option<String>,
    /// 서명 인증서의 SHA-1 지문, **대문자 hex**. `certstore.rs` 가 쓰는 형식과
    /// 같게 맞춘다 — 두 곳이 다르면 대조가 조용히 어긋난다.
    pub thumbprint: Option<String>,
    /// 서명이 **파일 안에** 있었나. 보고에 뜻이 있다 — 서드파티 배포물인지 OS
    /// 구성요소인지가 갈린다.
    pub kind: SignatureKind,
}

/// 서명이 어디에 있었나.
///
/// **둘은 배타적이지 않다.** 2026-08-25 실측: `kernel32.dll` 은 파일 안에
/// 인증서 테이블(17,008바이트)이 있으면서 카탈로그에도 들어 있고,
/// `notepad.exe` 는 테이블이 없어(0바이트) 카탈로그만으로 신뢰를 얻는다.
/// PowerShell 의 `Get-AuthenticodeSignature` 가 둘 다 `SignatureType: Catalog`
/// 로 보고하는 것은 **카탈로그를 먼저 찾기 때문**이지 파일에 서명이 없어서가
/// 아니다.
///
/// 그래서 이 값이 답하는 것은 좁다 — *"파일 안에 인증서 테이블이 있는가"*.
/// 신뢰 판정 자체는 `trusted` 가 말하며, 그것은 OS 가 두 경로를 모두 본 결과다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureKind {
    /// 파일 안에 인증서 테이블이 있다.
    Embedded,
    /// 파일에는 없다. 신뢰로 판정됐다면 **카탈로그가 보증한 것**이다.
    CatalogOnly,
    /// 서명이 없다. **확인은 했다.**
    Unsigned,
}

#[derive(Debug)]
pub enum VerifyError {
    /// 경로를 Windows 와이드 문자열로 만들 수 없다.
    BadPath,
    /// `WinVerifyTrust` 가 우리가 다루기로 한 것 밖의 코드를 냈다. 값을 담아
    /// 둔다 — "확인하지 못했다" 를 보고할 때 사유가 있어야 한다.
    Unexpected(i32),
    /// Windows 가 아니다.
    Unsupported,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::BadPath => write!(f, "경로를 Windows 문자열로 옮기지 못했습니다"),
            VerifyError::Unexpected(c) => {
                write!(f, "WinVerifyTrust 가 예상 밖의 코드를 냈습니다: {c:#010x}")
            }
            VerifyError::Unsupported => write!(f, "이 플랫폼에는 Authenticode 가 없습니다"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// 파일의 코드 서명을 확인한다.
///
/// `Ok` 는 **확인했다**는 뜻이고, `Err` 는 확인하지 못했다는 뜻이다.
#[cfg(windows)]
pub fn verify(path: &std::path::Path) -> Result<Verdict, VerifyError> {
    windows::verify(path)
}

#[cfg(not(windows))]
pub fn verify(_path: &std::path::Path) -> Result<Verdict, VerifyError> {
    // Linux 에는 Authenticode 가 없다. 여기서 `trusted: false` 를 내면 그것이
    // "서명 없음" 으로 읽혀 2층이 무너진다 — 못 한다고 말한다 (P12 에서 그
    // 플랫폼의 개념으로 다시 세운다).
    Err(VerifyError::Unsupported)
}

#[cfg(windows)]
mod windows {
    //! `WinVerifyTrust` 호출부. **이 크레이트의 `unsafe` 는 이 모듈에만 있다.**
    //!
    //! # 두 경로를 다 본다
    //!
    //! `WTD_CHOICE_FILE` 은 **파일 안의 인증서만** 본다. `notepad.exe` 처럼
    //! 카탈로그로만 서명된 파일은 그 경로에서 `TRUST_E_NOSIGNATURE` 가 나온다
    //! (2026-08-25 실측). 그래서 내장 서명이 없으면 카탈로그를 찾아
    //! `WTD_CHOICE_CATALOG` 로 다시 묻는다 — `Get-AuthenticodeSignature` 가 하는
    //! 것과 같은 절차다.

    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::Cryptography::Catalog::{
        CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
        CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
        CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
    };
    use windows_sys::Win32::Security::Cryptography::{
        CertGetCertificateContextProperty, CertGetNameStringW, BCRYPT_SHA256_ALGORITHM,
        CERT_CONTEXT, CERT_SHA1_HASH_PROP_ID,
    };
    use windows_sys::Win32::Security::WinTrust::{
        WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
        WTHelperProvDataFromStateData, WinVerifyTrust, CRYPT_PROVIDER_DATA,
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
        WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
        WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    use super::{SignatureKind, Verdict, VerifyError};

    /// `CertGetNameStringW` 의 타입. RDN 전체를 문자열로 달라는 뜻이다.
    ///
    /// **`CERT_X500_NAME_STR` 를 여기 넣으면 안 된다.** 그것은 `CertNameToStr`
    /// 의 *형식* 값이고, 이 함수의 타입 열거와 번호가 겹친다 — 3 을 넣으면
    /// `CERT_NAME_ATTR_TYPE` 로 해석되어 CN 하나만 돌아온다. 처음에 그렇게
    /// 적었고 실측에서 `Microsoft Windows` 만 나와 드러났다.
    const CERT_NAME_RDN_TYPE: u32 = 2;

    /// 위 타입의 `pvTypePara` 로 넘길 형식. 전체 DN 문자열.
    const CERT_X500_NAME_STR: u32 = 3;
    /// CN 이 앞에 오게 한다 — `Get-AuthenticodeSignature` 가 보여 주는 순서이고,
    /// 사람이 눈으로 대조할 값이므로 그쪽에 맞춘다.
    const CERT_NAME_STR_REVERSE_FLAG: u32 = 0x0200_0000;

    // HRESULT 는 **16진 그대로 적고 캐스팅한다.** 십진으로 옮겨 적었다가 두 개를
    // 틀렸다 — `TRUST_E_SUBJECT_FORM_UNKNOWN` 을 0x800B0113 으로,
    // `TRUST_E_SUBJECT_NOT_TRUSTED` 를 잘못 계산한 값으로 적어, 서명 없는 파일이
    // "확인하지 못했다" 로 새어 나갔다. 손으로 하는 진법 변환을 코드에 남기지 않는다.

    /// 서명 없음.
    const TRUST_E_NOSIGNATURE: i32 = 0x800B_0100u32 as i32;
    /// 파일 형식이 서명을 담을 수 있는 것이 아니다 (예: 텍스트 파일).
    const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B_0003u32 as i32;
    /// 서명은 있으나 주체를 신뢰하지 않는다.
    const TRUST_E_SUBJECT_NOT_TRUSTED: i32 = 0x800B_0004u32 as i32;
    /// 인증서가 만료됐다.
    const CERT_E_EXPIRED: i32 = 0x800B_0101u32 as i32;
    /// 발급자 체인을 신뢰하지 않는다 — **자기서명이 여기로 온다.**
    const CERT_E_UNTRUSTEDROOT: i32 = 0x800B_0109u32 as i32;
    /// 체인을 세우지 못했다 (발급자를 찾을 수 없다).
    const CERT_E_CHAINING: i32 = 0x800B_010Au32 as i32;
    /// 테스트 루트로 서명됐다.
    const CERT_E_UNTRUSTEDTESTROOT: i32 = 0x800B_010Du32 as i32;
    /// 사용자가 명시적으로 불신 처리했다.
    const TRUST_E_EXPLICIT_DISTRUST: i32 = 0x800B_0111u32 as i32;
    /// 서명이 깨졌다 — 서명 이후 파일이 바뀌었다.
    const TRUST_E_BAD_DIGEST: i32 = 0x8009_6010u32 as i32;

    /// 서명자 정보. 신뢰하지 않는 서명에서도 뽑는다 — 보고에서 "자기서명
    /// CN=Evil" 이라고 말할 수 있어야 한다.
    type Signer = (Option<String>, Option<String>);

    fn wide(path: &Path) -> Result<Vec<u16>, VerifyError> {
        // Windows 는 UTF-16 을 받는다. 널 종료를 우리가 붙인다 — 붙이지 않으면
        // API 가 버퍼 끝을 넘어 읽는다.
        let mut v: Vec<u16> = path.as_os_str().encode_wide().collect();
        if v.contains(&0) {
            return Err(VerifyError::BadPath);
        }
        v.push(0);
        Ok(v)
    }

    /// 상태 초기화의 공통부. **`dwUnionChoice` 와 union 은 호출자가 채운다.**
    fn base_data() -> WINTRUST_DATA {
        // POD 구조체이고 Windows 가 "0 으로 채우고 필요한 필드만 설정하라" 고
        // 규정한다. 필드를 하나하나 적으면 windows-sys 버전이 올라 필드가 늘
        // 때마다 컴파일이 깨지고, 그때 무엇을 0 으로 둘지 다시 판단해야 한다.
        let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
        data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        data.dwUIChoice = WTD_UI_NONE;
        // **네트워크를 켜지 않는다** (설계-01 D8). 두 값이 함께 있어야 한다 —
        // REVOKE_NONE 만으로는 체인 구성 중 AIA 를 따라갈 수 있다.
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data
    }

    /// `WinVerifyTrust` 를 부르고, 상태를 닫기 **전에** 서명자를 뽑는다.
    ///
    /// # Safety
    ///
    /// `data` 의 union 이 `dwUnionChoice` 와 맞게 채워져 있어야 하고, 그 안이
    /// 가리키는 것들이 이 호출 동안 살아 있어야 한다.
    unsafe fn call(data: &mut WINTRUST_DATA) -> (i32, Option<Signer>) {
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let status = WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            (data as *mut WINTRUST_DATA).cast(),
        );

        // 상태 데이터가 살아 있는 동안 읽는다. **CLOSE 이후에는 읽을 수 없다.**
        let signer = signer_of(data.hWVTStateData);

        // 무엇을 반환하든 상태를 닫는다. 닫지 않으면 핸들이 샌다.
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            (data as *mut WINTRUST_DATA).cast(),
        );

        (status, signer)
    }

    pub fn verify(path: &Path) -> Result<Verdict, VerifyError> {
        let wpath = wide(path)?;

        // ── 1차: 파일 안의 서명 ──────────────────────────────────
        let mut file_info: WINTRUST_FILE_INFO = unsafe { std::mem::zeroed() };
        file_info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
        file_info.pcwszFilePath = wpath.as_ptr();

        let mut data = base_data();
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.Anonymous.pFile = &mut file_info;

        // SAFETY: `file_info` 와 `wpath` 가 이 함수 끝까지 살아 있고, union 이
        // `WTD_CHOICE_FILE` 과 맞게 채워졌다.
        let (mut status, mut signer) = unsafe { call(&mut data) };

        let embedded = has_embedded(path);

        // ── 2차: 카탈로그 ────────────────────────────────────────
        //
        // 파일에 서명이 없을 때만 간다. 있는데 실패했다면 그 실패가 답이다 —
        // 카탈로그로 덮어써 통과시키면 "변조된 서명" 이 "카탈로그로 통과" 가
        // 되어 버린다.
        if status == TRUST_E_NOSIGNATURE && !embedded {
            if let Some((cat_status, cat_signer)) = verify_via_catalog(path, &wpath) {
                status = cat_status;
                signer = cat_signer;
            }
        }

        let (subject, thumbprint) = signer.unwrap_or((None, None));
        let kind = if embedded {
            SignatureKind::Embedded
        } else if status == TRUST_E_NOSIGNATURE || status == TRUST_E_SUBJECT_FORM_UNKNOWN {
            SignatureKind::Unsigned
        } else {
            SignatureKind::CatalogOnly
        };

        match status {
            0 => Ok(Verdict {
                trusted: true,
                subject,
                thumbprint,
                kind,
            }),

            // 확인했고, 신뢰할 수 없다. **여기서 `Ok` 를 내는 것이 중요하다** —
            // 호출자는 "확인 실패" 와 "신뢰 안 함" 을 다르게 다뤄야 한다.
            TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN => Ok(Verdict {
                trusted: false,
                subject: None,
                thumbprint: None,
                kind: SignatureKind::Unsigned,
            }),
            TRUST_E_SUBJECT_NOT_TRUSTED
            | CERT_E_UNTRUSTEDROOT
            | CERT_E_UNTRUSTEDTESTROOT
            | TRUST_E_EXPLICIT_DISTRUST
            | CERT_E_CHAINING
            | CERT_E_EXPIRED
            | TRUST_E_BAD_DIGEST => Ok(Verdict {
                trusted: false,
                subject,
                thumbprint,
                kind,
            }),

            other => Err(VerifyError::Unexpected(other)),
        }
    }

    /// 이 파일의 해시를 담고 있는 카탈로그를 찾아 그것으로 검증한다.
    ///
    /// `None` 은 "카탈로그 경로를 쓸 수 없었다" 이며 **판정이 아니다** — 호출자는
    /// 1차 결과를 그대로 쓴다.
    fn verify_via_catalog(path: &Path, wpath: &[u16]) -> Option<(i32, Option<Signer>)> {
        let file = std::fs::File::open(path).ok()?;
        let handle = file.as_raw_handle() as HANDLE;

        let mut admin: isize = 0;
        // SAFETY: `admin` 은 우리 스택 변수이고, 나머지 인자는 널 허용이다.
        // SHA-256 은 Windows 8 이후 카탈로그의 해시다.
        if unsafe {
            CryptCATAdminAcquireContext2(
                &mut admin,
                std::ptr::null(),
                BCRYPT_SHA256_ALGORITHM,
                std::ptr::null(),
                0,
            )
        } == 0
        {
            return None;
        }

        // 해제를 한 곳에 모은다 — 아래 어느 갈래로 빠져도 지나간다.
        let result = catalog_lookup(admin, handle, wpath);

        // SAFETY: 위에서 얻은 컨텍스트이며 아직 해제하지 않았다.
        unsafe { CryptCATAdminReleaseContext(admin, 0) };
        result
    }

    fn catalog_lookup(
        admin: isize,
        handle: HANDLE,
        wpath: &[u16],
    ) -> Option<(i32, Option<Signer>)> {
        // 해시 길이를 먼저 묻는다.
        let mut len: u32 = 0;
        // SAFETY: `pbhash` 가 널이면 길이만 채운다는 것이 이 API 의 규약이다.
        unsafe {
            CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut len, std::ptr::null_mut(), 0)
        };
        if len == 0 {
            return None;
        }
        let mut hash = vec![0u8; len as usize];
        // SAFETY: `hash` 는 방금 `len` 바이트로 잡았다.
        if unsafe {
            CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut len, hash.as_mut_ptr(), 0)
        } == 0
        {
            return None;
        }

        // SAFETY: `hash` 는 살아 있고 `len` 바이트다.
        let cat = unsafe {
            CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), len, 0, std::ptr::null_mut())
        };
        if cat == 0 {
            // 어떤 카탈로그에도 없다 — 서명되지 않은 파일이다.
            return None;
        }

        let mut info: CATALOG_INFO = unsafe { std::mem::zeroed() };
        info.cbStruct = std::mem::size_of::<CATALOG_INFO>() as u32;
        // SAFETY: `cat` 은 방금 얻은 컨텍스트이고 `info` 는 우리 스택 변수다.
        let ok = unsafe { CryptCATCatalogInfoFromContext(cat, &mut info, 0) };

        let out = if ok != 0 {
            // 멤버 태그는 파일 해시의 대문자 hex 다. 카탈로그 안에서 이 이름으로
            // 항목을 찾는다.
            let tag: String = hash.iter().map(|b| format!("{b:02X}")).collect();
            let mut wtag: Vec<u16> = tag.encode_utf16().collect();
            wtag.push(0);

            let mut ci: WINTRUST_CATALOG_INFO = unsafe { std::mem::zeroed() };
            ci.cbStruct = std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32;
            ci.pcwszCatalogFilePath = info.wszCatalogFile.as_ptr();
            ci.pcwszMemberTag = wtag.as_ptr();
            ci.pcwszMemberFilePath = wpath.as_ptr();
            ci.hMemberFile = handle;
            ci.pbCalculatedFileHash = hash.as_mut_ptr();
            ci.cbCalculatedFileHash = len;
            ci.hCatAdmin = admin;

            let mut data = base_data();
            data.dwUnionChoice = WTD_CHOICE_CATALOG;
            data.Anonymous.pCatalog = &mut ci;

            // SAFETY: `ci` · `wtag` · `hash` · `info` · `wpath` 가 모두 이 블록이
            // 끝날 때까지 살아 있고, union 이 `WTD_CHOICE_CATALOG` 와 맞다.
            Some(unsafe { call(&mut data) })
        } else {
            None
        };

        // SAFETY: 위에서 얻은 카탈로그 컨텍스트이며 아직 해제하지 않았다.
        unsafe { CryptCATAdminReleaseCatalogContext(admin, cat, 0) };
        out
    }

    /// 파일 안에 인증서 테이블이 있는가.
    ///
    /// 구분은 보고에만 쓰이므로 **PE 헤더를 직접 보는 것으로 충분하다** — 여기서
    /// 틀려도 신뢰 판정은 바뀌지 않는다.
    fn has_embedded(path: &Path) -> bool {
        let Ok(bytes) = std::fs::read(path) else {
            return false;
        };
        embedded_cert_size(&bytes).is_some_and(|n| n > 0)
    }

    /// PE 의 `IMAGE_DIRECTORY_ENTRY_SECURITY`(인덱스 4) 크기.
    ///
    /// 경계를 하나하나 확인한다 — 남이 만든 파일이고, 넘겨 읽으면 패닉이다.
    fn embedded_cert_size(b: &[u8]) -> Option<u32> {
        let u16at = |o: usize| -> Option<u16> {
            Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
        };
        let u32at = |o: usize| -> Option<u32> {
            Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
        };

        if u16at(0)? != 0x5A4D {
            return None; // "MZ" 가 아니다
        }
        let pe = u32at(0x3C)? as usize;
        if u32at(pe)? != 0x0000_4550 {
            return None; // "PE\0\0" 가 아니다
        }
        let opt = pe + 24;
        // 데이터 디렉터리 시작 위치가 32비트/64비트에서 다르다.
        let dir = match u16at(opt)? {
            0x10B => opt + 96,
            0x20B => opt + 112,
            _ => return None,
        };
        // 인덱스 4 = SECURITY. 각 항목은 (RVA, Size) 8바이트이고 Size 가 뒤 4다.
        u32at(dir + 4 * 8 + 4)
    }

    /// 검증 상태에서 첫 서명자의 (subject DN, SHA-1 지문)을 꺼낸다.
    ///
    /// # Safety
    ///
    /// `state` 는 `WTD_STATEACTION_VERIFY` 호출이 채운 값이어야 하고, 아직
    /// `CLOSE` 되지 않았어야 한다.
    unsafe fn signer_of(state: HANDLE) -> Option<Signer> {
        if state.is_null() {
            return None;
        }
        let prov: *mut CRYPT_PROVIDER_DATA = WTHelperProvDataFromStateData(state);
        if prov.is_null() {
            return None;
        }
        // 서명자 0 = 첫 서명. 이중 서명(SHA-1 + SHA-256)이면 첫 것을 쓴다 —
        // 어느 쪽이든 같은 주체가 서명하는 것이 관례이고, 다르면 그 자체가
        // 이상하므로 첫 것으로 보고하고 사람이 보게 한다.
        let signer = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
        if signer.is_null() {
            return None;
        }
        let cert = WTHelperGetProvCertFromChain(signer, 0);
        if cert.is_null() {
            return None;
        }
        let ctx = (*cert).pCert;
        if ctx.is_null() {
            return None;
        }
        Some((subject_of(ctx), thumbprint_of(ctx)))
    }

    /// # Safety
    /// `ctx` 는 살아 있는 `CERT_CONTEXT` 여야 한다.
    unsafe fn subject_of(ctx: *const CERT_CONTEXT) -> Option<String> {
        let format: u32 = CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG;
        let para = (&format as *const u32).cast::<std::ffi::c_void>();

        // 길이를 먼저 묻는다(널 종료 포함). 0 또는 1 이면 이름이 없다.
        // 세 번째 인자 0 = 발급자가 아니라 주체다.
        let need = CertGetNameStringW(ctx, CERT_NAME_RDN_TYPE, 0, para, std::ptr::null_mut(), 0);
        if need <= 1 {
            return None;
        }
        let mut buf = vec![0u16; need as usize];
        let got = CertGetNameStringW(ctx, CERT_NAME_RDN_TYPE, 0, para, buf.as_mut_ptr(), need);
        if got <= 1 {
            return None;
        }
        // 널 종료를 뺀다.
        let s = String::from_utf16_lossy(&buf[..(got as usize - 1)]);
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    /// # Safety
    /// `ctx` 는 살아 있는 `CERT_CONTEXT` 여야 한다.
    unsafe fn thumbprint_of(ctx: *const CERT_CONTEXT) -> Option<String> {
        let mut len: u32 = 0;
        if CertGetCertificateContextProperty(
            ctx,
            CERT_SHA1_HASH_PROP_ID,
            std::ptr::null_mut(),
            &mut len,
        ) == 0
            || len == 0
        {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        if CertGetCertificateContextProperty(
            ctx,
            CERT_SHA1_HASH_PROP_ID,
            buf.as_mut_ptr().cast(),
            &mut len,
        ) == 0
        {
            return None;
        }
        buf.truncate(len as usize);
        // 대문자 hex — `certstore.rs` 가 레지스트리 키 이름에서 얻는 형식과 같다.
        Some(buf.iter().map(|b| format!("{b:02X}")).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 확인하지_못한_것과_서명_없음은_다른_타입이다() {
        // 이 시험은 타입 수준의 약속을 못 박는다. `Err` 는 "모른다" 이고
        // `Ok(trusted:false)` 는 "확인했고 아니다" 다 — 둘이 같은 값이 되면
        // 설계-03 §3 의 규칙이 코드에서 사라진다.
        let unknown: Result<Verdict, VerifyError> = Err(VerifyError::Unsupported);
        let unsigned = Ok::<_, VerifyError>(Verdict {
            trusted: false,
            subject: None,
            thumbprint: None,
            kind: SignatureKind::Unsigned,
        });
        assert!(unknown.is_err());
        assert!(unsigned.is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn 없는_파일은_확인하지_못했다로_끝난다() {
        let r = verify(std::path::Path::new("C:\\없는파일-remedy-test.exe"));
        // 없는 파일을 "서명 없음" 으로 읽으면 안 된다.
        assert!(r.is_err(), "없는 파일에 판정을 냈다: {r:?}");
    }
}
