//! 판정 기준 — 데이터 룰 `remedy-net-criteria` 를 찾아 서명을 확인하고 읽는다 (코어 1.12.0).
//!
//! **기준은 이 바이너리에 들어 있지 않다.** 받은 꾸러미의 `plugins/remedy-net-criteria/` 가 url 표
//! (`url.json`)와 이미지 · 컨테이너 기준(`baseline.json`)을 담고, 이 프로그램은 점검을 시작할 때 그 폴더를
//! 본체가 룰 폴더를 확인하는 것과 같은 사슬(`remedy-trust`)로 확인한다 — 배포 키의 서명, 파일이 서명한
//! 그대로인가(더해진 것도 빠진 것도 없다), 서명 주석의 이름. 그래서 기준이 바뀌면 그 폴더의 파일과 버전만
//! 고치고 이 프로그램은 다시 짓지 않는다.
//!
//! 찾지 못하거나 확인하지 못하면 **점검하지 않는다** — 종료 4(받은 파일이 온전하지 않다 · 본체가 받는 종료
//! 코드 표 안). 바꿔치기한 기준이면 취약한 것을 양호로 낼 수 있으므로, 확인 없이 읽는 길을 두지 않는다.
//!
//! # 어디서 찾나
//!
//! `REMEDY_NET_CRITERIA` 가 폴더를 가리키면 그것, 아니면 이 실행 파일의 폴더(`remedy-net/`) 옆의
//! `plugins/remedy-net-criteria/` — 받은 꾸러미의 배치다. 어느 쪽이든 같은 확인을 지난다.
//!
//! # 어느 키로 확인하나
//!
//! 배포 빌드에 박힌 공개키(`REMEDY_TRUST_ANCHOR` — 배포 잡이 본체와 같은 환경에서 이 프로그램을 짓는다).
//! 개발 빌드는 `REMEDY_NET_ANCHOR` 로도 받는다 — 본체가 개발 빌드에서 동반 프로그램을 확인할 때 쓰는 그
//! 이름이다. 배포 빌드는 그 환경 변수를 읽지 않는다.

use remedy_sdk::i18n::Lang;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// 데이터 룰의 id — 폴더 이름이자 서명 주석의 이름.
pub const ID: &str = "remedy-net-criteria";
/// url 표.
pub const URL_FILE: &str = "url.json";
/// 이미지 · 컨테이너 기준.
pub const BASELINE_FILE: &str = "baseline.json";
/// 기준 폴더를 따로 가리키는 환경 변수.
pub const DIR_ENV: &str = "REMEDY_NET_CRITERIA";

/// 배포 빌드에 박힌 공개키(base64 한 줄). 개발 빌드는 비어 있다.
const EMBEDDED_ANCHOR: Option<&str> = option_env!("REMEDY_TRUST_ANCHOR");

/// 기준을 쓰지 못하는 까닭.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// 폴더가 없다 — 받은 파일을 덜 풀었거나 그 폴더를 지웠다.
    Absent(PathBuf),
    /// 이 빌드에는 서명을 확인할 공개키가 없다(배포본이 아니다).
    NoAnchor,
    /// 서명 매니페스트나 서명 파일이 없다.
    NotSigned(PathBuf),
    /// 서명이 맞지 않거나, 폴더의 파일이 서명한 것과 다르다(확인한 뒤 바뀐 것 포함).
    Tampered(PathBuf),
    /// 서명은 맞지만 이 기준 폴더에 한 서명이 아니다(서명 주석의 이름이 다르다).
    NotCriteria(PathBuf, String),
    /// 확인한 파일을 이 프로그램이 읽지 못한다 — 모르는 형식 · 견줄 수 없는 꼴. (파일, 까닭)
    Unreadable(String, String),
}

impl Refusal {
    /// 사용자에게 보이는 글(합쇼체). 끝에 할 일을 적는다.
    pub fn message(&self, lang: Lang) -> String {
        match self {
            Refusal::Absent(dir) => lang.pick(
                format!(
                    "판정 기준 폴더를 찾지 못해 점검하지 않았습니다: {}\n  \
                     받은 파일을 통째로 다시 풀어 실행하십시오 (기준은 plugins/{ID} 에 있습니다).",
                    dir.display()
                ),
                format!(
                    "The criteria folder was not found, so nothing was checked: {}\n  \
                     Extract the whole download again and run it (the criteria are in plugins/{ID}).",
                    dir.display()
                ),
            ),
            Refusal::NoAnchor => lang
                .t(
                    "이 프로그램은 판정 기준의 서명을 확인할 수 없어 점검하지 않았습니다 (배포본이 아닙니다).",
                    "This build cannot verify the signature of the criteria, so nothing was checked (not an official release).",
                )
                .to_string(),
            Refusal::NotSigned(dir) => lang.pick(
                format!(
                    "판정 기준 폴더에 서명이 없어 점검하지 않았습니다: {} — 배포처에서 받은 것이 맞는지 확인하십시오.",
                    dir.display()
                ),
                format!(
                    "The criteria folder is not signed, so nothing was checked: {} — check that it came from the vendor.",
                    dir.display()
                ),
            ),
            Refusal::Tampered(dir) => lang.pick(
                format!(
                    "판정 기준 폴더의 내용이 서명한 것과 달라 점검하지 않았습니다: {} — 배포처에서 다시 받으십시오.",
                    dir.display()
                ),
                format!(
                    "The criteria folder differs from what was signed, so nothing was checked: {} — download it again from the vendor.",
                    dir.display()
                ),
            ),
            Refusal::NotCriteria(dir, id) => lang.pick(
                format!(
                    "판정 기준 폴더의 서명이 기준의 것이 아니어서({id}) 점검하지 않았습니다: {} — 배포처에서 다시 받으십시오.",
                    dir.display()
                ),
                format!(
                    "The signature in the criteria folder is not the criteria's ({id}), so nothing was checked: {} — download it again from the vendor.",
                    dir.display()
                ),
            ),
            Refusal::Unreadable(file, why) => lang.pick(
                format!(
                    "판정 기준 파일({file})을 이 프로그램이 읽지 못해 점검하지 않았습니다 — 같은 릴리스의 파일을 함께 쓰십시오.\n  ({why})"
                ),
                format!(
                    "This program cannot read the criteria file ({file}), so nothing was checked — use files from the same release together.\n  ({why})"
                ),
            ),
        }
    }
}

/// 서명을 확인한 기준 폴더.
pub struct Verified {
    dir: PathBuf,
    version: String,
    /// 서명한 파일 → SHA-256.
    tree: BTreeMap<String, String>,
}

impl Verified {
    /// 데이터 룰의 버전(서명 주석의 것).
    pub fn version(&self) -> &str {
        &self.version
    }

    /// 확인한 폴더.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// 서명한 파일 하나의 글. 확인한 뒤 바뀌지 않았는지 **다시 해시해** 본다.
    pub fn read(&self, name: &str) -> Result<String, Refusal> {
        let Some(want) = self.tree.get(name) else {
            return Err(Refusal::Unreadable(
                name.to_string(),
                "서명한 파일 목록에 없다 / not in the signed file list".to_string(),
            ));
        };
        let bytes = std::fs::read(self.dir.join(name)).map_err(|_| self.tampered())?;
        if remedy_trust::sha256_hex(&bytes) != *want {
            return Err(self.tampered());
        }
        String::from_utf8(bytes).map_err(|_| {
            Refusal::Unreadable(
                name.to_string(),
                "UTF-8 글이 아니다 / not UTF-8 text".to_string(),
            )
        })
    }

    fn tampered(&self) -> Refusal {
        Refusal::Tampered(self.dir.clone())
    }
}

/// 기준 폴더를 찾아 확인한다.
pub fn open() -> Result<Verified, Refusal> {
    let anchor = EMBEDDED_ANCHOR.map(str::to_string).or_else(dev_anchor);
    verify(&locate(), anchor.as_deref())
}

/// `REMEDY_NET_CRITERIA` 가 있으면 그것, 없으면 이 실행 파일의 폴더 옆 `plugins/remedy-net-criteria`.
fn locate() -> PathBuf {
    if let Some(dir) = std::env::var_os(DIR_ENV).filter(|v| !v.is_empty()) {
        return PathBuf::from(dir);
    }
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().and_then(Path::parent).map(Path::to_path_buf))
        .unwrap_or_default()
        .join("plugins")
        .join(ID)
}

#[cfg(debug_assertions)]
fn dev_anchor() -> Option<String> {
    std::env::var("REMEDY_NET_ANCHOR")
        .ok()
        .filter(|v| !v.trim().is_empty())
}

#[cfg(not(debug_assertions))]
fn dev_anchor() -> Option<String> {
    None
}

/// 본체가 룰 폴더를 확인하는 것과 같은 사슬 — 서명 · 파일 목록 · 서명 주석의 이름.
pub fn verify(dir: &Path, anchor_b64: Option<&str>) -> Result<Verified, Refusal> {
    let dir = dir.to_path_buf();
    if !dir.is_dir() {
        return Err(Refusal::Absent(dir));
    }
    let Some(b64) = anchor_b64 else {
        return Err(Refusal::NoAnchor);
    };
    let tampered = |_| Refusal::Tampered(dir.clone());
    let anchor = remedy_trust::Anchor::from_base64(b64).map_err(|_| Refusal::NoAnchor)?;
    let manifest = std::fs::read(dir.join(remedy_trust::MANIFEST_NAME))
        .map_err(|_| Refusal::NotSigned(dir.clone()))?;
    let signature = std::fs::read_to_string(dir.join(remedy_trust::SIGNATURE_NAME))
        .map_err(|_| Refusal::NotSigned(dir.clone()))?;
    let verified =
        remedy_trust::verify_manifest(&anchor, &manifest, &signature).map_err(tampered)?;
    let tree = remedy_trust::collect(&dir).map_err(|_| Refusal::Tampered(dir.clone()))?;
    verified
        .check_tree(&tree)
        .map_err(|_| Refusal::Tampered(dir.clone()))?;
    let signed = verified.comment();
    if signed.id != ID {
        return Err(Refusal::NotCriteria(dir, signed.id.clone()));
    }
    Ok(Verified {
        version: signed.version.clone(),
        dir,
        tree,
    })
}

/// 기준 파일 둘을 이 프로그램이 읽을 수 있는가 — 실행 때 읽는 것과 같은 코드다. 저장소 검사
/// (`cargo xtask net-criteria`)가 서명하기 전에 본다.
pub fn check_texts(url: &str, baseline: &str) -> Result<(), String> {
    crate::url::check_table(url).map_err(|e| format!("{URL_FILE}: {e}"))?;
    crate::scan::rules::RuleSet::from_json(baseline)
        .map(|_| ())
        .map_err(|e| format!("{BASELINE_FILE}: {e}"))
}

/// 실행마다 한 번 읽는다 — 점검은 따로 도는 스레드에서도 쓰므로 그 실행이 끝날 때까지 둔다.
pub(crate) fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

#[cfg(test)]
pub(crate) mod testkit {
    //! 시험이 쓰는 기준 폴더 — 고정 사본(`testdata/`)을 일회용 키로 서명한다.
    use minisign::KeyPair;
    use std::path::Path;

    pub(crate) const URL: &str = include_str!("../testdata/url.json");
    pub(crate) const BASELINE: &str = include_str!("../testdata/baseline.json");

    /// 폴더를 통째로 서명한다 — 룰을 서명하는 것과 같은 형식(`cargo xtask sign`).
    pub(crate) fn sign(dir: &Path, kp: &KeyPair, id: &str, version: &str) {
        let tree = remedy_trust::collect(dir).expect("트리");
        let manifest = remedy_trust::Manifest::render(&tree);
        let comment = remedy_trust::TrustedComment::render(id, version, "2026-11-13T00:00:00Z");
        let sig = minisign::sign(
            Some(&kp.pk),
            &kp.sk,
            manifest.as_bytes(),
            Some(&comment),
            Some("remedy plugin signature"),
        )
        .expect("서명");
        std::fs::write(dir.join(remedy_trust::MANIFEST_NAME), manifest).expect("매니페스트");
        std::fs::write(dir.join(remedy_trust::SIGNATURE_NAME), sig.to_string()).expect("서명 파일");
    }

    /// 공개키의 base64 한 줄 — 배포 빌드에 박는 값과 같은 꼴.
    pub(crate) fn anchor(kp: &KeyPair) -> String {
        let boxed = kp.pk.to_box().expect("공개키 상자").to_string();
        boxed.lines().nth(1).expect("공개키 줄").trim().to_string()
    }

    /// 고정 사본 둘을 담아 서명한 기준 폴더.
    pub(crate) fn folder(dir: &Path, kp: &KeyPair) {
        std::fs::create_dir_all(dir).expect("폴더");
        std::fs::write(dir.join(super::URL_FILE), URL).expect("url.json");
        std::fs::write(dir.join(super::BASELINE_FILE), BASELINE).expect("baseline.json");
        sign(dir, kp, super::ID, "1.0.0");
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::{anchor, folder, sign};
    use super::*;
    use minisign::KeyPair;

    fn keypair() -> KeyPair {
        KeyPair::generate_unencrypted_keypair().expect("키쌍")
    }

    fn temp(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("remedy-net-criteria-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn a_signed_folder_is_read_and_its_files_come_back_as_signed() {
        let kp = keypair();
        let d = temp("ok");
        folder(&d, &kp);
        let v = verify(&d, Some(&anchor(&kp))).expect("확인");
        assert_eq!(v.version(), "1.0.0");
        assert_eq!(v.read(URL_FILE).expect("url"), testkit::URL);
        assert_eq!(v.read(BASELINE_FILE).expect("baseline"), testkit::BASELINE);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn nothing_is_trusted_without_the_folder_a_key_or_a_signature() {
        let kp = keypair();
        let d = temp("refuse");
        assert_eq!(
            verify(&d, Some(&anchor(&kp))).err(),
            Some(Refusal::Absent(d.clone()))
        );
        std::fs::create_dir_all(&d).expect("폴더");
        std::fs::write(d.join(URL_FILE), testkit::URL).expect("url");
        assert_eq!(verify(&d, None).err(), Some(Refusal::NoAnchor));
        assert_eq!(
            verify(&d, Some(&anchor(&kp))).err(),
            Some(Refusal::NotSigned(d.clone()))
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn another_key_a_changed_file_or_another_rule_is_refused() {
        let kp = keypair();
        let d = temp("tamper");
        folder(&d, &kp);
        // 다른 키
        let other = keypair();
        assert_eq!(
            verify(&d, Some(&anchor(&other))).err(),
            Some(Refusal::Tampered(d.clone()))
        );
        // 바뀐 파일
        std::fs::write(d.join(URL_FILE), "{}").expect("바꿈");
        assert_eq!(
            verify(&d, Some(&anchor(&kp))).err(),
            Some(Refusal::Tampered(d.clone()))
        );
        // 더해진 파일
        folder(&d, &kp);
        std::fs::write(d.join("extra.json"), "{}").expect("더함");
        assert_eq!(
            verify(&d, Some(&anchor(&kp))).err(),
            Some(Refusal::Tampered(d.clone()))
        );
        // 다른 룰의 서명
        let _ = std::fs::remove_file(d.join("extra.json"));
        sign(&d, &kp, "php2shell-url-check", "0.1.1");
        assert_eq!(
            verify(&d, Some(&anchor(&kp))).err(),
            Some(Refusal::NotCriteria(
                d.clone(),
                "php2shell-url-check".to_string()
            ))
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_file_changed_after_the_check_is_not_read() {
        let kp = keypair();
        let d = temp("toctou");
        folder(&d, &kp);
        let v = verify(&d, Some(&anchor(&kp))).expect("확인");
        std::fs::write(d.join(BASELINE_FILE), "{}").expect("바꿈");
        assert_eq!(
            v.read(BASELINE_FILE).err(),
            Some(Refusal::Tampered(d.clone()))
        );
        assert!(matches!(v.read("nope.json"), Err(Refusal::Unreadable(..))));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn every_refusal_speaks_both_languages_and_says_what_to_do() {
        let d = PathBuf::from("x");
        for r in [
            Refusal::Absent(d.clone()),
            Refusal::NoAnchor,
            Refusal::NotSigned(d.clone()),
            Refusal::Tampered(d.clone()),
            Refusal::NotCriteria(d.clone(), "other".to_string()),
            Refusal::Unreadable("url.json".to_string(), "why".to_string()),
        ] {
            let ko = r.message(Lang::Ko);
            let en = r.message(Lang::En);
            assert!(ko.contains("점검하지 않았습니다"), "{ko}");
            assert!(en.contains("nothing was checked"), "{en}");
        }
    }
}
