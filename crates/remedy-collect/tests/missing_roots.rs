//! 수집기가 **없는 루트를 없다고 말하는가** (관측 01 D2, 설계-02 §8).
//!
//! # 왜 가짜 백엔드를 만들어서까지 재는가
//!
//! D2 는 여기서 살았다. `collect_files` 가 존재하지 않는 루트를 조용히
//! `continue` 했고, 그래서 `scan_roots` 가 통째로 어긋난 실행이
//! **파일 0건 · `truncated=false` · `denied_dirs=0`** 으로 "완전한 관측"이 됐다.
//! 그 위에서 종료 코드 0 "위협 없음" 이 나왔다.
//!
//! 이 사실을 `Observation` 쪽 단위 테스트로는 잡을 수 없다. 그쪽은 `Observations`
//! 를 손으로 만들어 넣으므로 **수집기가 실제로 무엇을 채우는지는 건드리지
//! 않는다.** 실제로 가드 역검증에서 수집기 코드를 원래대로 되돌렸더니
//! 단위 테스트가 전부 통과했다 — 그 순간 이 파일이 필요하다는 것이 확정됐다.

use remedy_artifacts::{Scope, SecurityProductCollector};
use remedy_collect::{collect_all, Collector};
use remedy_platform::read::{
    EnvRead, FsEntry, FsRead, ProcessRead, RawProcess, RegValue, RegistryRead, Seen, WalkResult,
};
use remedy_platform::PlatformError;
use remedy_sdk::catalog::{Platform, Subject};

/// 지정한 경로만 존재하는 파일 시스템.
struct FakeFs {
    /// 존재하는 디렉터리와 그 아래 항목.
    present: Vec<(String, Vec<FsEntry>)>,
    /// 존재하는 레지스트리 키. 파일 시스템과 **다른 물음**이다.
    keys: Vec<String>,
    /// **있는지조차 물을 수 없는** 자리 (B-9). 부모까지 막힌 트리가 그렇다.
    locked: Vec<String>,
    /// 물었는데 답이 오지 않은 자리 — 도달 불가 UNC · 준비 안 된 장치.
    unknown: Vec<String>,
    /// 부모가 주는 하위 키 이름. **잠긴 키와 없는 키를 가르는 재료**다 (B-9).
    subkeys: Vec<(String, Vec<String>)>,
}

impl FakeFs {
    fn new(present: Vec<(&str, Vec<&str>)>) -> Self {
        Self {
            present: present
                .into_iter()
                .map(|(root, files)| {
                    let entries = files
                        .into_iter()
                        .map(|p| FsEntry {
                            path: p.to_string(),
                            is_dir: false,
                            is_reparse: false,
                            size: 1,
                            mtime: "2026-08-21T00:00:00Z".into(),
                            ctime: None,
                            mode: None,
                        })
                        .collect();
                    (root.to_string(), entries)
                })
                .collect(),
            keys: Vec::new(),
            locked: Vec::new(),
            unknown: Vec::new(),
            subkeys: Vec::new(),
        }
    }

    fn with_keys(mut self, keys: &[&str]) -> Self {
        self.keys = keys.iter().map(|k| k.to_string()).collect();
        self
    }

    /// **있는데 물을 수 없는** 자리를 더한다 (B-9).
    fn with_locked(mut self, paths: &[&str]) -> Self {
        self.locked = paths.iter().map(|p| p.to_string()).collect();
        self
    }

    /// 물었는데 답이 오지 않는 자리를 더한다 (B-9).
    fn with_unknown(mut self, paths: &[&str]) -> Self {
        self.unknown = paths.iter().map(|p| p.to_string()).collect();
        self
    }

    /// 부모가 주는 하위 키 이름을 더한다 (B-9).
    fn with_subkeys(mut self, parent: &str, names: &[&str]) -> Self {
        self.subkeys.push((
            parent.to_string(),
            names.iter().map(|n| n.to_string()).collect(),
        ));
        self
    }
}

impl FsRead for FakeFs {
    fn walk(&self, root: &str, _limit: usize) -> Result<WalkResult, PlatformError> {
        Ok(WalkResult {
            entries: self
                .present
                .iter()
                .find(|(r, _)| r == root)
                .map(|(_, e)| e.clone())
                .unwrap_or_default(),
            truncated: false,
            denied: 0,
            denied_paths: Vec::new(),
        })
    }

    fn read_file(&self, _path: &str, _max: u64) -> Result<Option<Vec<u8>>, PlatformError> {
        Ok(None)
    }

    fn look(&self, path: &str) -> Seen {
        if self.locked.iter().any(|p| p == path) {
            return Seen::Locked;
        }
        if self.unknown.iter().any(|p| p == path) {
            return Seen::CannotTell;
        }
        if self.present.iter().any(|(r, _)| r == path) {
            Seen::Present
        } else {
            Seen::Absent
        }
    }
}

impl EnvRead for FakeFs {
    fn expand(&self, s: &str) -> String {
        s.to_string()
    }
}

impl ProcessRead for FakeFs {
    fn processes(&self) -> Result<Vec<RawProcess>, PlatformError> {
        Ok(Vec::new())
    }
}

impl RegistryRead for FakeFs {
    fn value(&self, _key: &str, _name: &str) -> Result<Option<RegValue>, PlatformError> {
        Ok(None)
    }
    fn subkeys(&self, key: &str) -> Result<Vec<String>, PlatformError> {
        // **부모가 이름을 주는지**가 잠긴 키와 없는 키를 가른다 (B-9).
        Ok(self
            .subkeys
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, names)| names.clone())
            .unwrap_or_default())
    }
    fn values(&self, _key: &str) -> Result<Vec<(String, RegValue)>, PlatformError> {
        Ok(Vec::new())
    }
    fn key_exists(&self, key: &str) -> bool {
        self.keys.iter().any(|k| k.eq_ignore_ascii_case(key))
    }
}

fn scope(roots: &[&str]) -> Scope {
    let mut s = Scope::diagnostic(
        roots.iter().map(|r| r.to_string()).collect(),
        Platform::Windows,
    );
    // 예약 작업 수집기는 고정 시스템 경로를 보므로 이 시험의 변수가 아니다.
    s.subjects = vec![Subject::File];
    s
}

#[test]
fn a_root_that_does_not_exist_is_recorded() {
    let fs = FakeFs::new(vec![("c:\\있음", vec!["c:\\있음\\a.exe"])]);
    let c = Collector::new(fs);
    let obs = collect_all(&c, &scope(&["c:\\있음", "c:\\없음"])).expect("수집");

    assert_eq!(obs.missing_roots, vec!["c:\\없음".to_string()]);
    assert_eq!(obs.files().len(), 1, "있는 루트는 정상 수집되어야 한다");
    // 거부와 섞지 않는다 — 없는 것과 못 본 것은 다른 사실이다.
    assert_eq!(obs.denied_dirs, 0);
    // **못 물은 자리와도 섞지 않는다** (B-9). 정말 없는 루트는 그쪽이 아니다.
    assert!(
        obs.unreadable_roots.is_empty(),
        "{:?}",
        obs.unreadable_roots
    );
}

/// **못 물은 루트가 "없는 루트" 로 집계되던 자리** (B-9 · 2026-10-27).
///
/// # 무엇이 조용히 깨졌는가
///
/// `Path::exists()` 는 `metadata()` 의 오류 전부를 `false` 로 접는다. 그래서
/// 부모까지 막힌 트리와 도달 불가 UNC 가 `missing_roots` 로 들어갔다. 열린
/// 루트가 하나라도 함께 있으면 `all_roots_missing()` 이 성립하지 않으므로
/// **경고 한 줄 없이 종료 0 "위협이 발견되지 않았습니다"** 가 나갔다 —
/// 기계에 들여다보지도 못한 폴더가 있는데 도구가 없다고 말한 것이다.
///
/// 실기기로 재현했다(2026-10-27): `icacls` 로 부모를 막은 트리 하나와 열린
/// 폴더 하나를 선언했더니 `missing_roots` 에 막힌 쪽이 들어가고 `denied_dirs`
/// 는 0, 종료 코드는 0 이었다.
#[test]
fn a_root_we_could_not_even_ask_about_is_not_called_missing() {
    for mark in ["locked", "unknown"] {
        let fs = FakeFs::new(vec![("c:\\있음", vec!["c:\\있음\\a.exe"])]);
        let fs = if mark == "locked" {
            fs.with_locked(&["c:\\잠김"])
        } else {
            fs.with_unknown(&["c:\\잠김"])
        };
        let c = Collector::new(fs);
        let obs = collect_all(&c, &scope(&["c:\\있음", "c:\\잠김"])).expect("수집");

        assert!(
            obs.missing_roots.is_empty(),
            "{mark}: 못 물은 루트를 '없는 루트' 로 적었다 — {:?}",
            obs.missing_roots
        );
        assert_eq!(
            obs.unreadable_roots,
            vec!["c:\\잠김".to_string()],
            "{mark}: 못 물은 자리가 어디에도 남지 않았다"
        );
        // 열린 루트는 정상 수집되어야 한다 — 이것이 전제다. 이 줄이 없으면
        // 아래 단정이 "아무것도 수집하지 못했다" 로도 참이 된다.
        assert_eq!(obs.files().len(), 1, "{mark}");

        // **그래서 종료 0 이 나갈 수 없다.** 전부 없는 것이 아니므로
        // `all_roots_missing()` 은 거짓이고, 거부도 0 이다 — 새 칸만이 이것을
        // 붙잡는다.
        let o = remedy_sdk::artifact::Observation {
            declared_roots: 2,
            missing_roots: obs.missing_roots.clone(),
            unreadable_roots: obs.unreadable_roots.clone(),
            denied_dirs: obs.denied_dirs,
            ..Default::default()
        };
        assert!(!o.all_roots_missing(), "{mark}: 전제가 무너졌다");
        assert_eq!(o.denied_dirs, 0, "{mark}: 전제가 무너졌다");
        assert!(!o.is_complete(), "{mark}: 못 봤는데 완전하다고 한다");
        assert!(
            !o.is_complete_for_check(),
            "{mark}: 점검도 면제가 아니다 — 범위가 없는 것과 못 본 것은 다르다"
        );
        assert!(
            o.reasons().iter().any(|r| r.contains("c:\\잠김")),
            "{mark}: 사유 줄이 자리를 적지 않았다 — {:?}",
            o.reasons()
        );
    }
}

/// **잠긴 레지스트리 키도 같다** (B-9).
///
/// `key_exists` 도 참·거짓뿐이라 잠긴 키가 "없는 루트" 로 집계됐다. 레지스트리
/// 수집기들은 `deny_if_unreadable` 로 따로 세고 있었지만 `missing_roots` 는
/// 그대로였다 — 고객 화면이 *"전부 존재하지 않아"* 라고 **틀린 말**을 한다.
#[test]
fn a_locked_registry_root_is_not_called_missing() {
    // 부모는 이름을 주는데 키가 열리지 않는다 = 잠겼다.
    let fs = FakeFs::new(vec![("c:\\있음", vec![])])
        .with_keys(&["HKLM\\SOFTWARE\\Vendor"])
        .with_subkeys("HKLM\\SOFTWARE\\Vendor", &["Thing"]);
    let c = Collector::new(fs);
    let obs =
        collect_all(&c, &scope(&["c:\\있음", "HKLM\\SOFTWARE\\Vendor\\Thing"])).expect("수집");

    assert!(
        obs.missing_roots.is_empty(),
        "잠긴 키를 '없는 루트' 로 적었다 — {:?}",
        obs.missing_roots
    );
    assert_eq!(
        obs.unreadable_roots,
        vec!["HKLM\\SOFTWARE\\Vendor\\Thing".to_string()]
    );
}

#[test]
fn every_root_missing_yields_an_incomplete_observation() {
    // **D2 그 자체.** 아무 곳도 열지 못한 수집이 "위협 없음" 을 말하면 안 된다.
    let fs = FakeFs::new(vec![]);
    let c = Collector::new(fs);
    let s = scope(&["c:\\없음1", "c:\\없음2"]);
    let obs = collect_all(&c, &s).expect("수집");

    assert_eq!(obs.missing_roots.len(), 2);
    assert!(obs.files().is_empty());

    let env = remedy_artifacts::assemble(
        "r".into(),
        "t".into(),
        remedy_sdk::artifact::HostInfo {
            hostname: "T".into(),
            os: "windows".into(),
            version: "10".into(),
            arch: "amd64".into(),
        },
        remedy_sdk::artifact::CoreInfo {
            version: "0".into(),
            build: "dev".into(),
        },
        &s,
        obs,
    );
    let o = env.body.observation();
    assert!(
        !o.is_complete(),
        "루트가 전부 없었는데 완전한 관측이라고 한다"
    );
    // 두 언어를 다 잰다 — 라이브러리 시험은 영어로 돌므로 `reasons()` 만 보면
    // 한국어 쪽이 재어지지 않는다. 그 한국어 문구는 콘솔 기준선과 하네스가 읽는다.
    use remedy_sdk::i18n::Lang;
    assert!(o
        .reasons_in(Lang::Ko)
        .iter()
        .any(|r| r.contains("전부 존재하지 않아")));
    assert!(o.reasons_in(Lang::En).iter().any(|r| r.contains("missing")));
}

#[test]
fn all_roots_present_is_complete() {
    // 반대 방향. 정상 수집이 불완전으로 찍히면 6번은 곧 무시된다.
    let fs = FakeFs::new(vec![
        ("c:\\a", vec!["c:\\a\\x.exe"]),
        ("c:\\b", vec!["c:\\b\\y.exe"]),
    ]);
    let c = Collector::new(fs);
    let s = scope(&["c:\\a", "c:\\b"]);
    let obs = collect_all(&c, &s).expect("수집");

    assert!(obs.missing_roots.is_empty());
    assert_eq!(obs.files().len(), 2);
}

#[test]
fn a_present_but_empty_root_is_not_missing() {
    // 존재하는데 비어 있는 것은 **본 것**이다. 이것을 '없음' 으로 세면 깨끗한
    // 시스템마다 6번이 뜨고, 그러면 진짜 6번도 함께 무시된다.
    let fs = FakeFs::new(vec![("c:\\빈곳", vec![])]);
    let c = Collector::new(fs);
    let obs = collect_all(&c, &scope(&["c:\\빈곳"])).expect("수집");

    assert!(
        obs.missing_roots.is_empty(),
        "있는데 비어 있는 것은 본 것이다"
    );
    assert!(obs.files().is_empty());
}

#[test]
fn security_products_are_still_collected_when_roots_are_missing() {
    // 진단 정보는 루트와 무관하게 나와야 한다 — 루트가 어긋난 실행일수록
    // "이 PC 에 무엇이 깔려 있었나" 가 더 필요하다.
    let fs = FakeFs::new(vec![]);
    let c = Collector::new(fs);
    let obs = collect_all(&c, &scope(&["c:\\없음"])).expect("수집");
    // 가짜 레지스트리는 비어 있으므로 목록이 비는 것이 정상이다. 여기서 재는
    // 것은 **수집이 중단되지 않았다** 는 사실이다.
    assert!(obs.security_products.is_empty());
    assert_eq!(
        c.collect_security_products().expect("보안 제품").len(),
        obs.security_products.len()
    );
}

#[test]
fn every_declared_subject_gets_collected() {
    // 선언된 subject 는 결과가 비더라도 **담겨야** 한다. 담기지 않으면 그것은
    // "찾아봤는데 없었다" 가 아니라 "못 봤다" 이고, 관측이 통째로 불완전해진다.
    //
    // 한동안 `network_conn` 하나가 여기서 빠져 있었고 그 사실 자체를 시험이
    // 못박고 있었다. 그것이 카탈로그에서 빠졌으므로(설계-01 D11) 이제 예외가
    // 없다 — **이 시험의 값어치가 여기서 바뀐다.** 전에는 "하나가 빠진다" 를
    // 기록했고, 지금은 **subject 를 새로 넣고 `collect_all` 에 `harvest!` 줄을
    // 빠뜨리면 깨지는 가드**다.
    let fs = FakeFs::new(vec![("c:\\있음", vec![])]);
    let c = Collector::new(fs);
    let mut s = scope(&["c:\\있음"]);
    s.subjects = Subject::ALL.to_vec();
    let obs = collect_all(&c, &s).expect("수집");

    let missing: Vec<&str> = Subject::ALL
        .iter()
        .filter(|x| !obs.records.contains_key(x))
        .map(|x| x.id())
        .collect();
    assert!(
        missing.is_empty(),
        "선언했는데 담기지 않은 subject: {missing:?} — \
         `collect_all` 에 harvest! 줄이 빠졌거나, 수집기 없는 subject 를 정의했다"
    );

    // 전부 담겼으면 관측은 완전하다. 위 단언이 통과하는데 이것이 실패하면
    // `assemble` 이 담긴 것을 세지 못하고 있다는 뜻이다.
    let env = remedy_artifacts::assemble(
        "r".into(),
        "t".into(),
        remedy_sdk::artifact::HostInfo {
            hostname: "T".into(),
            os: "windows".into(),
            version: "10".into(),
            arch: "amd64".into(),
        },
        remedy_sdk::artifact::CoreInfo {
            version: "0".into(),
            build: "dev".into(),
        },
        &s,
        obs,
    );
    let o = env.body.observation();
    assert!(
        o.uncollected_subjects.is_empty(),
        "담겼는데 미수집으로 셌다: {:?}",
        o.uncollected_subjects
    );
}

/// **레지스트리 루트를 파일 시스템에 묻지 않는다.**
///
/// `FsRead::exists` 에 `HKLM\...` 을 넘기면 언제나 거짓이고, 그러면 값을 읽어
/// 낸 키가 "없는 루트" 로 집계된다. 2026-09-04 실기기에서 드러났다 —
/// `appinit-implant` 정답이 청정 Win10 에서 종료 코드 6 을 냈다. 선언한 루트
/// 셋 중 둘은 검체의 폴더라 정말로 없었고, 셋째인 레지스트리 키는 값 19개를
/// 읽어냈는데도 없는 것으로 세어 `all_roots_missing()` 이 성립했다.
///
/// **검체의 폴더로 좁게 잡는 것이 옳은 설계인데, 그렇게 적은 플러그인이 청정
/// 기계마다 관측 불완전을 냈다** — 건강한 기계 전부에서 우는 경보다.
#[test]
fn a_registry_root_is_asked_of_the_registry() {
    let fs = FakeFs::new(vec![]).with_keys(&["HKLM\\SOFTWARE\\있는키"]);
    let c = Collector::new(fs);
    let obs = collect_all(
        &c,
        &scope(&["HKLM\\SOFTWARE\\있는키", "HKLM\\SOFTWARE\\없는키"]),
    )
    .expect("수집");

    assert_eq!(
        obs.missing_roots,
        vec!["HKLM\\SOFTWARE\\없는키".to_string()],
        "있는 키가 없는 것으로 집계됐다 — 레지스트리 루트를 파일 시스템에 물었다"
    );
}

/// 끝의 `\*` 를 떼고 묻는다.
///
/// 그 별표는 "직속 하위 키로 펼쳐라" 는 표시이지 키 이름의 일부가 아니다.
/// 별표째 물으면 어떤 키도 존재하지 않고, 그것을 쓰는 플러그인은 전부 관측
/// 불완전이 된다 — IFEO 를 보는 룰이 그렇게 적는다.
#[test]
fn a_registry_root_with_a_star_strips_it_before_asking() {
    let fs = FakeFs::new(vec![]).with_keys(&["HKLM\\SOFTWARE\\펼칠키"]);
    let c = Collector::new(fs);
    let obs = collect_all(&c, &scope(&["HKLM\\SOFTWARE\\펼칠키\\*"])).expect("수집");

    assert!(
        obs.missing_roots.is_empty(),
        "별표를 떼지 않고 물었다: {:?}",
        obs.missing_roots
    );
}

/// 검체의 폴더가 없는 **청정 기계**에서, 레지스트리 루트가 살아 있으면
/// 관측은 완전하다 — 실기기가 낸 그 상황 그대로다.
#[test]
fn a_clean_machine_with_a_live_registry_root_is_complete() {
    let fs = FakeFs::new(vec![]).with_keys(&["HKLM\\SOFTWARE\\살아있음"]);
    let c = Collector::new(fs);
    let s = scope(&[
        "C:\\ProgramData\\검체폴더",
        "C:\\ProgramData\\검체폴더2",
        "HKLM\\SOFTWARE\\살아있음",
    ]);
    let obs = collect_all(&c, &s).expect("수집");

    assert_eq!(obs.missing_roots.len(), 2, "검체 폴더 둘만 없어야 한다");

    let env = remedy_artifacts::assemble(
        "r".into(),
        "t".into(),
        remedy_sdk::artifact::HostInfo {
            hostname: "T".into(),
            os: "windows".into(),
            version: "10".into(),
            arch: "amd64".into(),
        },
        remedy_sdk::artifact::CoreInfo {
            version: "0".into(),
            build: "dev".into(),
        },
        &s,
        obs,
    );
    assert!(
        env.body.observation().is_complete(),
        "청정 기계에서 관측 불완전이 섰다 — 이것이 실기기가 낸 오탐 경보다"
    );
}

/// 두 크레이트의 표본 상한이 같아야 한다 (2026-09-14).
///
/// `remedy-artifacts` 는 `remedy-platform` 에 의존하지 않아 상수를 공유할 수
/// 없다. 갈라지면 걷기가 32개를 담았는데 합치는 쪽이 16개에서 자르는 식이
/// 되고, **그 손실은 아무 데도 적히지 않는다** — 개수와 목록의 차이가 "표본"
/// 인지 "버림" 인지 구분되지 않기 때문이다.
///
/// 이 크레이트가 둘 다 보므로 여기서 단정한다.
#[test]
fn the_two_denied_sample_limits_agree() {
    assert_eq!(
        remedy_artifacts::DENIED_SAMPLE,
        remedy_platform::read::DENIED_SAMPLE,
        "표본 상한이 갈라졌다"
    );
}

/// **좁힌 자리도 선언한 자리다** (2026-10-27 · 적대 검증이 짚은 high).
///
/// `subject_roots` 는 `scan_roots` 보다 깊은 경로일 수 있고, 수집기들은 그것을
/// 두 갈래 `exists()` 로 걸러 낸다. 그래서 좁힌 자리가 **막혀** 있으면 걷지도
/// 않고 세지도 않아 — 선언한 범위의 절반을 못 봤는데 화면에 흔적이 없었다.
/// `scan_roots` 쪽에서 막은 구멍이 한 층 아래 그대로 남아 있었다.
#[test]
fn a_narrowed_root_we_could_not_ask_about_is_counted_too() {
    let open = "c:\\있음";
    let file = "c:\\있음\\a.exe";

    let mut s = scope(&[open]);
    s.subject_roots
        .insert(Subject::File, vec!["c:\\있음\\깊은곳".to_string()]);
    let c =
        Collector::new(FakeFs::new(vec![(open, vec![file])]).with_locked(&["c:\\있음\\깊은곳"]));
    let obs = collect_all(&c, &s).expect("수집");
    assert_eq!(
        obs.unreadable_roots,
        vec!["c:\\있음\\깊은곳".to_string()],
        "좁힌 자리를 못 물었는데 아무 데도 남지 않았다"
    );
    // **없는 루트로 세지 않는다.** `declared_roots` 는 `scan_roots` 의 수라서
    // 거기에 더하면 `all_roots_missing()` 의 분모와 어긋난다.
    assert!(obs.missing_roots.is_empty(), "{:?}", obs.missing_roots);

    // 좁힌 자리가 **없을** 때는 세지 않는다 — 미설치가 정상이다.
    let mut s2 = scope(&[open]);
    s2.subject_roots
        .insert(Subject::File, vec!["c:\\있음\\없는곳".to_string()]);
    let c2 = Collector::new(FakeFs::new(vec![(open, vec![file])]));
    let obs2 = collect_all(&c2, &s2).expect("수집");
    assert!(
        obs2.unreadable_roots.is_empty() && obs2.missing_roots.is_empty(),
        "없는 좁힘을 불완전으로 셌다 — 미설치 기계가 영원히 6 이 된다: {:?} {:?}",
        obs2.unreadable_roots,
        obs2.missing_roots
    );

    // 선언하지 않은 subject 의 좁힘은 묻지 않는다 — 모으지 않는 자리다.
    let mut s3 = scope(&[open]);
    s3.subject_roots
        .insert(Subject::TextConfig, vec!["c:\\잠김".to_string()]);
    let c3 = Collector::new(FakeFs::new(vec![(open, vec![file])]).with_locked(&["c:\\잠김"]));
    let obs3 = collect_all(&c3, &s3).expect("수집");
    assert!(
        obs3.unreadable_roots.is_empty(),
        "모으지도 않는 subject 의 좁힘으로 불완전을 만들었다: {:?}",
        obs3.unreadable_roots
    );
}
