//! 수집 범위 — **권한 상한이지 성능 최적화가 아니다** (설계-02 §2·§4).
//!
//! `scan_roots` 는 경로 기반 접근 전부의 상한이고, 증거에서 파생된 경로까지 포함한다.
//! `subjects` 는 열거가 허용되는 대상 타입의 상한이다. 선언한 것만 볼 수 있다.

use remedy_sdk::catalog::{Platform, Subject};
use remedy_sdk::normalize;
use std::collections::BTreeMap;

/// 한 번의 수집이 볼 수 있는 범위.
#[derive(Debug, Clone)]
pub struct Scope {
    /// 정규화·전개가 끝난 절대 경로들.
    pub scan_roots: Vec<String>,
    /// 그중 `%REMOVABLE%` 에서 나온 것들.
    ///
    /// **읽는 것과 부수는 것은 다른 결정이다.** 매니페스트의 `allow_removable`
    /// 은 "읽어도 좋다" 까지이고, 그 위의 파일을 지우는 것은 사람이 눈앞의
    /// 매체를 보고 판단할 일이다 (설계-03 §4). 계획기가 그 구분을 하려면 어느
    /// 루트가 이동식이었는지 스냅샷에 남아 있어야 한다.
    pub removable_roots: Vec<String>,
    pub subjects: Vec<Subject>,
    /// subject 하나에만 적용되는 **더 좁은** 상한 (매니페스트의 subject_roots).
    ///
    /// 적히지 않은 subject 는 [`Self::scan_roots`] 전부를 쓴다. 여기 값은
    /// 언제나 `scan_roots` 안이다 — 린트가 그것을 오류로 막고, 그래서 읽기
    /// 권한의 상한은 여전히 `scan_roots` 하나다.
    pub subject_roots: BTreeMap<Subject, Vec<String>>,
    /// 확장자 없이도 `text_config` 로 읽을 **드롭인 디렉터리** (매니페스트의
    /// `text_config_dirs` · C-5).
    ///
    /// `subject_roots` 와 방향만 반대다 — 그쪽은 같은 상한 안에서 **좁히고**,
    /// 이쪽은 같은 상한 안에서 **읽는 것을 넓힌다.** 여기 값도 언제나
    /// `scan_roots` 안이고 린트가 오류로 막으므로, 읽기 권한의 상한은 여전히
    /// `scan_roots` 하나다.
    ///
    /// **직접 자식만** 읽는다. 이유는 `remedy_collect::config` 의
    /// `text_config_files` 에 있다.
    pub text_config_dirs: Vec<String>,
    pub platform: Platform,
    /// 파일 하나의 해시 계산 상한. 넘으면 메타데이터만 담는다.
    pub max_hash_bytes: u64,
    /// 수집할 파일 개수 상한. 넘으면 `truncated` 가 선다.
    pub max_files: usize,
}

impl Scope {
    /// 진단 모드용 범위 — **플러그인 없이** 도는 경로다 (설계-00 §5).
    ///
    /// 플러그인이 없으면 `scan_roots` 도 없으므로, 호출자가 명시적으로 준 루트만 본다.
    pub fn diagnostic(roots: Vec<String>, platform: Platform) -> Self {
        Self {
            scan_roots: roots,
            removable_roots: Vec::new(),
            subjects: vec![Subject::File, Subject::Persistence],
            subject_roots: BTreeMap::new(),
            // 진단 모드에는 매니페스트가 없다. 선언 없이 확장자 밖의 파일을
            // 읽는 길은 **없다.**
            text_config_dirs: Vec::new(),
            platform,
            max_hash_bytes: 32 * 1024 * 1024,
            max_files: 500_000,
        }
    }

    /// 이 subject 가 훑을 루트.
    ///
    /// **좁혀 적힌 것이 있으면 그것만, 없으면 전부.** 수집기가
    /// `scan_roots` 를 직접 순회하면 이 구분이 사라지므로, 경로를 도는
    /// 자리는 전부 이 함수를 지난다.
    ///
    /// **이것은 수집의 상한이다.** 삭제의 상한은 [`Self::allows`] 이고 그쪽은
    /// 좁아지지 않는다 — 이유는 그 함수의 문서에.
    ///
    /// **빈 목록도 그대로 돌려준다.** `scan_roots` 로 물러나면 작성자가
    /// 좁히려던 자리가 조용히 넓어진다 — 권한이 놀랍게 느는 쪽으로 틀리는
    /// 것이 0건으로 틀리는 것보다 나쁘다. 애초에 빈 목록이 여기 오지 않도록
    /// 린트가 오류로 막고 `scope_from_manifest` 가 한 번 더 막는다.
    pub fn roots_for(&self, s: Subject) -> &[String] {
        match self.subject_roots.get(&s) {
            Some(v) => v,
            None => &self.scan_roots,
        }
    }

    /// 이 경로가 상한 안에 있는가.
    ///
    /// 성분 경계에서 비교한다. 단순 접두 비교는 `C:\Program Files\Foo` 와
    /// `C:\Program Files\Foobar` 를 구분하지 못한다.
    ///
    /// # `subject_roots` 는 여기에 걸리지 않는다 — **의도한 것이다**
    ///
    /// `guard.rs` 가 적어 둔 원칙은 *"수집이 그 상한을 안 받으면 제거도 안
    /// 받아야 한다"* 이고, 그것은 **subject 차원**의 대칭이다. 좁힘은 그 대칭을
    /// 깨지 않는다 — 두 갈래로 나뉠 뿐이다.
    ///
    /// | 지우려는 대상 | 어디서 왔나 | 상한 |
    /// |---|---|---|
    /// | 수집된 레코드 | `roots_for(S)` 안에서만 모였다 | **이미 좁혀져 있다** |
    /// | capture 값 (`dir.delete_recursive`) | 레코드가 아니라 **경로 문자열** | `scan_roots` |
    ///
    /// 첫 줄이 **전이로** 성립한다. subject S 의 레코드는 `roots_for(S)` 밖에서
    /// 모일 수 없으므로, 그 레코드를 겨눈 Op 의 대상도 자동으로 그 안이다.
    /// 2026-09-04 감염 실기기에서 확인했다 — `structured_config` 를
    /// `%PROGRAMDATA%\Acme\Agent` 로 좁힌 답안의 `structured_config.remove_key`
    /// 가 정확히 그 폴더의 파일을 겨눴다.
    ///
    /// 둘째 줄은 **좁히지 않는다.** 디렉터리 경로는 어느 subject 의 레코드도
    /// 아니다. 그것을 `file` 의 좁힘에 묶으면 *"파일을 어디서 모으는가"* 와
    /// *"어느 디렉터리를 지워도 되는가"* 라는 다른 두 물음을 한 값으로 답하게
    /// 된다. 파일 시스템 경로의 상한은 파일 시스템의 상한 — `scan_roots` 다.
    ///
    /// 그리고 그 편이 안전하다. 좁힘이 삭제 상한이 되면 **읽기 권한의 상한이
    /// 다시 두 곳**이 되고, 그것이 `subject_roots` 를 만들 때 피한 바로 그
    /// 모양이다.
    pub fn allows(&self, path: &str) -> bool {
        self.scan_roots
            .iter()
            .any(|r| normalize::is_within(path, r, self.platform))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(roots: &[&str]) -> Scope {
        Scope::diagnostic(
            roots.iter().map(|s| s.to_string()).collect(),
            Platform::Windows,
        )
    }

    /// **좁힘은 삭제 상한이 아니다** — 그리고 그것이 의도다.
    ///
    /// `allows` 는 파일 시스템 경로의 상한을 묻는 함수이고, 그 상한은
    /// `scan_roots` 다. `subject_roots` 는 **어느 subject 를 어디서 모으는가**를
    /// 정할 뿐이다.
    ///
    /// 둘을 섞으면 `dir.delete_recursive` 처럼 대상이 **레코드가 아니라 capture
    /// 값**인 Op 이 갈 곳을 잃는다 — 디렉터리 경로는 어느 subject 의 레코드도
    /// 아니어서, 어느 좁힘을 적용할지 정할 근거가 없다.
    ///
    /// 수집된 레코드를 겨눈 Op 은 **전이로** 이미 좁혀져 있다. subject S 의
    /// 레코드는 `roots_for(S)` 밖에서 모일 수 없기 때문이다. 그래서 좁힘을
    /// 삭제 상한으로 만들 이유가 없고, 만들면 읽기 권한의 상한이 다시 두 곳이
    /// 된다.
    ///
    /// **이 시험이 깨졌다면** 누군가 `allows` 를 subject 별로 바꾼 것이다.
    /// 위 문단을 먼저 읽고 판단할 것.
    #[test]
    fn narrowing_does_not_narrow_the_deletion_ceiling() {
        let mut s = scope(&["C:\\wide"]);
        s.subject_roots
            .insert(Subject::File, vec!["C:\\wide\\narrow".to_string()]);

        // 좁힘은 수집에 걸린다.
        assert_eq!(s.roots_for(Subject::File), ["C:\\wide\\narrow".to_string()]);
        // 좁히지 않은 subject 는 상한 전부.
        assert_eq!(s.roots_for(Subject::Persistence), s.scan_roots.as_slice());

        // 삭제 상한은 그대로 `scan_roots` 다. capture 에서 나온 디렉터리는
        // 좁힘 밖이어도 상한 안이면 지울 수 있다.
        assert!(
            s.allows("C:\\wide\\other\\payload"),
            "좁힘이 삭제 상한까지 좁혔다 — 함수 문서를 읽고 판단할 것"
        );
        // 상한 밖은 여전히 막힌다.
        assert!(!s.allows("C:\\elsewhere\\payload"));
    }

    #[test]
    fn allows_only_inside_declared_roots() {
        let s = scope(&["C:\\Users\\test\\AppData\\Local\\Programs"]);
        assert!(s.allows("C:\\Users\\test\\AppData\\Local\\Programs\\app\\main.js"));
        assert!(s.allows("c:\\users\\TEST\\appdata\\local\\programs"));
        assert!(!s.allows("C:\\Windows\\System32\\cmd.exe"));
    }

    #[test]
    fn sibling_prefix_is_not_inside() {
        // 이 구분이 없으면 파생 경로 검사가 무의미해진다.
        let s = scope(&["C:\\a\\b"]);
        assert!(!s.allows("C:\\a\\bcd\\x"));
    }

    #[test]
    fn empty_roots_allow_nothing() {
        // 상한이 비어 있으면 아무것도 읽을 수 없어야 한다. 기본값이 '전부 허용'
        // 이면 선언을 빠뜨린 플러그인이 조용히 전체 디스크를 읽는다.
        let s = scope(&[]);
        assert!(!s.allows("C:\\anything"));
    }
}
