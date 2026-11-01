//! remedy-yara — YARA 엔진 격리 래퍼 (설계-09 P4, 설계-04 §1).
//!
//! **엔진은 여기에만 있다.** `remedy-detect` 만 이 크레이트를 의존하고, 그
//! 위로는 `yara_x` 타입이 새어 나가지 않는다. 엔진을 갈아 끼우는 날 고칠 곳이
//! 한 파일이어야 한다.
//!
//! # 왜 바이트만 받는가
//!
//! 이 크레이트는 경로를 받지 않는다. `remedy-detect` 는 `remedy-platform` 을
//! 의존할 수 없고(설계-04 §1), 그 금지가 **플러그인 룰은 시스템에 접근할 수
//! 없다**를 구조적으로 보장한다. YARA 가 파일을 직접 열면 그 보장이 무너진다.
//!
//! 그래서 스캔 대상은 **스냅샷에 담긴 바이트**뿐이다. 담기지 않은 대상에 걸린
//! YARA 규칙은 미매치가 아니라 **미평가**이며, 그 사실이 보고되어야 한다
//! (설계-03 §1) — 미평가 규칙이 있는 판정은 감염 확정에 쓸 수 없다.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

pub const CRATE_NAME: &str = "remedy-yara";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraError(pub String);

impl std::fmt::Display for YaraError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// `rules/<파일>.yar:<룰 이름>` 참조.
///
/// 파일과 룰 이름을 **둘 다** 요구하는 이유는 이름 충돌 때문이다. 플러그인이
/// 여러 `.yar` 을 싣고 같은 이름의 룰이 둘 있으면, 파일 없이는 어느 쪽인지
/// 정할 수 없고 그 선택이 조용히 바뀔 수 있다.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RuleRef {
    pub file: String,
    pub rule: String,
}

impl RuleRef {
    /// `rules/x.yar:name` 을 가른다.
    pub fn parse(s: &str) -> Result<Self, YaraError> {
        // 경로에 `:` 가 들어갈 수 있으므로(`C:\...`) **마지막** 콜론으로 가른다.
        let (file, rule) = s.rsplit_once(':').ok_or_else(|| {
            YaraError(format!(
                "'{s}' 는 'rules/<파일>.yar:<룰 이름>' 형태가 아닙니다"
            ))
        })?;
        if file.is_empty() || rule.is_empty() {
            return Err(YaraError(format!(
                "'{s}' 는 'rules/<파일>.yar:<룰 이름>' 형태가 아닙니다"
            )));
        }
        Ok(Self {
            file: file.replace('\\', "/"),
            rule: rule.to_string(),
        })
    }

    pub fn as_text(&self) -> String {
        format!("{}:{}", self.file, self.rule)
    }
}

/// 플러그인이 실은 `.yar` 들을 컴파일해 둔 것.
pub struct RuleSet {
    /// 파일마다 따로 컴파일한다. 한 덩어리로 묶으면 파일 A 의 문법 오류가
    /// 파일 B 의 룰까지 못 쓰게 만들고, 작성자는 어느 파일이 문제인지 모른다.
    by_file: BTreeMap<String, yara_x::Rules>,
    /// 컴파일하지 못한 파일과 그 이유. **버리지 않는다** — 그 파일의 룰을
    /// 참조하는 조건은 미매치가 아니라 미평가다.
    pub failed: BTreeMap<String, String>,
}

impl RuleSet {
    /// `(파일 이름, 원문)` 목록을 컴파일한다.
    pub fn compile(sources: &[(String, String)]) -> Self {
        let mut by_file = BTreeMap::new();
        let mut failed = BTreeMap::new();
        for (name, text) in sources {
            let key = name.replace('\\', "/");
            match compile_one(text) {
                Ok(r) => {
                    by_file.insert(key, r);
                }
                Err(e) => {
                    failed.insert(key, e);
                }
            }
        }
        Self { by_file, failed }
    }

    pub fn is_empty(&self) -> bool {
        self.by_file.is_empty() && self.failed.is_empty()
    }

    pub fn files(&self) -> Vec<&str> {
        self.by_file.keys().map(String::as_str).collect()
    }

    /// 바이트열을 훑는다.
    ///
    /// - `Ok(true)` — 그 룰이 맞았다
    /// - `Ok(false)` — 훑었는데 안 맞았다
    /// - `Err` — **훑지 못했다.** 미매치와 다르다.
    pub fn matches(&self, r: &RuleRef, bytes: &[u8]) -> Result<bool, YaraError> {
        let rules = self.compiled(r)?;
        let mut scanner = yara_x::Scanner::new(rules);
        // 타임아웃은 두지 않는다 (결정 2026-09-07). 그때의 근거는 *"걸리면 `Err`
        // 가 호출자에서 **불일치**로 접혀 조용한 미탐이 된다 — 멈추는 쪽이 놓치는
        // 쪽보다 낫다"* 였다. 2026-10-26 부터 `Err` 는 미평가로 나가 판정이 없으면
        // 종료 6 이다 — 조용하지 않다. 결정을 다시 볼지는 따로 정한다. 오래 걸리는
        // 것은 심장박동이 보인다.
        let results = scanner
            .scan(bytes)
            .map_err(|e| YaraError(format!("{} 스캔 실패: {e}", r.as_text())))?;
        Ok(results.matching_rules().any(|m| m.identifier() == r.rule))
    }

    /// 바이트 없이 **참조만** 본다 — 그 파일이 컴파일됐고 그 룰 이름이 있는가.
    ///
    /// 레코드와 무관한 플러그인의 결함이라, 훑을 바이트가 없는 레코드에서도
    /// 그 이름으로 말해야 한다(2026-10-26 적대 검증 — 본문 없는 레코드에서는
    /// 오타가 *"본문 없음"* 으로 읽혔다). [`RuleSet::matches`] 도 이것을 먼저 본다.
    pub fn check(&self, r: &RuleRef) -> Result<(), YaraError> {
        self.compiled(r).map(|_| ())
    }

    fn compiled(&self, r: &RuleRef) -> Result<&yara_x::Rules, YaraError> {
        if let Some(why) = self.failed.get(&r.file) {
            return Err(YaraError(format!(
                "{} 를 컴파일하지 못했습니다: {why}",
                r.file
            )));
        }
        let rules = self.by_file.get(&r.file).ok_or_else(|| {
            YaraError(format!(
                "{} 이 플러그인에 없습니다 (있는 파일: {})",
                r.file,
                if self.by_file.is_empty() {
                    "없음".to_string()
                } else {
                    self.files().join(" · ")
                }
            ))
        })?;

        // 룰 이름이 그 파일에 있는지 **먼저** 본다. 없는 이름을 미매치로
        // 흘려보내면 오타 난 참조가 조용히 "안 맞았다" 가 되고, 작성자는
        // 룰이 왜 안 도는지 알 수 없다.
        match rules.iter().find(|x| x.identifier() == r.rule) {
            None => {
                return Err(YaraError(format!(
                    "{} 에 '{}' 라는 룰이 없습니다",
                    r.file, r.rule
                )))
            }
            // **private 룰은 결과에 나오지 않는다** — 바이트가 맞아도 늘 "안
            // 맞았다" 가 된다. 다른 룰이 안에서 쓰는 것이라 직접 부르지 않는다
            // (가이드 20). 오류로 말하지 않으면 그 오타가 조용히 미탐이 된다.
            Some(x) if x.is_private() => {
                return Err(YaraError(format!(
                "{} 의 '{}' 는 private 룰이라 결과에 나오지 않습니다 — 공개 룰을 가리켜야 합니다",
                r.file, r.rule
            )))
            }
            Some(_) => {}
        }
        Ok(rules)
    }
}

/// 파일 하나를 컴파일한다. **`include` 를 끈다** — 켜 두면 `.yar` 의 `include` 가
/// 프로세스의 작업 폴더나 절대 경로에서 디스크를 읽는다. 이 크레이트가 파일을
/// 열지 않는다는 보장(머리말)과 결정성이 그 길로 깨진다(2026-10-26 적대 검증).
fn compile_one(text: &str) -> Result<yara_x::Rules, String> {
    let mut c = yara_x::Compiler::new();
    c.enable_includes(false);
    c.add_source(text).map_err(|e| e.to_string())?;
    Ok(c.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = r#"
        rule marker {
            strings:
                $m = "REMEDY-MARKER" ascii
            condition:
                $m
        }
        rule other { condition: false }
    "#;

    fn ruleset() -> RuleSet {
        RuleSet::compile(&[("rules/a.yar".into(), A.into())])
    }

    #[test]
    fn a_reference_splits_on_the_last_colon() {
        // 경로에 콜론이 들어갈 수 있다. 첫 콜론으로 가르면 `C:\x.yar:r` 이
        // 파일 `C` 로 읽힌다.
        let r = RuleRef::parse("C:\\rules\\a.yar:marker").unwrap();
        assert_eq!(r.file, "C:/rules/a.yar");
        assert_eq!(r.rule, "marker");
    }

    #[test]
    fn a_reference_without_a_rule_name_is_refused() {
        for s in ["rules/a.yar", "rules/a.yar:", ":marker", ""] {
            assert!(RuleRef::parse(s).is_err(), "{s} 를 받아들였다");
        }
    }

    #[test]
    fn a_matching_rule_says_so_and_a_non_matching_one_says_so() {
        let rs = ruleset();
        let m = RuleRef::parse("rules/a.yar:marker").unwrap();
        assert_eq!(rs.matches(&m, b"xx REMEDY-MARKER yy"), Ok(true));
        assert_eq!(rs.matches(&m, b"nothing here"), Ok(false));
    }

    #[test]
    fn only_the_named_rule_counts_even_if_another_matched() {
        // 파일 안의 아무 룰이나 맞으면 참이 되게 두면, 룰 이름을 적는 뜻이 없다.
        let rs = RuleSet::compile(&[(
            "rules/b.yar".into(),
            r#"
                rule always { condition: true }
                rule never  { condition: false }
            "#
            .into(),
        )]);
        let never = RuleRef::parse("rules/b.yar:never").unwrap();
        assert_eq!(rs.matches(&never, b"anything"), Ok(false));
    }

    #[test]
    fn a_missing_rule_name_is_an_error_not_a_miss() {
        // 미매치로 흘려보내면 오타 난 참조가 조용히 "안 맞았다" 가 된다.
        let rs = ruleset();
        let bad = RuleRef::parse("rules/a.yar:없는룰").unwrap();
        let e = rs.matches(&bad, b"x").unwrap_err();
        assert!(e.0.contains("없는룰"), "{e}");
        // **바이트 없이도 같은 말을 한다** — 훑을 본문이 없는 레코드에서도.
        assert_eq!(rs.check(&bad), Err(e));
        assert_eq!(
            rs.check(&RuleRef::parse("rules/a.yar:marker").unwrap()),
            Ok(())
        );
    }

    #[test]
    fn a_missing_file_names_the_files_that_do_exist() {
        // 오류 메시지가 가이드의 절반이다 (설계-01).
        let rs = ruleset();
        let bad = RuleRef::parse("rules/nope.yar:marker").unwrap();
        let e = rs.matches(&bad, b"x").unwrap_err();
        assert!(
            e.0.contains("rules/a.yar"),
            "있는 파일을 알려주지 않는다: {e}"
        );
    }

    #[test]
    fn a_broken_rule_file_is_an_error_not_a_silent_miss() {
        // 문법 오류를 미매치로 다루면 룰이 통째로 죽은 채 판정이 나간다.
        let rs = RuleSet::compile(&[("rules/bad.yar".into(), "rule x { condition".into())]);
        assert!(rs.failed.contains_key("rules/bad.yar"));
        let r = RuleRef::parse("rules/bad.yar:x").unwrap();
        assert!(rs.matches(&r, b"x").is_err());
    }

    #[test]
    fn a_private_rule_reference_is_an_error_not_a_miss() {
        // private 룰은 결과에 나오지 않는다 — 가리키면 맞아도 늘 "안 맞았다" 였다.
        // 그것을 쓰는 공개 룰은 그대로 돈다.
        let rs = RuleSet::compile(&[(
            "rules/p.yar".into(),
            r#"
                private rule hidden { strings: $a = "PRIVATE-MARK" condition: $a }
                rule shown { condition: hidden }
            "#
            .into(),
        )]);
        let hidden = RuleRef::parse("rules/p.yar:hidden").unwrap();
        let e = rs.check(&hidden).unwrap_err();
        assert!(e.0.contains("private"), "{e}");
        assert!(rs.matches(&hidden, b"PRIVATE-MARK").is_err());
        let shown = RuleRef::parse("rules/p.yar:shown").unwrap();
        assert_eq!(rs.matches(&shown, b"PRIVATE-MARK"), Ok(true));
    }

    #[test]
    fn an_include_is_refused_not_read_from_disk() {
        // `include` 는 작업 폴더나 절대 경로에서 디스크를 읽는다 — 이 크레이트가
        // 파일을 열지 않는다는 보장이 그 길로 깨진다. 컴파일 오류로 거절한다.
        //
        // **있는 파일**을 가리킨다 — 없는 파일이면 켜 둬도 "못 찾았다" 로 실패해
        // 이 시험이 아무것도 재지 않는다.
        let dir = std::env::temp_dir().join(format!("remedy-yara-include-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let other = dir.join("other.yar");
        std::fs::write(&other, "rule other { condition: true }").unwrap();
        let src = format!(
            "include \"{}\"\nrule r {{ condition: other }}",
            other.display().to_string().replace('\\', "/")
        );
        let rs = RuleSet::compile(&[("rules/inc.yar".into(), src)]);
        let _ = std::fs::remove_dir_all(&dir);
        let why = rs
            .failed
            .get("rules/inc.yar")
            .expect("include 를 거절해야 한다 — 있는 파일이어도");
        assert!(why.contains("include"), "{why}");
    }

    #[test]
    fn one_broken_file_does_not_take_down_the_others() {
        let rs = RuleSet::compile(&[
            ("rules/a.yar".into(), A.into()),
            ("rules/bad.yar".into(), "rule x { condition".into()),
        ]);
        let ok = RuleRef::parse("rules/a.yar:marker").unwrap();
        assert_eq!(rs.matches(&ok, b"REMEDY-MARKER"), Ok(true));
    }

    #[test]
    fn scanning_the_same_bytes_twice_gives_the_same_answer() {
        // 결정성이 없으면 같은 스냅샷을 두 번 평가한 결과가 달라진다.
        let rs = ruleset();
        let m = RuleRef::parse("rules/a.yar:marker").unwrap();
        let body = b"REMEDY-MARKER";
        assert_eq!(rs.matches(&m, body), rs.matches(&m, body));
    }

    #[test]
    fn an_empty_input_is_scanned_not_skipped() {
        let rs = ruleset();
        let m = RuleRef::parse("rules/a.yar:marker").unwrap();
        assert_eq!(rs.matches(&m, b""), Ok(false));
    }

    #[test]
    fn this_crate_never_opens_a_file() {
        // **설계-09 P4 의 "mmap SIGBUS 대응" 이 여기서 해소된다.**
        //
        // 스캔 중에 파일이 잘리면 매핑된 페이지를 읽는 순간 SIGBUS 로 프로세스가
        // 죽는다. 그래서 파일을 매핑하는 스캐너는 그 신호를 다뤄야 하는데,
        // **우리는 매핑하지 않는다** — 훑는 것은 스냅샷에 담긴 바이트뿐이고
        // (`matches(&self, _, bytes: &[u8])`), 그 바이트는 수집 시점에 이미
        // 복사된 것이다. 스캔 도중 원본이 잘려도 우리 쪽에는 아무 일이 없다.
        //
        // 그 성질은 `remedy-detect` 가 `remedy-platform` 을 의존하지 못한다는
        // 규칙(설계-04 §1, `cargo xtask arch`)이 지킨다. 다만 이 크레이트가
        // `yara_x::Scanner::scan_file` 을 직접 부르면 그 규칙을 우회한다.
        // 여기서 그것을 막는다.
        // **시험 모듈 앞까지만 본다.** 금지 목록 자체가 이 파일 안에 있으므로,
        // 전체를 훑으면 시험이 자기 자신을 걸어 언제나 실패한다.
        let src = include_str!("lib.rs");
        let code = src.split("#[cfg(test)]").next().unwrap_or(src);
        for forbidden in ["scan_file", "std::fs", "memmap"] {
            let hits = code
                .lines()
                .filter(|l| l.contains(forbidden) && !l.trim_start().starts_with("//"))
                .count();
            assert_eq!(
                hits, 0,
                "'{forbidden}' 가 코드에 있다 — 파일을 매핑하면 스캔 도중 잘린 \
                 파일에서 SIGBUS 로 죽는다"
            );
        }
    }
}
