//! 같은 제품의 점검 발견을 묶는다 — *모두 검사* 끝 요약 밑의 **제품마다 — 올리면 해결되는 버전**
//! (목표 remedy_기본검사_룰관리 결정 ③④).
//!
//! 같은 모듈에 시기가 다른 취약점이 나와 룰이 여럿이어도(A → B) 판정은 룰마다 그대로다. 묶음은 화면에만 있다.
//!
//! - **고친 판은 새 데이터가 아니다.** 판정이 선 증거의 맞은 술어(`*_version_lt` 의 값)가 그 기계의 고친 판이다.
//! - **같은 설치본이면 가장 높은 판 하나로 모두 풀린다.** 패키지 이름이나 파일 경로가 같은 자리에서 둘 이상의 룰이
//!   맞으면, 그 가운데 가장 높은 고친 판으로 올리면 낮은 판을 요구하는 줄은 맞지 않는다. 설치본이 다르면(같은 기계의
//!   PHP 7.4 와 8.2) 판의 계열이 달라 섞지 않는다.
//! - **판으로 보지 않는 발견은 그 밑에 따로 적는다**(설정 · 고친 판을 모르는 줄) — 올려도 남을 수 있다.
//! - **대체 관계는 적지 않는다**(결정 ③) — 배포판이 CVE 를 따로 고치면 대체로 숨긴 발견이 조용히 빠진다.

use remedy_sdk::artifact::ScanBody;
use remedy_sdk::i18n::Lang;
use std::cmp::Ordering;
use std::collections::BTreeSet;

/// 판정이 선 증거 하나가 요구하는 고친 판 — 어느 설치본(`key`)이 어느 비교(`op`)로 얼마(`fixed`) 미만이었나.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Fix {
    pub key: String,
    pub op: String,
    pub fixed: String,
}

/// *모두 검사* 에서 무언가를 찾은 점검 룰 하나 — 묶음의 재료.
pub(crate) struct Found<'a> {
    pub label: &'a str,
    pub product: &'a str,
    pub fixes: &'a [Fix],
}

/// 고친 판끼리 견준다 — 술어마다 그 비교 규칙으로. 모르는 술어 · 읽지 못하는 판이면 `None` 이다(섞지 않는다).
fn cmp(op: &str, a: &str, b: &str) -> Option<Ordering> {
    use remedy_detect::compare;
    match op {
        "pkg_version_lt" => compare::pkg_version_cmp(a, b),
        "rpm_version_lt" => compare::rpm_version_cmp(a, b),
        "apk_version_lt" => compare::apk_version_cmp(a, b),
        "version_lt" => compare::version_cmp(a, b),
        _ => None,
    }
}

/// 판정이 선 증거의 고친 판. 판정식이 짚는 규칙(`verdict_rules`)의 증거만 본다 — 그룹에 함께 든 다른 규칙의 증거는
/// 판정과 상관없다. 한 증거가 판 비교를 둘 이상 맞혔으면 높은 쪽이 그 줄의 고친 판이다.
pub(crate) fn fixes_of(body: &ScanBody) -> Vec<Fix> {
    let passed: BTreeSet<&str> = body.verdicts.iter().map(String::as_str).collect();
    let in_verdict: BTreeSet<&str> = body
        .groups
        .iter()
        .filter(|g| passed.contains(g.id.as_str()))
        .flat_map(|g| g.evidence.iter().map(String::as_str))
        .collect();
    let mut out: Vec<Fix> = Vec::new();
    for e in &body.evidence {
        if !in_verdict.contains(e.id.as_str()) {
            continue;
        }
        if !body.verdict_rules.is_empty() && !body.verdict_rules.contains(&e.rule) {
            continue;
        }
        let mut best: Option<(&str, &str)> = None;
        for p in &e.matched {
            let Some(v) = p.value.as_ref().and_then(|v| v.as_str()) else {
                continue;
            };
            if !p.op.ends_with("version_lt") {
                continue;
            }
            best = match best {
                Some((op, cur)) if op == p.op && cmp(op, v, cur) == Some(Ordering::Greater) => {
                    Some((op, v))
                }
                Some(kept) => Some(kept),
                None => Some((p.op.as_str(), v)),
            };
        }
        let Some((op, fixed)) = best else {
            continue;
        };
        let key = ["name", "path"]
            .iter()
            .find_map(|k| e.target.get(*k).and_then(|v| v.as_str()))
            .unwrap_or(e.rule.as_str());
        let fix = Fix {
            key: key.to_string(),
            op: op.to_string(),
            fixed: fixed.to_string(),
        };
        if !out.contains(&fix) {
            out.push(fix);
        }
    }
    out
}

/// 한 설치본의 올릴 판 — 그 판으로 풀리는 룰들.
struct Upgrade<'a> {
    keys: Vec<&'a str>,
    op: &'a str,
    fixed: &'a str,
    labels: Vec<&'a str>,
}

/// 제품마다의 줄. 같은 제품(대소문자를 가리지 않는다)의 발견을 처음 나온 차례로 모은다. 판으로 풀리는 줄이 하나도
/// 없는 제품은 적지 않는다 — 올릴 판이 없으면 이 묶음이 할 말이 없다. 찾은 것이 없으면 빈다. `dash` 는 요약의 다른
/// 줄과 같은 이음표다(`deco().dash()` — ASCII 화면에서는 ` - `).
pub(crate) fn lines(found: &[Found<'_>], lang: Lang, dash: &str) -> Vec<String> {
    let mut products: Vec<(&str, Vec<&Found<'_>>)> = Vec::new();
    for f in found {
        let want = f.product.to_lowercase();
        match products.iter_mut().find(|(p, _)| p.to_lowercase() == want) {
            Some((_, rules)) => rules.push(f),
            None => products.push((f.product, vec![f])),
        }
    }
    let mut out = Vec::new();
    for (product, rules) in &products {
        let ups = upgrades(rules);
        if ups.is_empty() {
            continue;
        }
        for u in &ups {
            out.push(upgrade_line(lang, dash, product, u));
        }
        let rest: Vec<&str> = rules
            .iter()
            .filter(|r| r.fixes.is_empty())
            .map(|r| r.label)
            .collect();
        if !rest.is_empty() {
            let rest = rest.join(" · ");
            out.push(lang.pick(
                format!(
                    "  {product}{dash}버전으로 판정하지 않는 항목입니다(올려도 남을 수 있습니다): {rest}"
                ),
                format!("  {product}{dash}not judged by version (may remain after upgrading): {rest}"),
            ));
        }
    }
    out
}

/// 설치본(`key` · 비교)마다 가장 높은 고친 판을 고르고, 올릴 판과 풀리는 룰이 같은 설치본은 한 줄로 합친다
/// (`php8.2-cli · php8.2-fpm`). 견줄 수 없는 판은 합치지 않고 따로 둔다.
fn upgrades<'a>(rules: &[&'a Found<'a>]) -> Vec<Upgrade<'a>> {
    let mut per: Vec<Upgrade<'a>> = Vec::new();
    for r in rules {
        for fx in r.fixes {
            let slot = per.iter_mut().find(|u| {
                u.keys[0] == fx.key
                    && u.op == fx.op
                    && (u.fixed == fx.fixed || cmp(u.op, &fx.fixed, u.fixed).is_some())
            });
            match slot {
                Some(u) => {
                    if cmp(u.op, &fx.fixed, u.fixed) == Some(Ordering::Greater) {
                        u.fixed = fx.fixed.as_str();
                    }
                    if !u.labels.contains(&r.label) {
                        u.labels.push(r.label);
                    }
                }
                None => per.push(Upgrade {
                    keys: vec![fx.key.as_str()],
                    op: fx.op.as_str(),
                    fixed: fx.fixed.as_str(),
                    labels: vec![r.label],
                }),
            }
        }
    }
    let mut merged: Vec<Upgrade<'a>> = Vec::new();
    for u in per {
        match merged
            .iter_mut()
            .find(|m| m.op == u.op && m.fixed == u.fixed && m.labels == u.labels)
        {
            Some(m) => m.keys.extend(u.keys),
            None => merged.push(u),
        }
    }
    merged
}

fn upgrade_line(lang: Lang, dash: &str, product: &str, u: &Upgrade<'_>) -> String {
    let keys = u.keys.join(" · ");
    let labels = u.labels.join(" · ");
    let n = u.labels.len();
    let fixed = u.fixed;
    if n > 1 {
        lang.pick(
            format!("  {product}{dash}{keys} 의 버전을 {fixed} 이상으로 올리면 이 {n}개 항목이 모두 해결됩니다: {labels}"),
            format!("  {product}{dash}upgrading {keys} to {fixed} or later resolves all {n}: {labels}"),
        )
    } else {
        lang.pick(
            format!("  {product}{dash}{keys} 의 버전을 {fixed} 이상으로 올리면 이 항목이 해결됩니다: {labels}"),
            format!("  {product}{dash}upgrading {keys} to {fixed} or later resolves: {labels}"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 요약의 이음표(그리는 화면) — `deco().dash()` 와 같다.
    const DASH: &str = " — ";

    fn fix(key: &str, op: &str, fixed: &str) -> Fix {
        Fix {
            key: key.into(),
            op: op.into(),
            fixed: fixed.into(),
        }
    }

    /// A → B — 같은 패키지에서 두 룰이 맞으면 높은 판 하나로 둘 다 풀린다(낮은 판을 요구하는 A 는 B 의 판에서 맞지 않는다).
    #[test]
    fn the_higher_fix_on_the_same_install_resolves_both() {
        let a = [fix("php8.2-cli", "pkg_version_lt", "8.2.30-1~deb12u1")];
        let b = [fix("php8.2-cli", "pkg_version_lt", "8.2.35-1~deb12u1")];
        let found = [
            Found {
                label: "A 점검",
                product: "PHP",
                fixes: &a,
            },
            Found {
                label: "B 점검",
                product: "PHP",
                fixes: &b,
            },
        ];
        assert_eq!(
            lines(&found, Lang::Ko, DASH),
            vec!["  PHP — php8.2-cli 의 버전을 8.2.35-1~deb12u1 이상으로 올리면 이 2개 항목이 모두 해결됩니다: A 점검 · B 점검"]
        );
    }

    /// 판으로 보지 않는 발견(설정)은 판 줄 밑에 따로 — 올려도 남는다.
    #[test]
    fn a_finding_not_judged_by_version_is_listed_under_the_upgrade() {
        let v = [fix("php8.2-cli", "pkg_version_lt", "8.2.35-1~deb12u1")];
        let found = [
            Found {
                label: "PHP2Shell 점검",
                product: "PHP",
                fixes: &v,
            },
            Found {
                label: "PHP 세션 점검",
                product: "php",
                fixes: &[],
            },
        ];
        let got = lines(&found, Lang::Ko, DASH);
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(
            got[0].ends_with("올리면 이 항목이 해결됩니다: PHP2Shell 점검"),
            "{got:?}"
        );
        assert_eq!(
            got[1],
            "  PHP — 버전으로 판정하지 않는 항목입니다(올려도 남을 수 있습니다): PHP 세션 점검"
        );
    }

    /// 설치본이 다르면(같은 기계의 7.4 와 8.2) 판의 계열이 달라 높은 쪽으로 합치지 않는다.
    #[test]
    fn different_installs_keep_their_own_fix() {
        let v = [
            fix("php7.4-cli", "pkg_version_lt", "7.4.33-1+deb11u9"),
            fix("php8.2-cli", "pkg_version_lt", "8.2.35-1~deb12u1"),
        ];
        let found = [Found {
            label: "PHP2Shell 점검",
            product: "PHP",
            fixes: &v,
        }];
        let got = lines(&found, Lang::Ko, DASH);
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(
            got[0].contains("php7.4-cli 의 버전을 7.4.33-1+deb11u9 이상으로"),
            "{got:?}"
        );
        assert!(
            got[1].contains("php8.2-cli 의 버전을 8.2.35-1~deb12u1 이상으로"),
            "{got:?}"
        );
    }

    /// 올릴 판과 풀리는 룰이 같은 설치본은 한 줄로 합친다 — 패키지마다 같은 줄이 늘어서지 않게.
    #[test]
    fn packages_with_the_same_upgrade_share_one_line() {
        let v = [
            fix("php8.2-cli", "pkg_version_lt", "8.2.35-1~deb12u1"),
            fix("php8.2-fpm", "pkg_version_lt", "8.2.35-1~deb12u1"),
        ];
        let found = [Found {
            label: "PHP2Shell 점검",
            product: "PHP",
            fixes: &v,
        }];
        let got = lines(&found, Lang::Ko, DASH);
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(
            got[0].contains("php8.2-cli · php8.2-fpm 의 버전을"),
            "{got:?}"
        );
    }

    /// 판으로 풀리는 줄이 없는 제품 · 찾은 것이 없으면 이 묶음은 할 말이 없다.
    #[test]
    fn nothing_to_upgrade_means_no_lines() {
        let found = [Found {
            label: "PHP 세션 점검",
            product: "PHP",
            fixes: &[],
        }];
        assert!(lines(&found, Lang::Ko, DASH).is_empty());
        assert!(lines(&[], Lang::Ko, DASH).is_empty());
    }

    /// 판정이 선 그룹의, 판정식이 짚는 규칙의 증거에서만 고친 판을 뽑는다. 한 증거가 판 비교를 둘 맞혔으면 높은 쪽이다.
    #[test]
    fn fixes_come_from_the_evidence_that_made_the_verdict() {
        let body: ScanBody = serde_json::from_value(serde_json::json!({
            "evidence": [
                { "id": "deb12_vuln#0", "rule": "deb12_vuln", "subject": "package",
                  "target": { "name": "php8.2-cli", "version": "8.2.20-1~deb12u1" },
                  "matched": [
                    { "field": "source", "op": "equals", "value": "php8.2" },
                    { "field": "version", "op": "pkg_version_lt", "value": "8.2.30-1~deb12u1" },
                    { "field": "version", "op": "pkg_version_lt", "value": "8.2.35-1~deb12u1" }
                  ] },
                { "id": "other#0", "rule": "other", "subject": "package",
                  "target": { "name": "php8.2-cli" },
                  "matched": [ { "field": "version", "op": "pkg_version_lt", "value": "9.0" } ] },
                { "id": "deb12_vuln#1", "rule": "deb12_vuln", "subject": "package",
                  "target": { "name": "php8.2-fpm" },
                  "matched": [ { "field": "version", "op": "pkg_version_lt", "value": "8.2.35-1~deb12u1" } ] }
            ],
            "groups": [
                { "id": "g0", "evidence": ["deb12_vuln#0", "other#0"], "verdict": true },
                { "id": "g1", "evidence": ["deb12_vuln#1"], "verdict": false }
            ],
            "verdicts": ["g0"],
            "verdict_rules": ["deb12_vuln"]
        }))
        .expect("시험 결과 본문");
        assert_eq!(
            fixes_of(&body),
            vec![fix("php8.2-cli", "pkg_version_lt", "8.2.35-1~deb12u1")]
        );
    }
}
