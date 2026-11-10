//! `remedy-net container` — 이 기계의 컨테이너 엔진(Docker · Podman)에 읽기 요청만 보내, 실행 중인 컨테이너의
//! 파일에서 PHP · Node.js 를 찾아 PHP2Shell · PHP 세션 설정 · Node.js 기준과 견준다.
//!
//! 사내 runtime-scanner 의 `container` 를 옮겼다. 컨테이너 안에서 명령을 실행하지 않고, 꺼져 있는 엔진을 띄우지
//! 않는다. 컨테이너에서 읽을 수 있는 파일만 보므로 **양호를 내지 않는다** — 취약(2) 또는 확인 필요(6). 차례:
//! 명령줄 · 엔진 주소의 꼴 검사 → 약관 → 결과 폴더 → 점검(따로 도는 스레드 · [`crate::scan::run`]) → 화면 · 결과
//! 파일. `--list` 는 약관도 결과 폴더도 없이 목록만 낸다.

use crate::cmdline::{self, Arg};
use crate::consent::Answer;
use crate::output::{fail, local_path, DEFAULT_OUT_DIR};
use crate::scan::budget::{Budget, Cancel};
use crate::scan::model::{Product, TargetKind};
use crate::scan::rules::RuleSet;
use crate::scan::run::{self, Engine, Spec};
use crate::text::{ascii_safe, plain};
use crate::Outcome;
use remedy_sdk::i18n::Lang;

/// 결과 파일에 싣는 약관 판(문구는 2026-11-10 카드).
pub(crate) const TERMS_VERSION: &str = "2026-11-10.1";
/// 한 실행의 컨테이너 수 — 스캐너와 같다.
const MAX_IDS: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Options {
    pub(crate) ids: Vec<String>,
    pub(crate) list: bool,
    pub(crate) endpoint: String,
    pub(crate) products: Vec<Product>,
    pub(crate) consent: Option<Answer>,
    pub(crate) out_dir: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Parsed {
    Help,
    Run(Options),
}

/// 컨테이너 ID 는 자리 인자로도 `--id` 로도, 옵션은 그 앞뒤 어디에나. 엔진 주소와 ID 의 꼴은 엔진에 닿기 전에 본다.
pub(crate) fn parse(args: &[String], lang: Lang) -> Result<Parsed, String> {
    let mut o = Options {
        ids: Vec::new(),
        list: false,
        endpoint: crate::scan::container::default_endpoint().to_string(),
        products: vec![Product::Php, Product::Node],
        consent: None,
        out_dir: DEFAULT_OUT_DIR.to_string(),
    };
    let valued = ["id", "endpoint", "runtime", "consent", "out-dir"];
    for arg in cmdline::tokens(args, &["list"], &valued, lang)? {
        match arg {
            Arg::Flag("list") => o.list = true,
            Arg::Flag(_) => return Ok(Parsed::Help),
            Arg::Positional(id) | Arg::Value("id", id) => push_id(&mut o.ids, id, lang)?,
            Arg::Value("endpoint", v) => o.endpoint = v,
            Arg::Value("runtime", v) => o.products = cmdline::runtime(&v, lang)?,
            Arg::Value("consent", v) => o.consent = Some(Answer::parse(&v, lang)?),
            Arg::Value(_, v) => o.out_dir = local_path(v, lang)?,
        }
    }
    if o.list && !o.ids.is_empty() {
        return Err(lang
            .t(
                "--list 는 목록만 냅니다 — 컨테이너 ID 와 함께 쓸 수 없습니다.",
                "--list only lists — it cannot be combined with container IDs.",
            )
            .to_string());
    }
    if !o.list && o.ids.is_empty() {
        return Err(lang
            .t(
                "점검할 컨테이너 ID 를 적으십시오 — remedy-net container ID [ID ...] [옵션] (목록은 --list)",
                "give the container IDs to check — remedy-net container ID [ID ...] [options] (--list lists them)",
            )
            .to_string());
    }
    crate::scan::container::validate_selection(&o.endpoint, &o.ids, lang)?;
    Ok(Parsed::Run(o))
}

fn push_id(ids: &mut Vec<String>, raw: String, lang: Lang) -> Result<(), String> {
    if raw.trim().is_empty() || ids.len() >= MAX_IDS {
        return Err(lang
            .t(
                "컨테이너 ID 는 비워 둘 수 없고 50개까지 적을 수 있습니다.",
                "a container ID cannot be empty, and at most 50 can be given.",
            )
            .to_string());
    }
    ids.push(raw);
    Ok(())
}

pub fn run(args: &[String], lang: Lang) -> Outcome {
    let o = match parse(args, lang) {
        Ok(Parsed::Help) => {
            print!("{}", ascii_safe(help(lang)));
            return Outcome::Clear;
        }
        Ok(Parsed::Run(o)) => o,
        Err(why) => {
            eprintln!(
                "{}",
                ascii_safe(lang.pick(
                    format!(
                        "입력 오류: {why}\n쓰는 법은 'remedy-net container --help' 로 보십시오."
                    ),
                    format!("input error: {why}\nsee 'remedy-net container --help'."),
                ))
            );
            return Outcome::BadInput;
        }
    };
    if o.list {
        return list(&o.endpoint, lang);
    }
    let rules = RuleSet::builtin();
    let n = o.ids.len();
    let (ids, endpoint, products) = (o.ids, o.endpoint, o.products.clone());
    let engine: Engine = Box::new(move |_dir, budget, done| {
        let req = crate::scan::container::Request {
            endpoint: &endpoint,
            ids: &ids,
            products: &products,
            rules,
            lang,
        };
        crate::scan::container::scan(&req, budget, done)
    });
    let spec = Spec {
        command: "container",
        kind: TargetKind::Container,
        terms: terms(lang),
        prompt: prompt(lang),
        terms_version: TERMS_VERSION,
        consent: o.consent,
        out_dir: o.out_dir,
        products: o.products,
        rules,
        start: lang.pick(
            format!("점검 시작: 컨테이너 {n}개 — 엔진 API 요청 128회 · 실행 전체 10분까지."),
            format!("Checking {n} container(s) — up to 128 engine API requests and 10 minutes for the run."),
        ),
        limitations: limitations(lang),
        lang,
    };
    run::run(spec, engine)
}

/// `--list` — 실행 중인 컨테이너를 보여 준다. 점검하지 않으므로 약관도 결과 폴더도 없다.
fn list(endpoint: &str, lang: Lang) -> Outcome {
    let budget = Budget::new(TargetKind::Container, Cancel::default(), lang);
    let found = match crate::scan::container::list(endpoint, &budget, lang) {
        Ok(f) => f,
        Err(why) => return fail(lang, &why),
    };
    println!("{}", lang.t("실행 중인 컨테이너:", "Running containers:"));
    if found.is_empty() {
        println!(
            "{}",
            lang.t("실행 중인 컨테이너가 없습니다.", "No container is running.")
        );
    }
    for c in &found {
        println!("{}  {}", plain(&c.id, 64), plain(&c.name, 200));
    }
    if let Some(first) = found.first() {
        let short = first.id.get(..12).unwrap_or(&first.id);
        println!(
            "{}: remedy-net container {}",
            lang.t("점검 예", "example"),
            plain(short, 12)
        );
    }
    let requests = budget.usage().container_requests;
    println!(
        "{}",
        lang.pick(
            format!("컨테이너 API 요청 {requests}회"),
            format!("{requests} container API request(s)"),
        )
    );
    Outcome::Clear
}

pub(crate) fn terms(lang: Lang) -> &'static str {
    lang.t(
        "이용 조건\n\
         1. 소유하거나 점검을 허락받은 컨테이너에만 쓰십시오.\n\
         2. 이 기계의 컨테이너 엔진(Docker · Podman)에 읽기 요청만 보내 PHP · Node.js 의 일부 취약점과\n\
         \x20  관련 설정을 점검합니다. 컨테이너 안에서 명령을 실행하거나 파일을 바꾸지 않습니다.\n\
         3. 요청하는 동안 엔진과 컨테이너에 부하가 생기고 엔진 기록에 남을 수 있습니다. 꺼져 있는 엔진은\n\
         \x20  띄우지 않습니다.\n\
         4. 컨테이너에서 읽을 수 있는 파일만 보므로 '양호' 를 내지 않습니다. 취약이 나오지 않아도\n\
         \x20  안전하다는 뜻이 아닙니다.\n\
         5. 결과는 지정한 폴더에 저장됩니다. 컨테이너 이름 · 경로 같은 내부 정보가 들어가니 공유하기 전에\n\
         \x20  확인하십시오.\n",
        "Terms of use\n\
         1. Use this only on containers you own or are authorized to check.\n\
         2. It sends only read requests to this machine's container engine (Docker · Podman) and checks for\n\
         \x20  some PHP and Node.js vulnerabilities and related settings. It runs no command inside the\n\
         \x20  containers and changes no file.\n\
         3. The requests add some load on the engine and the containers and may appear in the engine's\n\
         \x20  log. An engine that is not running is not started.\n\
         4. Only the files that can be read from the containers are seen, so the result is never \"clear\".\n\
         \x20  A result without \"vulnerable\" does not mean the container is safe.\n\
         5. Results are saved in the folder you choose. They contain internal details such as container\n\
         \x20  names and paths — review them before sharing.\n",
    )
}

pub(crate) fn prompt(lang: Lang) -> &'static str {
    lang.t(
        "점검 권한이 있고 위 내용에 동의하십니까? [y/n]: ",
        "Are you authorized to check these containers, and do you agree to the above? [y/n]: ",
    )
}

fn limitations(lang: Lang) -> Vec<String> {
    vec![lang
        .t(
            "컨테이너 결과는 엔진에서 읽을 수 있었던 파일에 한정되어 '양호' 를 내지 않습니다. 침해 여부는 판정하지 않습니다.",
            "A container result covers only the files that could be read through the engine, so it is never \"clear\". Compromise is not assessed.",
        )
        .to_string()]
}

/// `remedy-net container --help`. 명령 설명은 본체의 도움말처럼 해라체다.
pub fn help(lang: Lang) -> String {
    let rules = RuleSet::builtin();
    let (version, issued) = (rules.version(), rules.issued_at());
    let issued = issued.get(..10).unwrap_or(issued);
    let endpoint = crate::scan::container::default_endpoint();
    lang.pick(
        format!(
            "쓰는 법: remedy-net container 컨테이너ID [ID ...] [옵션]\n\
             \x20       remedy-net container --list [--endpoint 주소]\n\n\
             이 기계의 컨테이너 엔진(Docker · Podman)에 읽기 요청만 보내, 실행 중인 컨테이너의 파일에서 PHP ·\n\
             Node.js 를 찾아 PHP2Shell(CVE-2026-109618 · 109619) · PHP 세션 설정(CVE-2026-115560) · Node.js\n\
             (CVE-2026-111497) 기준과 견준다. 컨테이너 안에서 명령을 실행하지 않고, 꺼져 있는 엔진을 띄우지 않는다.\n\
             읽을 수 있는 파일만 보므로 '양호' 는 내지 않는다 — 취약(2) 또는 확인 필요(6).\n\n\
             옵션:\n\
             \x20 --id ID            점검할 컨테이너 ID(16진수 12~64자). 자리 인자와 함께 모두 50개까지\n\
             \x20 --list             실행 중인 컨테이너를 보여 준다(점검하지 않아 약관 · 결과 폴더가 없다)\n\
             \x20 --endpoint 주소    엔진 주소 (기본: {endpoint})\n\
             \x20 --runtime 제품     php · node · all (기본: all)\n\
             \x20 --consent y|n      약관에 미리 답한다(무인 실행). 빼면 묻는다\n\
             \x20 --out-dir 폴더     결과 JSON 을 쓸 폴더 (기본: results)\n\n\
             지키는 것: 실행 전체 10분 · 엔진 API 요청 128회 · 받는 양 256 MiB · 초당 10 MiB.\n\
             기준: {version} ({issued} 발행 · 만료 없음).\n"
        ),
        format!(
            "Usage: remedy-net container CONTAINER-ID [ID ...] [options]\n\
             \x20      remedy-net container --list [--endpoint ADDRESS]\n\n\
             Sends only read requests to this machine's container engine (Docker · Podman), finds PHP and\n\
             Node.js in the files of running containers and compares them with the PHP2Shell (CVE-2026-109618 ·\n\
             109619), PHP session setting (CVE-2026-115560) and Node.js (CVE-2026-111497) criteria. No command\n\
             is run inside the containers and an engine that is not running is not started. Only readable files\n\
             are seen, so the result is never \"clear\" — vulnerable (2) or needs review (6).\n\n\
             Options:\n\
             \x20 --id ID            a container ID to check (12 to 64 hex digits); up to 50 together with\n\
             \x20                    positional IDs\n\
             \x20 --list             list the running containers (no check, so no terms and no result folder)\n\
             \x20 --endpoint ADDRESS the engine address (default: {endpoint})\n\
             \x20 --runtime PRODUCT  php · node · all (default: all)\n\
             \x20 --consent y|n      answer the terms in advance (unattended runs); asked if omitted\n\
             \x20 --out-dir DIR      folder for the JSON result (default: results)\n\n\
             Limits: 10 minutes per run · 128 engine API requests · 256 MiB received · 10 MiB per second.\n\
             Criteria: {version} (issued {issued} · no expiry).\n"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_and_terms_are_bilingual_and_separate() {
        for lang in [Lang::Ko, Lang::En] {
            let h = help(lang);
            assert!(h.contains(RuleSet::builtin().version()), "{h}");
            assert!(h.contains(crate::scan::container::default_endpoint()));
            assert!(!h.contains(terms(lang)));
        }
        assert!(terms(Lang::Ko).starts_with("이용 조건\n1. "));
        assert!(terms(Lang::En).starts_with("Terms of use\n1. "));
    }
}
