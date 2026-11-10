//! `image` · `container` 의 실행 — 약관 → 결과 폴더 → 점검(따로 도는 스레드) → 화면 · 결과 파일.
//!
//! `url` 과 같은 차례다. 앞 단계에서 멈추면 점검도 결과 폴더도 없다. 점검 스레드는 끝난 대상을 하나씩 넘기고
//! (바로 화면에 낸다), Ctrl+C 나 실행 시한이 오면 0.5초를 더 기다린 뒤 그때까지 본 것으로 보고한다 — 막힌
//! 읽기를 끝까지 기다리지 않는다. 다 끝낸 대상은 그 모양대로 싣고, 끝내지 못한 대상에는 멈춘 까닭을 *보지 못한
//! 것* 으로 달고, 마지막에 *점검을 마치지 못한 범위* 를 하나 더 싣는다 — 멈춘 실행이 양호로 끝나지 않는다.

use super::budget::{Budget, Cancel, Halt, Usage};
use super::model::{aggregate, Product, Status, Target, TargetKind};
use super::report::{self, Consent, Criteria, Report, Tool};
use super::rules::RuleSet;
use crate::consent::{self, Answer};
use crate::output::{fail, prepare_dir, run_id, save_json};
use crate::text::ascii_safe;
use crate::{clock, Outcome};
use remedy_sdk::i18n::Lang;
use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant, SystemTime};

/// 화면 고리가 깨어나 취소 · 시한을 보는 간격.
const SLICE: Duration = Duration::from_millis(100);
/// 취소 · 시한 뒤 점검 스레드를 기다리는 시간 — 넘으면 남긴 부분 결과로 보고한다.
const GRACE: Duration = Duration::from_millis(500);
/// 길게 도는 점검의 진행 줄 간격.
const PROGRESS: Duration = Duration::from_secs(5);

/// 한 명령의 실행 조건.
pub(crate) struct Spec {
    /// `image` · `container` — 결과 파일 이름과 `command` 칸.
    pub(crate) command: &'static str,
    pub(crate) kind: TargetKind,
    pub(crate) terms: &'static str,
    pub(crate) prompt: &'static str,
    pub(crate) terms_version: &'static str,
    pub(crate) consent: Option<Answer>,
    pub(crate) out_dir: String,
    pub(crate) products: Vec<Product>,
    pub(crate) rules: &'static RuleSet,
    /// 점검을 시작하며 내는 줄.
    pub(crate) start: String,
    /// 끝에 화면에 내고 결과 파일의 `limitations` 에도 싣는 문장.
    pub(crate) limitations: Vec<String>,
    pub(crate) lang: Lang,
}

/// 점검 — 결과 폴더(이미지 아카이브를 잠시 풀 자리)와 예산을 받아, 끝낸 대상마다 `done` 을 부르고 모든 대상을
/// 돌려준다. 끝내지 못한 대상의 지금 모양은 [`Budget::record_target`] 으로 남긴다.
pub(crate) type Engine =
    Box<dyn FnOnce(&Path, &Budget, &mut dyn FnMut(&Target)) -> Vec<Target> + Send>;

enum Msg {
    Done(Target),
    Finished(Vec<Target>),
}

/// 표준 입출력과 Ctrl+C 로 돈다.
pub(crate) fn run(spec: Spec, engine: Engine) -> Outcome {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    execute(
        spec,
        engine,
        &mut stdin.lock(),
        &mut out,
        Cancel::default(),
        true,
    )
}

/// [`run`] 의 몸. `arm` 이 참이면 결과 폴더를 만든 뒤에 Ctrl+C 를 `cancel` 에 잇는다 — 약관을 묻는 동안의
/// Ctrl+C 는 프로그램을 그대로 끝낸다.
fn execute(
    spec: Spec,
    engine: Engine,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    cancel: Cancel,
    arm: bool,
) -> Outcome {
    let lang = spec.lang;
    let Some(via) = consent::ask(spec.terms, spec.prompt, spec.consent, lang, input, out) else {
        let _ = writeln!(
            out,
            "{}",
            lang.t("점검을 취소했습니다.", "Check cancelled.")
        );
        return Outcome::BadInput;
    };
    let accepted_at = SystemTime::now();
    let dir = match prepare_dir(Path::new(&spec.out_dir), lang) {
        Ok(d) => d,
        Err(why) => return fail(lang, why),
    };
    if arm {
        let c = cancel.clone();
        let _ = ctrlc::set_handler(move || c.set());
    }
    let started = SystemTime::now();
    let budget = Arc::new(Budget::new(spec.kind, cancel, lang));
    let _ = writeln!(out, "{}", ascii_safe(spec.start.clone()));
    let (tx, rx) = mpsc::channel::<Msg>();
    {
        let (budget, dir) = (Arc::clone(&budget), dir.clone());
        std::thread::spawn(move || {
            let all = engine(&dir, &budget, &mut |t: &Target| {
                let _ = tx.send(Msg::Done(t.clone()));
            });
            let _ = tx.send(Msg::Finished(all));
        });
    }
    let mut shown: Vec<Target> = Vec::new();
    let mut finished: Option<Vec<Target>> = None;
    let mut halt: Option<Halt> = None;
    let mut grace: Option<Instant> = None;
    let mut next_progress = Instant::now() + PROGRESS;
    loop {
        match rx.recv_timeout(SLICE) {
            Ok(Msg::Done(t)) => {
                show(out, &t, shown.len() + 1, lang);
                shown.push(t);
            }
            Ok(Msg::Finished(all)) => {
                finished = Some(all);
                break;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if halt.is_none() {
            halt = budget.halted();
            if halt.is_some() {
                grace = Some(Instant::now() + GRACE);
            }
        }
        if grace.is_some_and(|g| Instant::now() >= g) {
            break;
        }
        if halt.is_none() && Instant::now() >= next_progress {
            let _ = writeln!(out, "{}", progress(spec.kind, &budget.usage(), lang));
            next_progress += PROGRESS;
        }
    }
    // 점검 스레드가 취소 뒤 유예보다 먼저 끝나 위 줄에 닿지 못했어도, 멈춘 실행은 멈췄다고 적는다.
    if halt.is_none() {
        halt = budget.halted();
    }
    let seen: HashSet<String> = shown.iter().map(|t| t.id.clone()).collect();
    let targets = match (finished, halt) {
        (Some(all), None) => {
            // 끝난 대상을 넘기지 않은 점검이 있어도 화면에서 빠지지 않게 한다.
            let mut n = shown.len();
            for t in all.iter().filter(|t| !seen.contains(&t.id)) {
                n += 1;
                show(out, t, n, lang);
            }
            all
        }
        (finished, Some(h)) => {
            let why = stopped(h, lang);
            let rest: Vec<Target> = match finished {
                Some(all) => all
                    .into_iter()
                    .filter(|t| !seen.contains(&t.id))
                    .map(|mut t| {
                        t.add_gap(why.clone());
                        t.reason.clear();
                        t.action.clear();
                        t.finalize(lang);
                        t
                    })
                    .collect(),
                None => budget
                    .partial_targets(&why)
                    .into_iter()
                    .filter(|t| !seen.contains(&t.id))
                    .collect(),
            };
            let mut ts = shown;
            for t in rest
                .into_iter()
                .chain(std::iter::once(pending(spec.kind, &why, lang)))
            {
                show(out, &t, ts.len() + 1, lang);
                ts.push(t);
            }
            ts
        }
        (None, None) => {
            return fail(
                lang,
                lang.t(
                    "점검이 끝나기 전에 멈췄습니다.",
                    "the check stopped before it finished.",
                ),
            )
        }
    };
    let interrupted = halt.is_some();
    let ctx = Finish {
        spec: &spec,
        via: via.as_str(),
        accepted_at,
        started,
        dir: &dir,
    };
    ctx.finish(targets, interrupted, budget.usage(), out)
}

struct Finish<'a> {
    spec: &'a Spec,
    via: &'static str,
    accepted_at: SystemTime,
    started: SystemTime,
    dir: &'a Path,
}

impl Finish<'_> {
    fn finish(
        &self,
        targets: Vec<Target>,
        interrupted: bool,
        usage: Usage,
        out: &mut dyn Write,
    ) -> Outcome {
        let spec = self.spec;
        let lang = spec.lang;
        let verdict = aggregate(&targets);
        let outcome = match verdict {
            Status::Clear => Outcome::Clear,
            Status::Vulnerable => Outcome::Vulnerable,
            Status::ReviewRequired => Outcome::Review,
        };
        // 다 보았는데 근거가 모자란 것과 다 보지 못한 것은 결과 줄이 다르다.
        let all_seen = !interrupted && targets.iter().all(|t| t.complete);
        let report = Report {
            schema_version: report::SCHEMA_VERSION,
            tool: Tool {
                name: "remedy-net".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            command: spec.command.to_string(),
            run_id: run_id(self.started),
            language: lang.id().to_string(),
            started_at: clock::rfc3339(self.started),
            finished_at: clock::rfc3339(SystemTime::now()),
            consent: Consent {
                terms_version: spec.terms_version.to_string(),
                accepted_at: clock::rfc3339(self.accepted_at),
                via: self.via.to_string(),
            },
            criteria: Criteria::of(spec.rules, &spec.products),
            products: spec.products.clone(),
            verdict,
            exit_code: outcome.exit().code(),
            interrupted,
            targets,
            usage,
            limitations: spec.limitations.clone(),
        };
        let _ = writeln!(out);
        for line in &spec.limitations {
            let _ = writeln!(out, "{}", ascii_safe(line.clone()));
        }
        let _ = writeln!(
            out,
            "{}",
            ascii_safe(remedy_report::result_line_for(
                outcome.exit(),
                0,
                lang,
                Some(remedy_sdk::manifest::PluginKind::Check),
                all_seen,
            ))
        );
        match save_json(self.dir, spec.command, &report.run_id, &report) {
            Ok(path) => {
                let _ = writeln!(
                    out,
                    "{}: {}",
                    lang.t("결과 파일", "Report"),
                    ascii_safe(path.display().to_string())
                );
                outcome
            }
            Err(_) => fail(
                lang,
                lang.t(
                    "결과 파일을 쓰지 못했습니다.",
                    "could not write the report file.",
                ),
            ),
        }
    }
}

fn show(out: &mut dyn Write, t: &Target, n: usize, lang: Lang) {
    let _ = write!(out, "{}", ascii_safe(report::render(t, n, lang)));
}

/// 멈춘 까닭 — 끝내지 못한 대상의 *보지 못한 것* 이 된다.
fn stopped(halt: Halt, lang: Lang) -> String {
    match halt {
        Halt::Cancelled => lang
            .t(
                "사용자가 취소해 점검을 멈췄습니다.",
                "Stopped: cancelled by the user.",
            )
            .to_string(),
        other => {
            let why = other.message(lang);
            lang.pick(
                format!("점검을 멈췄습니다: {why}"),
                format!("Stopped: {why}"),
            )
        }
    }
}

/// 멈춘 실행에 마지막으로 싣는 대상 — 어디까지 보았는지 확인하지 못한 범위.
fn pending(kind: TargetKind, why: &str, lang: Lang) -> Target {
    let mut t = Target::new(
        "interrupted-scope",
        kind,
        lang.t("점검을 마치지 못한 범위", "unfinished scope"),
        &[],
    );
    t.add_gap(why);
    t.add_scope(lang.t(
        "지정한 대상 가운데 점검이 끝났는지 확인하지 못한 범위",
        "the part of the given targets that could not be confirmed as checked",
    ));
    t.reason = why.to_string();
    t.action = lang
        .t(
            "멈춘 까닭을 확인한 뒤 같은 대상으로 다시 점검하십시오.",
            "Check why it stopped, then run the same check again.",
        )
        .to_string();
    t.finalize(lang);
    t
}

/// 길게 도는 점검의 진행 줄.
fn progress(kind: TargetKind, u: &Usage, lang: Lang) -> String {
    let mib = |b: u64| b as f64 / f64::from(1u32 << 20);
    match kind {
        TargetKind::Image => lang.pick(
            format!(
                "점검 중 — 읽은 양 {:.1} MiB · 푼 양 {:.1} MiB · 파일 항목 {}개",
                mib(u.image_input_bytes),
                mib(u.image_expanded_bytes),
                u.entries
            ),
            format!(
                "checking — read {:.1} MiB · expanded {:.1} MiB · {} file entries",
                mib(u.image_input_bytes),
                mib(u.image_expanded_bytes),
                u.entries
            ),
        ),
        TargetKind::Container => lang.pick(
            format!(
                "점검 중 — 컨테이너 API {}회 · 받은 양 {:.1} MiB",
                u.container_requests,
                mib(u.container_bytes)
            ),
            format!(
                "checking — {} container API requests · received {:.1} MiB",
                u.container_requests,
                mib(u.container_bytes)
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::model::{Evidence, Finding};

    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "remedy-net-run-{name}-{}-{}",
            std::process::id(),
            run_id(SystemTime::now())
        ))
    }

    fn spec(out: &Path, consent: Option<Answer>) -> Spec {
        Spec {
            command: "image",
            kind: TargetKind::Image,
            terms: "이용 조건\n1. 시험.\n",
            prompt: "동의하십니까? [y/n]: ",
            terms_version: "시험",
            consent,
            out_dir: out.to_string_lossy().into_owned(),
            products: vec![Product::Php],
            rules: RuleSet::builtin(),
            start: "점검 시작".to_string(),
            limitations: vec!["한정 문장".to_string()],
            lang: Lang::Ko,
        }
    }

    fn target(id: &str, status: Status) -> Target {
        let mut t = Target::new(id, TargetKind::Image, id, &[Product::Php]);
        if status != Status::Clear {
            t.findings.push(Finding {
                product: Product::Php,
                id: format!("{id}:f"),
                name: "PHP 이미지 파일".to_string(),
                path: Some("/usr/local/bin/php".to_string()),
                version: Some("8.3.35".to_string()),
                package: None,
                vendor: None,
                runtime: None,
                cves: Vec::new(),
                status,
                reason: "시험".to_string(),
                action: String::new(),
                evidence: vec![Evidence::new("시험", "시험")],
            });
        }
        t.finalize(Lang::Ko);
        t
    }

    fn go(spec: Spec, engine: Engine, typed: &str, cancel: Cancel) -> (Outcome, String) {
        let mut out = Vec::new();
        let got = execute(spec, engine, &mut typed.as_bytes(), &mut out, cancel, false);
        (got, String::from_utf8(out).unwrap())
    }

    fn report_in(dir: &Path) -> serde_json::Value {
        let file = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.to_string_lossy().contains("remedy-net-image-"))
            .expect("결과 파일이 없다");
        serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap()
    }

    #[test]
    fn declining_runs_nothing_and_makes_no_folder() {
        let dir = scratch("declined");
        let engine: Engine = Box::new(|_, _, _| panic!("동의하지 않았는데 점검했다"));
        let (got, out) = go(spec(&dir, None), engine, "n\n", Cancel::default());
        assert_eq!(got, Outcome::BadInput);
        assert!(out.contains("점검을 취소했습니다."));
        assert!(!dir.exists());
    }

    #[test]
    fn a_finished_check_is_shown_and_saved_with_the_aggregate_verdict() {
        for (status, outcome, code) in [
            (Status::Clear, Outcome::Clear, 0),
            (Status::ReviewRequired, Outcome::Review, 6),
            (Status::Vulnerable, Outcome::Vulnerable, 2),
        ] {
            let dir = scratch("finished");
            let engine: Engine = Box::new(move |_, _, done| {
                let t = target("image-a", status);
                done(&t);
                vec![t]
            });
            let (got, out) = go(spec(&dir, Some(Answer::Yes)), engine, "", Cancel::default());
            assert_eq!(got, outcome, "{out}");
            assert_eq!(out.matches("[1] image-a").count(), 1, "{out}");
            assert!(out.contains("한정 문장"));
            assert!(out.contains("결과 파일: "));
            let r = report_in(&dir);
            assert_eq!(r["exit_code"], code);
            assert_eq!(r["command"], "image");
            assert_eq!(r["interrupted"], false);
            assert_eq!(r["consent"]["via"], "flag");
            assert_eq!(r["criteria"]["version"], RuleSet::builtin().version());
            assert_eq!(r["targets"].as_array().unwrap().len(), 1);
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn a_target_the_engine_did_not_announce_is_still_shown() {
        let dir = scratch("unannounced");
        let engine: Engine = Box::new(|_, _, _| vec![target("image-b", Status::Clear)]);
        let (got, out) = go(spec(&dir, Some(Answer::Yes)), engine, "", Cancel::default());
        assert_eq!(got, Outcome::Clear);
        assert!(out.contains("[1] image-b"), "{out}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// 취소 뒤에도 돌아오지 않는 점검 — 0.5초 뒤 남긴 모양으로 보고한다. 다 끝낸 대상은 그대로, 끝내지 못한
    /// 대상에는 까닭이 붙고, 마치지 못한 범위가 하나 더 실린다.
    #[test]
    fn a_stuck_check_is_reported_from_what_it_left() {
        let dir = scratch("stuck");
        let cancel = Cancel::default();
        let trigger = cancel.clone();
        let engine: Engine = Box::new(move |_, budget, done| {
            let first = target("image-done", Status::Clear);
            done(&first);
            let mut second = target("image-half", Status::Vulnerable);
            second.add_gap("레이어 둘째를 읽는 중");
            budget.record_target(&second);
            trigger.set();
            std::thread::sleep(Duration::from_secs(5));
            vec![first, second]
        });
        let t0 = Instant::now();
        let (got, out) = go(spec(&dir, Some(Answer::Yes)), engine, "", cancel);
        assert!(
            t0.elapsed() < Duration::from_secs(4),
            "막힌 점검을 기다렸다"
        );
        // 끝내지 못한 대상의 확인된 취약은 남는다.
        assert_eq!(got, Outcome::Vulnerable, "{out}");
        let r = report_in(&dir);
        assert_eq!(r["interrupted"], true);
        let ids: Vec<&str> = r["targets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["image-done", "image-half", "interrupted-scope"]);
        assert_eq!(r["targets"][0]["status"], "clear");
        let half_gaps = r["targets"][1]["gaps"].as_array().unwrap();
        assert!(half_gaps
            .iter()
            .any(|g| g.as_str().unwrap().contains("사용자가 취소해")));
        assert!(out.contains("[3] 점검을 마치지 못한 범위"), "{out}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// 취소를 보고 스스로 돌아온 점검 — 돌려준 것 가운데 화면에 나오지 않은 것에 까닭이 붙는다.
    #[test]
    fn a_check_that_returns_after_cancelling_is_still_marked_unfinished() {
        let dir = scratch("returned");
        let cancel = Cancel::default();
        let trigger = cancel.clone();
        let engine: Engine = Box::new(move |_, budget, _| {
            trigger.set();
            assert!(budget.check().is_err());
            vec![target("image-c", Status::Clear)]
        });
        let (got, out) = go(spec(&dir, Some(Answer::Yes)), engine, "", cancel);
        assert_eq!(got, Outcome::Review, "{out}");
        let r = report_in(&dir);
        assert_eq!(r["targets"][0]["status"], "review_required");
        assert_eq!(r["targets"][1]["id"], "interrupted-scope");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_target_at_all_needs_review() {
        let dir = scratch("empty");
        let engine: Engine = Box::new(|_, _, _| Vec::new());
        let (got, _) = go(spec(&dir, Some(Answer::Yes)), engine, "", Cancel::default());
        assert_eq!(got, Outcome::Review);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_file_where_the_folder_should_be_fails_before_checking() {
        let base = scratch("file");
        std::fs::create_dir_all(&base).unwrap();
        let file = base.join("taken");
        std::fs::write(&file, b"x").unwrap();
        let engine: Engine = Box::new(|_, _, _| panic!("결과 폴더 없이 점검했다"));
        let (got, _) = go(
            spec(&file, Some(Answer::Yes)),
            engine,
            "",
            Cancel::default(),
        );
        assert_eq!(got, Outcome::Failed);
        std::fs::remove_dir_all(&base).unwrap();
    }
}
