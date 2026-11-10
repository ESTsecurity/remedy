//! `remedy-net image` — 이미지 파일(OCI 레이아웃 · OCI 아카이브 · docker save)의 최종 파일 구성에서 PHP · Node.js
//! 를 찾아 PHP2Shell · PHP 세션 설정 · Node.js 기준과 견준다.
//!
//! 사내 runtime-scanner 의 `image` 를 옮겼다. 이미지를 실행하지 않고 네트워크를 쓰지 않는다. 차례: 명령줄 검사 →
//! 약관 → 결과 폴더 → 점검(따로 도는 스레드 · [`crate::scan::run`]) → 화면 · 결과 파일. 앞 단계에서 멈추면 점검도
//! 결과 폴더도 없다.

use crate::cmdline::{self, Arg};
use crate::consent::Answer;
use crate::output::{local_path, DEFAULT_OUT_DIR};
use crate::scan::model::{Product, TargetKind};
use crate::scan::rules::RuleSet;
use crate::scan::run::{self, Engine, Spec};
use crate::text::ascii_safe;
use crate::Outcome;
use remedy_sdk::i18n::Lang;

/// 결과 파일에 싣는 약관 판(문구는 2026-11-10 카드).
pub(crate) const TERMS_VERSION: &str = "2026-11-10.1";
/// 한 실행의 이미지 파일 수 — 스캐너와 같다.
const MAX_INPUTS: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Options {
    pub(crate) inputs: Vec<String>,
    pub(crate) products: Vec<Product>,
    pub(crate) consent: Option<Answer>,
    pub(crate) out_dir: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Parsed {
    Help,
    Run(Options),
}

/// 이미지 파일은 자리 인자로도 `--path` 로도, 옵션은 그 앞뒤 어디에나.
pub(crate) fn parse(args: &[String], lang: Lang) -> Result<Parsed, String> {
    let mut o = Options {
        inputs: Vec::new(),
        products: vec![Product::Php, Product::Node],
        consent: None,
        out_dir: DEFAULT_OUT_DIR.to_string(),
    };
    for arg in cmdline::tokens(args, &[], &["path", "runtime", "consent", "out-dir"], lang)? {
        match arg {
            Arg::Flag(_) => return Ok(Parsed::Help),
            Arg::Positional(p) | Arg::Value("path", p) => push_input(&mut o.inputs, p, lang)?,
            Arg::Value("runtime", v) => o.products = cmdline::runtime(&v, lang)?,
            Arg::Value("consent", v) => o.consent = Some(Answer::parse(&v, lang)?),
            Arg::Value(_, v) => o.out_dir = local_path(v, lang)?,
        }
    }
    if o.inputs.is_empty() {
        return Err(lang
            .t(
                "점검할 이미지 파일을 적으십시오 — remedy-net image 파일 [파일 ...] [옵션]",
                "give the image files to check — remedy-net image FILE [FILE ...] [options]",
            )
            .to_string());
    }
    Ok(Parsed::Run(o))
}

fn push_input(inputs: &mut Vec<String>, raw: String, lang: Lang) -> Result<(), String> {
    if raw.trim().is_empty() || inputs.len() >= MAX_INPUTS {
        return Err(lang
            .t(
                "이미지 파일은 비워 둘 수 없고 50개까지 적을 수 있습니다.",
                "an image file cannot be empty, and at most 50 can be given.",
            )
            .to_string());
    }
    inputs.push(local_path(raw, lang)?);
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
                    format!("입력 오류: {why}\n쓰는 법은 'remedy-net image --help' 로 보십시오."),
                    format!("input error: {why}\nsee 'remedy-net image --help'."),
                ))
            );
            return Outcome::BadInput;
        }
    };
    let rules = RuleSet::builtin();
    let n = o.inputs.len();
    let (inputs, products) = (o.inputs, o.products.clone());
    let engine: Engine = Box::new(move |dir, budget, done| {
        let req = crate::scan::image::Request {
            inputs: &inputs,
            work_dir: dir,
            products: &products,
            rules,
            lang,
        };
        crate::scan::image::scan(&req, budget, done)
    });
    let spec = Spec {
        command: "image",
        kind: TargetKind::Image,
        terms: terms(lang),
        prompt: prompt(lang),
        terms_version: TERMS_VERSION,
        consent: o.consent,
        out_dir: o.out_dir,
        products: o.products,
        rules,
        start: lang.pick(
            format!("점검 시작: 이미지 파일 {n}개 — 실행 전체 10분 · 읽는 양 8 GiB 까지."),
            format!("Checking {n} image file(s) — up to 10 minutes and 8 GiB read for the run."),
        ),
        limitations: limitations(lang),
        lang,
    };
    run::run(spec, engine)
}

pub(crate) fn terms(lang: Lang) -> &'static str {
    lang.t(
        "이용 조건\n\
         1. 소유하거나 점검을 허락받은 이미지에만 쓰십시오.\n\
         2. 지정한 이미지 파일을 읽어 PHP · Node.js 의 일부 취약점과 관련 설정을 점검합니다. 이미지를\n\
         \x20  실행하거나 바꾸지 않고 네트워크를 쓰지 않습니다.\n\
         3. 파일 하나로 받은 이미지는 결과 폴더 아래에 잠시 풀었다가 지웁니다. 이미지 크기만큼 디스크가\n\
         \x20  필요할 수 있습니다.\n\
         4. 결과는 이미지의 최종 파일 구성에 한정됩니다. 양호로 나와도 운영 중인 서비스나 해킹 피해\n\
         \x20  여부를 말하지 않습니다.\n\
         5. 결과는 지정한 폴더에 저장됩니다. 이미지 이름 · 경로 같은 내부 정보가 들어가니 공유하기 전에\n\
         \x20  확인하십시오.\n",
        "Terms of use\n\
         1. Use this only on images you own or are authorized to check.\n\
         2. It reads the image files you give and checks them for some PHP and Node.js vulnerabilities and\n\
         \x20  related settings. It does not run or change the images and does not use the network.\n\
         3. An image given as a single file is unpacked under the result folder for a while and then\n\
         \x20  deleted. This may need as much disk space as the image.\n\
         4. The result covers only the final file layout of the image. A \"clear\" result says nothing\n\
         \x20  about the running service or whether it was compromised.\n\
         5. Results are saved in the folder you choose. They contain internal details such as image names\n\
         \x20  and paths — review them before sharing.\n",
    )
}

pub(crate) fn prompt(lang: Lang) -> &'static str {
    lang.t(
        "점검 권한이 있고 위 내용에 동의하십니까? [y/n]: ",
        "Are you authorized to check these images, and do you agree to the above? [y/n]: ",
    )
}

fn limitations(lang: Lang) -> Vec<String> {
    [
        lang.t(
            "이미지 결과는 최종 파일 구성에 한정됩니다. 운영 서비스에 적용됐거나 실행 중이라는 뜻은 아닙니다.",
            "An image result covers only its final file layout. It does not mean the image is deployed or running.",
        ),
        lang.t(
            "양호 판정은 점검을 마친 범위와 고른 제품의 대상 CVE 에만 해당합니다. 침해 여부는 판정하지 않습니다.",
            "A clear verdict covers only the checked scope and the target CVEs of the chosen products. Compromise is not assessed.",
        ),
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// `remedy-net image --help`. 명령 설명은 본체의 도움말처럼 해라체다.
pub fn help(lang: Lang) -> String {
    let rules = RuleSet::builtin();
    let (version, issued) = (rules.version(), rules.issued_at());
    let issued = issued.get(..10).unwrap_or(issued);
    lang.pick(
        format!(
            "쓰는 법: remedy-net image 파일 [파일 ...] [옵션]\n\n\
             이미지 파일(OCI 레이아웃 폴더 · OCI 아카이브 · docker save 아카이브, 레이어는 gzip · zstd 도)의 최종\n\
             파일 구성에서 PHP · Node.js 를 찾아 PHP2Shell(CVE-2026-109618 · 109619) · PHP 세션 설정\n\
             (CVE-2026-115560) · Node.js(CVE-2026-111497) 기준과 견준다. 이미지를 실행하지 않고 네트워크를 쓰지\n\
             않는다. 다중 플랫폼 이미지는 플랫폼마다 따로 본다.\n\n\
             옵션:\n\
             \x20 --path 파일        점검할 이미지 파일. 자리 인자와 함께 모두 50개까지\n\
             \x20 --runtime 제품     php · node · all (기본: all)\n\
             \x20 --consent y|n      약관에 미리 답한다(무인 실행). 빼면 묻는다\n\
             \x20 --out-dir 폴더     결과 JSON 을 쓸 폴더 (기본: results). 파일 하나로 받은 이미지는 이 아래에\n\
             \x20                    잠시 풀었다가 지운다\n\n\
             지키는 것: 실행 전체 10분 · 읽는 양 8 GiB · 푼 양 8 GiB · 레이어 256개 · 파일 항목 100,000개.\n\
             기준: {version} ({issued} 발행 · 만료 없음).\n"
        ),
        format!(
            "Usage: remedy-net image FILE [FILE ...] [options]\n\n\
             Finds PHP and Node.js in the final file layout of image files (an OCI layout folder, an OCI archive\n\
             or a docker save archive; gzip and zstd layers too) and compares them with the PHP2Shell\n\
             (CVE-2026-109618 · 109619), PHP session setting (CVE-2026-115560) and Node.js (CVE-2026-111497)\n\
             criteria. The images are not run and the network is not used. A multi-platform image is checked\n\
             per platform.\n\n\
             Options:\n\
             \x20 --path FILE        an image file to check; up to 50 together with positional files\n\
             \x20 --runtime PRODUCT  php · node · all (default: all)\n\
             \x20 --consent y|n      answer the terms in advance (unattended runs); asked if omitted\n\
             \x20 --out-dir DIR      folder for the JSON result (default: results); an image given as a single\n\
             \x20                    file is unpacked below it for a while and then deleted\n\n\
             Limits: 10 minutes per run · 8 GiB read · 8 GiB expanded · 256 layers · 100,000 file entries.\n\
             Criteria: {version} (issued {issued} · no expiry).\n"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Parsed, String> {
        let v: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        parse(&v, Lang::Ko)
    }

    #[test]
    fn files_come_from_positionals_and_path_options_in_order() {
        let Ok(Parsed::Run(o)) = p(&[
            "a.tar",
            "--runtime",
            "node",
            "--path=b.oci",
            "--consent",
            "y",
            "c.tar",
            "--out-dir",
            "out",
        ]) else {
            panic!("거절됐다");
        };
        assert_eq!(o.inputs, vec!["a.tar", "b.oci", "c.tar"]);
        assert_eq!(o.products, vec![Product::Node]);
        assert_eq!(o.consent, Some(Answer::Yes));
        assert_eq!(o.out_dir, "out");
        let Ok(Parsed::Run(d)) = p(&["a.tar"]) else {
            panic!("거절됐다");
        };
        assert_eq!(d.products, vec![Product::Php, Product::Node]);
        assert_eq!(d.out_dir, DEFAULT_OUT_DIR);
    }

    #[test]
    fn bad_input_is_refused_before_anything_runs() {
        assert_eq!(p(&["--help"]), Ok(Parsed::Help));
        assert_eq!(p(&["a.tar", "-h"]), Ok(Parsed::Help));
        for bad in [
            &[][..],
            &[""][..],
            &["--path", ""][..],
            &["\\\\server\\share\\a.tar"][..],
            &["a.tar", "--runtime", "python"][..],
            &["a.tar", "--consent", "Y"][..],
            &["a.tar", "--out-dir", "//server/share"][..],
            &["a.tar", "--list"][..],
        ] {
            assert!(p(bad).is_err(), "{bad:?} 를 받았다");
        }
        let many: Vec<String> = (0..51).map(|i| format!("{i}.tar")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(p(&many).is_err(), "51개를 받았다");
        assert!(p(&many[..50]).is_ok());
    }

    #[test]
    fn help_and_terms_are_bilingual_and_separate() {
        for lang in [Lang::Ko, Lang::En] {
            let h = help(lang);
            assert!(h.contains(RuleSet::builtin().version()), "{h}");
            assert!(!h.contains(terms(lang)));
            assert!(terms(lang).lines().count() >= 6);
        }
        assert!(terms(Lang::Ko).starts_with("이용 조건\n1. "));
        assert!(terms(Lang::En).starts_with("Terms of use\n1. "));
    }
}
