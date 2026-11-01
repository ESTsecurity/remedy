//! `xtask metrics` — 자립률 집계 (설계-01 D10).
//!
//! # 왜 제품 CLI 가 아니라 여기인가
//!
//! 자립률은 **한 실행의 성질이 아니라 추세**다. 계획 하나만 보면 값이 0% 아니면
//! 100% 라 아무것도 말해 주지 않는다. 읽는 사람은 쌓인 실행을 보는 팀이고,
//! 그것은 개발·운영 도구의 자리다. 하위 명령 표(설계-01)에도 이런 명령이 없다.
//!
//! # 입력은 `apply` 가 남긴 계획이다
//!
//! `<state>/plan/<run_id>.json` — `resume` 이 재부팅 뒤에 찾는 그 자리다.
//! 따로 지표용 파일을 만들지 않는다. 만들면 그것을 쓰는 코드와 실제 실행이
//! 갈라지고, 그러면 지표가 실행을 반영하지 않는다.

use std::path::Path;

pub fn run(root: &Path, args: &[String]) -> Result<(), String> {
    let dir = match args.iter().position(|a| a == "--state-dir") {
        Some(i) => args
            .get(i + 1)
            .ok_or("--state-dir 에 값이 없다")?
            .to_string(),
        None => root
            .join("testbed/harness/results")
            .to_string_lossy()
            .into(),
    };
    let lang = match args.iter().position(|a| a == "--lang") {
        Some(i) => remedy_report::Lang::parse(args.get(i + 1).map(String::as_str).unwrap_or("ko")),
        None => remedy_report::Lang::Ko,
    };

    let plans = load_plans(Path::new(&dir))?;
    println!("계획 {}건을 {} 에서 읽었다", plans.len(), dir);
    if plans.is_empty() {
        // **재지 않은 것을 0% 로 접지 않는다.** 표본이 없는 실행이 "자립률
        // 바닥" 으로 읽히면 그 수치가 사람을 잘못된 곳으로 보낸다.
        println!("자립률: 잰 것이 없다 — 계획을 남긴 실행이 없다.");
        println!("  `remedy apply --state-dir <dir>` 이 <dir>/plan/ 에 남긴다.");
        return Ok(());
    }
    let s = remedy_report::self_sufficiency(plans.iter());
    print!("{}", remedy_report::render_self_sufficiency(&s, lang));

    // **세 범주 중 하나만 셀 수 있다는 사실을 감추지 않는다** (설계-01 D10).
    println!();
    println!("여기서 세는 것은 '파괴 동작이 없다' 하나뿐이다 — 미룸이 Op 을");
    println!("이름으로 들기 때문이다. 관찰 대상이 없거나 로직을 표현할 수 없는");
    println!("경우는 룰을 **쓸 수조차 없어** 계획까지 오지 못한다. 그 둘의 입력은");
    println!("사람이 적는 목록이며 그것이 설계-09 P9 의 '없어서 불편한 API' 다.");
    Ok(())
}

/// `<state>/plan/*.json` 을 전부 읽는다.
fn load_plans(state: &Path) -> Result<Vec<remedy_sdk::artifact::PlanEnvelope>, String> {
    let dir = state.join("plan");
    let rd = match std::fs::read_dir(&dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    };
    let mut out = Vec::new();
    let mut paths: Vec<_> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    // 순서를 고정한다. 흔들리면 같은 상태를 두 번 읽은 결과가 달라진다.
    paths.sort();
    for p in paths {
        let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        // **읽지 못한 것을 조용히 건너뛰지 않는다.** 깨진 계획 하나가 분모에서
        // 빠지면 자립률이 실제보다 좋아 보인다.
        let plan = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))?;
        out.push(plan);
    }
    Ok(out)
}
