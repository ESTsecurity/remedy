//! 재평가 결과를 남기는 자리 (설계-03 §8).
//!
//! # 왜 필요한가
//!
//! `verify_after_reboot` 는 재부팅 뒤 `verify` 를 한 번 돌리도록 예약한다. 그
//! 실행에는 **사람이 없다** — RunOnce 는 콘솔 없이 돌고, OS 는 항목을 실행
//! 직전에 지운다.
//!
//! 그래서 결과가 갈 곳이 없었다. 2026-08-29 실기기 측정에서 재부팅 뒤
//! `verify` 가 **실제로 도는 것**을 확인했는데(프로세스 생성 감사 4688),
//! 그 판정이 무엇이었는지는 어디에서도 알 수 없었다:
//!
//! - 콘솔 출력은 아무도 보지 않는다
//! - 종료 코드는 그 프로세스와 함께 사라진다
//! - 파일도 저널도 남지 않는다
//!
//! **설계-03 §5 는 무인 배포에서 종료 코드가 "후속 조치의 트리거" 라고 적는다.**
//! 받는 쪽이 없으면 그 문장이 성립하지 않는다.
//!
//! # 왜 상태 디렉터리인가
//!
//! 그 자리에 이미 이 run 의 나머지가 있다 — `plan/<id>.json`(무엇을 하려 했나) ·
//! `journal/<id>.jsonl`(무엇을 했나) · `quarantine/<id>.rq`(되돌리는 수단).
//! 재평가는 **그 run 에 대한 판정**이므로 같은 자리에 같은 이름으로 붙는다.
//!
//! `--out` 을 예약 명령에 얹는 길도 있었다. 그러면 기록이 **예약된 실행에만**
//! 생기고, 분석가가 손으로 부른 `verify` 는 아무것도 남기지 않는다. 남길지
//! 말지가 부르는 방법에 따라 갈리면 그것은 감사 기록이 아니다.
//!
//! # 덧붙이지 덮어쓰지 않는다
//!
//! 같은 run 을 두 번 재평가할 수 있다 — 예약된 것 한 번, 사람이 한 번. 뒤엣것이
//! 앞엣것을 지우면 **"재부팅 직후에는 무엇이었나"** 를 물을 수 없게 된다.
//!
//! # 다 보지 못했으면 그 관측도 싣는다 (2026-10-26)
//!
//! 재평가가 잘리거나 막혔으면 그 줄에 **무엇을 못 봤는지**(`observation`)가 함께
//! 간다 — 결과와 무관하게(재발 · 잔존과 겹쳐도). 재부팅 회차에는 그것을 물을 사람이
//! 없다. 판정도 남은 증거도 없으면 결과는 `incomplete`(종료 6)다. 온전한 회차의 줄에는
//! 그 필드가 없다. 줄을 글자로 읽는 쪽이 있고, 옛 줄도 그대로 읽혀야 한다.
//!
//! # 여기서 실패해도 재평가는 실패가 아니다
//!
//! 기록하지 못한 것과 판정하지 못한 것은 다르다. 쓰기가 막혔다고 종료 코드를
//! 바꾸면 무인 배포가 **성공한 치료를 실패로 읽는다.**
//!
//! 다만 그 실패는 조용하다 — 예약된 실행에는 stderr 를 읽는 사람도 없다. 즉
//! 소비자는 *"재평가가 안 돌았다"* 와 *"돌았는데 못 적었다"* 를 구분하지 못한다.
//! 두 번째 채널 없이는 닫을 수 없는 틈이고, 여기 적어 둔다.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// 이 run 의 재평가 기록이 사는 곳.
pub fn path(state_dir: &Path, run_id: &str) -> PathBuf {
    state_dir.join("verify").join(format!("{run_id}.jsonl"))
}

/// 재평가 한 번의 결과.
///
/// **종료 코드를 함께 적는다.** 설계-03 §5 가 무인 배포의 트리거로 지목한 것이
/// 그 값이고, 이 파일을 읽는 쪽은 프로세스를 보지 못했으므로 여기서 받아야 한다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyRecord {
    /// RFC3339 UTC.
    pub at: String,
    pub run_id: String,
    pub plugin_id: String,
    pub plugin_version: String,
    /// `clean` · `partial` · `recurred` · `incomplete`(2026-10-26 부터).
    pub outcome: String,
    /// 이 재평가가 프로세스로서 돌려준 값 (설계-02 §8).
    pub exit_code: i32,
    /// 다시 선 판정. 재발일 때만 비어 있지 않다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verdicts: Vec<String>,
    /// 치료 전 증거 중 **아직 남아 있는 것**. 부분 치료의 근거다.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remaining: Vec<String>,
    /// 재평가의 관측 — **온전하지 않을 때만** 싣는다(결정 2026-10-26). 재부팅 회차에는
    /// 사람이 없어 왜 "치료 성공" 을 말하지 못했는지가 이 줄에 있어야 한다.
    /// 온전한 회차의 줄은 전과 같다 — 그 줄을 글자로 읽는 쪽이 있다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<remedy_sdk::artifact::Observation>,
}

/// 한 줄 덧붙인다.
///
/// 디렉터리가 없으면 만든다 — `verify` 는 `apply` 없이도 불릴 수 있고, 그때는
/// 상태 디렉터리에 이 하위 폴더가 아직 없다.
pub fn append(state_dir: &Path, rec: &VerifyRecord) -> Result<PathBuf, String> {
    use std::io::Write;
    let p = path(state_dir, &rec.run_id);
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)
            .map_err(|e| format!("{} 를 만들지 못했습니다: {e}", d.display()))?;
    }
    let mut line = serde_json::to_string(rec).map_err(|e| e.to_string())?;
    line.push('\n');
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&p)
        .map_err(|e| format!("{} 를 열지 못했습니다: {e}", p.display()))?;
    f.write_all(line.as_bytes())
        .map_err(|e| format!("{} 에 쓰지 못했습니다: {e}", p.display()))?;
    Ok(p)
}

/// 적힌 것을 읽는다. **깨진 줄은 건너뛰지 않고 멈춘다** — 감사 기록을 일부만
/// 읽고 전부인 척하면 그 위에서 내린 판단이 근거 없는 것이 된다.
pub fn read(state_dir: &Path, run_id: &str) -> Result<Vec<VerifyRecord>, String> {
    let p = path(state_dir, run_id);
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{} 를 읽지 못했습니다: {e}", p.display())),
    };
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        out.push(
            serde_json::from_str(line)
                .map_err(|e| format!("{}:{} 줄이 깨졌습니다: {e}", p.display(), i + 1))?,
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn lab(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("remedy-verify-log-{name}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn rec(outcome: &str, exit: i32) -> VerifyRecord {
        VerifyRecord {
            at: "2026-08-29T03:06:31Z".into(),
            run_id: "r1".into(),
            plugin_id: "evilai-locust".into(),
            plugin_version: "0.1.0".into(),
            outcome: outcome.into(),
            exit_code: exit,
            verdicts: Vec::new(),
            remaining: Vec::new(),
            observation: None,
        }
    }

    #[test]
    fn an_incomplete_record_says_what_was_not_seen() {
        // 재부팅 회차에는 사람이 없다 — **왜 "치료 성공" 을 말하지 못했는지**가
        // 이 줄에 있어야 다음 판단을 한다(결정 2026-10-26).
        let d = lab("incomplete");
        let mut r = rec("incomplete", 6);
        r.observation = Some(remedy_sdk::artifact::Observation {
            truncated: true,
            ..Default::default()
        });
        append(&d, &r).unwrap();
        let back = read(&d, "r1").unwrap();
        assert_eq!(back[0].outcome, "incomplete");
        assert_eq!(back[0].exit_code, 6);
        assert!(back[0].observation.as_ref().is_some_and(|o| o.truncated));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_complete_record_is_written_as_before() {
        // 완전한 회차의 줄에는 그 필드가 없다 — 이 줄을 글자로 읽는 쪽(리눅스
        // 재부팅 하네스의 glob)이 그대로이고, 옛 줄도 그대로 읽힌다.
        let line = serde_json::to_string(&rec("clean", 0)).unwrap();
        assert!(!line.contains("observation"), "{line}");
        let old = r#"{"at":"t","run_id":"r","plugin_id":"p","plugin_version":"1","outcome":"clean","exit_code":0}"#;
        let back: VerifyRecord = serde_json::from_str(old).unwrap();
        assert!(back.observation.is_none());
    }

    #[test]
    fn a_second_verify_does_not_erase_the_first() {
        // **재부팅 직후에는 무엇이었나** 를 나중에도 물을 수 있어야 한다.
        // 사람이 손으로 한 번 더 부르면 그 답이 사라지면 안 된다.
        let d = lab("append");
        append(&d, &rec("partial", 3)).unwrap();
        append(&d, &rec("clean", 0)).unwrap();

        let all = read(&d, "r1").unwrap();
        assert_eq!(all.len(), 2, "{all:?}");
        assert_eq!(all[0].outcome, "partial");
        assert_eq!(all[0].exit_code, 3);
        assert_eq!(all[1].outcome, "clean");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn nothing_recorded_is_an_empty_list_not_an_error() {
        // 재평가가 아직 없는 run 은 정상이다. 오류로 만들면 부르는 쪽이
        // "없음" 과 "못 읽음" 을 구분하려고 오류 문자열을 파싱하게 된다.
        let d = lab("empty");
        assert!(read(&d, "없는run").unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_broken_line_stops_the_read() {
        // **일부만 읽고 전부인 척하지 않는다.** 감사 기록에서 그것은
        // "재발 기록이 없다" 를 거짓으로 만든다.
        let d = lab("broken");
        append(&d, &rec("clean", 0)).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(path(&d, "r1"))
            .unwrap()
            .write_all("{ 이건 JSON 이 아니다\n".as_bytes())
            .unwrap();

        let e = read(&d, "r1").expect_err("멈춰야 한다");
        assert!(e.contains("2 줄이 깨졌습니다"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_record_carries_why_not_just_what() {
        // 판정만 있으면 "재발했다" 까지만 알 수 있다. 무엇이 다시 섰는지가
        // 있어야 사람이 다음 판단을 한다 (설계-03 §8 — 자동 재치료는 하지 않는다).
        let d = lab("why");
        let mut r = rec("recurred", 2);
        r.verdicts = vec!["locust".into()];
        r.remaining = vec!["ev-task".into(), "ev-payload".into()];
        append(&d, &r).unwrap();

        let back = read(&d, "r1").unwrap();
        assert_eq!(back[0].verdicts, vec!["locust".to_string()]);
        assert_eq!(back[0].remaining.len(), 2);
        let _ = std::fs::remove_dir_all(&d);
    }
}
