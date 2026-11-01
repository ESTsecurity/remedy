//! 저널 — **자동 롤백을 위한 것이 아니다** (설계-03 §5).
//!
//! 파일·레지스트리·작업에 걸친 진짜 원자성은 불가능하다. 그래서 fsync 된
//! append-only 저널을 쓰되, 그 목적은 **복원 가능성의 보장과 정확한 상태 보고**다.
//!
//! ```text
//!   각 Action 마다:  intent -> backup -> outcome
//! ```
//!
//! # 왜 되돌리지 않는가
//!
//! 로더와 페이로드를 지우는 계획에서 로더는 지워졌고 페이로드 삭제가 실패했다고
//! 하자. 여기서 롤백하면 **로더가 복원되어 위협이 재무장된다.** 절반만 제거된
//! 상태가 위험한 것은 사실이지만, 온전한 악성코드로 되돌리는 것보다는 낫다.
//! 데이터 트랜잭션의 직관("전부 아니면 전무")을 위협 제거에 그대로 옮기면 안 된다.
//!
//! 되돌리기는 **사람의 결정**이며 `remedy restore` 로만 일어난다.
//!
//! # 잘려도 읽힌다
//!
//! 크래시는 쓰기 도중에 온다. 한 줄이 반만 쓰인 채 끝나면 그 줄만 버리고 **마지막
//! 완료 지점**을 말할 수 있어야 한다. 저널을 통째로 못 읽게 되면 "무엇까지 했는가"
//! 를 영영 알 수 없고, 그러면 이어서 수행할 수도 되돌릴 수도 없다.
#![forbid(unsafe_code)]

use remedy_sdk::catalog::Op;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub const CRATE_NAME: &str = "remedy-journal";

/// 이 실행의 저널이 놓이는 곳.
///
/// **경로를 규약으로 못 박는다.** 실행기가 제 마음대로 정하면 크래시 후
/// 재기동한 다른 코드가 그것을 찾지 못하고, 그러면 "무엇까지 했는가" 를 영영
/// 알 수 없다. 격리 컨테이너가 `<state>/quarantine/<run_id>.rq` 인 것과 같은
/// 자리에 둔다.
pub fn journal_path(state_dir: &Path, run_id: &str) -> PathBuf {
    state_dir.join("journal").join(format!("{run_id}.jsonl"))
}

/// 아직 끝나지 않은 실행의 저널들.
///
/// 재기동한 실행기가 **이어서 수행할 것**을 찾는 자리다. 끝난 실행(`End` 기록이
/// 있는 것)은 제외한다.
pub fn unfinished(state_dir: &Path) -> std::io::Result<Vec<(String, Reading)>> {
    let dir = state_dir.join("journal");
    let rd = match std::fs::read_dir(&dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) != Some("jsonl") {
            continue;
        }
        let run_id = match p.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let reading = Journal::read(&p)?;
        if !reading.finished() {
            out.push((run_id, reading));
        }
    }
    // 순서가 흔들리면 같은 상태를 두 번 읽은 결과가 달라진다.
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// 저널에 남는 한 줄.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rec", rename_all = "snake_case")]
pub enum Record {
    /// 실행이 시작됐다. 어느 계획을 근거로 도는지 남긴다.
    Start {
        run_id: String,
        plugin_id: String,
        /// 계획 파일의 해시. **승인한 계획과 실제로 수행한 계획이 같은가**를
        /// 나중에 물을 수 있어야 한다.
        plan_sha256: String,
        created: String,
        /// **어떤 바이너리가 이 기계를 고쳤는가** — `verified`·`unsigned`·
        /// `unknown` (`SelfIntegrity::id`).
        ///
        /// 2026-09-02 에 서명 없는 배포 빌드도 파괴를 하게 됐다. 통제를 하나
        /// 뺐으면 **흔적은 남겨야 한다** — 그 전까지 이 사실은 `support-bundle`
        /// 에만 있었고 그것은 *지금* 그 자리에 있는 파일을 재므로, 나중에
        /// 바이너리가 바뀌면 치료 당시와 다른 값을 보고한다.
        ///
        /// `Option` 인 이유는 **옛 저널을 계속 읽기 위해서**다. 이 줄이 없는
        /// 기록은 그 시절의 것이고, 없는 것을 `unknown` 으로 적으면 "검사했는데
        /// 몰랐다" 와 구분되지 않는다.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        self_integrity: Option<String>,
    },
    /// 이 Action 을 하려 한다. **수행 전에** 쓴다.
    ///
    /// `op` 는 문자열이 아니라 `Op` 다. 감사 로그가 계획과 **같은 어휘**를 써야
    /// 하고(설계-03 §7), 문자열이면 오타가 컴파일에 걸리지 않는다. `Action.op`
    /// 도 `Op` 이므로 실행기가 그대로 옮겨 적을 수 있다.
    Intent { seq: u32, op: Op, target: String },
    /// 백업이 끝났다. 이 줄이 없으면 그 Action 은 되돌릴 수 없다.
    Backup { seq: u32, entry_id: String },
    /// 수행 결과.
    Outcome {
        seq: u32,
        #[serde(flatten)]
        outcome: Outcome,
    },
    /// 실행이 끝났다.
    End { run_id: String, at: String },
    /// **크래시 뒤에 이어받았다.** 이 줄 위와 아래는 서로 다른 프로세스가 썼다.
    ///
    /// 없어도 이어서 수행할 수는 있다. 그런데 감사 로그를 읽는 사람이 같은
    /// `seq` 의 `Backup` 이 두 번 나오는 것을 보고 **실행기가 백업을 두 번 했다**
    /// 고 읽는다. 시도의 경계를 적어 두면 그 오해가 생기지 않는다 (설계-03 §7).
    Resumed {
        run_id: String,
        at: String,
        /// 이어받을 때 이미 있던 줄 수. 이 줄 위로 몇 줄이 이전 시도의 것인가.
        after_records: usize,
    },
    /// Action 에 붙지 않는 사실. **하려 했으나 하지 못한 것**이 여기 남는다.
    ///
    /// 복원 지점 생성이 그 첫 자리다 — 실패해도 치료는 진행하지만(설계-00 §5-2),
    /// 실패한 사실이 남지 않으면 나중에 "복원 지점이 있는 줄 알았다" 가 된다.
    Note { text: String },
    /// **우리가 심은 자동실행** — 재부팅 뒤 재검사 예약 (설계-03 §8 자기 흔적
    /// 규칙 3 · P12).
    ///
    /// 치료 도구가 남긴 자동실행이 감사 로그에 없으면, 나중에 그 항목을 본
    /// 사람(타 백신 포함)이 *"누가 왜 심었나"* 를 물을 곳이 없다. 한동안 이 사실은
    /// 화면(`run.log`)에만 있었다.
    ///
    /// **`End` 앞에 온다.** 마지막 줄이 `End` 여야 끝난 회차다
    /// ([`Reading::finished`]) — 뒤에 적으면 끝난 회차가 이어받기 대상으로
    /// 되살아난다.
    VerifyScheduled {
        /// 걸린 자리 — RunOnce 값 · 유닛 파일. 백엔드가 말하지 않으면 없다.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        location: Option<String>,
        /// 실행 직전에 그 항목을 지우는 주체 — `os` · `itself` (규칙 2).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        removed_by: Option<String>,
        /// 재부팅 뒤 돌 명령줄 그대로.
        command: String,
    },
    /// 재부팅 뒤 재검사를 **걸지 못했다** — 그 이유. 계획이 원했는데 걸리지
    /// 않은 것도 이 회차가 한 일의 일부다.
    VerifyNotScheduled { reason: String },
}

/// 한 Action 의 결과. **둘뿐이다** — 재부팅 뒤 재시도(설계-03 §5 의 큐)는 v1 에
/// 없다. 파괴 실패는 `Failed` 로 남고 부분 치료로 보고된다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    Done,
    Failed { reason: String },
}

/// 읽어 들인 저널.
#[derive(Debug, Clone, Default)]
pub struct Reading {
    pub records: Vec<Record>,
    /// 마지막 줄이 온전하지 않았는가. **크래시의 흔적이다.**
    pub truncated: bool,
    /// 온전하게 읽힌 바이트 수. 이어 쓰려면 여기부터다.
    pub complete_bytes: u64,
}

impl Reading {
    /// 이 저널이 **어느 계획**을 근거로 열렸는가.
    ///
    /// 이어받을 때 지금 들어온 계획과 대조하는 자리다. run_id 는 같은데 내용이
    /// 다른 계획으로 이어받으면, 수행된 결과는 사용자가 승인한 어느 계획과도
    /// 다른 것이 된다.
    pub fn plan_sha256(&self) -> Option<&str> {
        self.records.iter().find_map(|r| match r {
            Record::Start { plan_sha256, .. } => Some(plan_sha256.as_str()),
            _ => None,
        })
    }

    /// 하려 한다고 적힌 Action.
    ///
    /// 이어받은 실행이 **빠진 것만** 채워 넣는 자리다. 크래시가 `Start` 와 첫
    /// `Intent` 사이에 오면 저널은 "무엇을 하려던 참이었는가" 를 말하지 못한다.
    pub fn intended(&self) -> BTreeSet<u32> {
        self.records
            .iter()
            .filter_map(|r| match r {
                Record::Intent { seq, .. } => Some(*seq),
                _ => None,
            })
            .collect()
    }

    /// 백업이 끝난 Action.
    ///
    /// **집합이다.** 이어받은 실행이 백업 단계를 다시 돌면 같은 `seq` 의 `Backup`
    /// 이 두 번 적히는데, 그것은 백업이 두 번 끝났다는 뜻이지 대상이 둘이라는
    /// 뜻이 아니다.
    pub fn backed_up(&self) -> BTreeSet<u32> {
        self.records
            .iter()
            .filter_map(|r| match r {
                Record::Backup { seq, .. } => Some(*seq),
                _ => None,
            })
            .collect()
    }

    /// 결과가 남은 Action. **나중 기록이 이긴다.**
    pub fn decided(&self) -> BTreeMap<u32, Outcome> {
        let mut out = BTreeMap::new();
        for r in &self.records {
            if let Record::Outcome { seq, outcome } = r {
                out.insert(*seq, outcome.clone());
            }
        }
        out
    }

    /// 백업까지 끝났으나 결과가 남지 않은 Action.
    ///
    /// 크래시가 정확히 그 사이에 왔다는 뜻이다. 되돌릴 수는 있지만
    /// **수행됐는지 알 수 없다** — 그 사실을 그대로 보고해야 한다.
    pub fn undecided(&self) -> Vec<u32> {
        let decided = self.decided();
        self.backed_up()
            .into_iter()
            .filter(|s| !decided.contains_key(s))
            .collect()
    }

    /// 이 실행이 정상적으로 끝났는가.
    pub fn finished(&self) -> bool {
        matches!(self.records.last(), Some(Record::End { .. }))
    }
}

/// 이어 쓰기 전용 저널.
pub struct Journal {
    file: File,
}

impl Journal {
    /// 열거나 만든다. **이어 쓴다** — 지우지 않는다.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file })
    }

    /// 크래시로 잘린 저널을 **이어 쓸 수 있게** 연다.
    ///
    /// 잘린 꼬리를 먼저 잘라 낸다. 그러지 않으면 이어 쓴 첫 줄이 쓰다 만 줄 뒤에
    /// 그대로 붙어 **한 줄로 깨지고**, `read` 는 깨진 줄에서 멈추므로 이어서
    /// 수행한 기록이 **통째로 읽히지 않는다.** 저널이 있는데 아무것도 모르는
    /// 상태가 되고, 그러면 다음 재기동이 처음부터 다시 파괴하려 든다.
    ///
    /// `complete_bytes` 를 직접 받지 않고 `Reading` 을 받는 이유는, 그 숫자가
    /// **이 파일을 읽어서 나온 것**이어야 하기 때문이다. 다른 데서 온 숫자로
    /// 자르면 온전한 기록을 지운다.
    pub fn resume(path: &Path, reading: &Reading) -> std::io::Result<Self> {
        if reading.truncated {
            let f = OpenOptions::new().write(true).open(path)?;
            f.set_len(reading.complete_bytes)?;
            f.sync_all()?;
        }
        Self::open(path)
    }

    /// 한 줄 쓰고 **디스크까지 내린다.**
    ///
    /// fsync 하지 않으면 크래시 시 OS 버퍼에 있던 줄이 사라진다. 그 줄이
    /// `Backup` 이었다면 격리물은 디스크에 있는데 저널은 모르는 상태가 되고,
    /// 복원 도구는 그것을 찾지 못한다.
    /// 한 줄을 붙인다. **줄마다 `at`(RFC 3339 UTC) 이 붙는다** — 레코드가 이미
    /// 시각을 가지면(`Start.created`·`End.at`·`Resumed.at`) 그대로 둔다.
    ///
    /// 왜 레코드 타입에 넣지 않았는가: `Intent`·`Backup`·`Outcome` 을 만드는 자리가
    /// 스무 곳이고 그 전부가 시각을 알 필요는 없다. 시각은 **쓰는 순간**의 것이니
    /// 쓰는 자리가 찍는다. 읽는 쪽은 모르는 필드를 무시하므로 옛 저널도 새 저널도
    /// 같은 코드로 읽힌다 (2026-09-07 관측성 Phase 3).
    pub fn append(&mut self, rec: &Record) -> std::io::Result<()> {
        let mut line = stamp(rec, &now_rfc3339())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.sync_data()
    }

    /// 저널을 읽는다. **잘려 있어도 읽는다.**
    pub fn read(path: &Path) -> std::io::Result<Reading> {
        let f = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Reading::default()),
            Err(e) => return Err(e),
        };
        let mut out = Reading::default();
        let mut reader = BufReader::new(f);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            let n = reader.read_until(b'\n', &mut buf)?;
            if n == 0 {
                break;
            }
            // 개행으로 끝나지 않으면 쓰다 만 줄이다. 크래시 지점이 여기다.
            if !buf.ends_with(b"\n") {
                out.truncated = true;
                break;
            }
            match serde_json::from_slice::<Record>(&buf[..buf.len() - 1]) {
                Ok(r) => {
                    out.records.push(r);
                    out.complete_bytes += n as u64;
                }
                Err(_) => {
                    // 개행은 있는데 파싱이 안 된다 — 부분 쓰기 뒤에 개행만 들어간
                    // 경우다. 여기서 멈추고 **뒤를 믿지 않는다.** 뒤를 계속 읽으면
                    // 크래시 이전과 이후가 섞인 것을 온전한 기록으로 오해한다.
                    out.truncated = true;
                    break;
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("remedy-journal-test-{name}"));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn start() -> Record {
        Record::Start {
            run_id: "r1".into(),
            plugin_id: "p".into(),
            plan_sha256: "a".repeat(64),
            created: "2026-08-21T00:00:00Z".into(),
            self_integrity: Some("unsigned".into()),
        }
    }

    /// **옛 저널을 계속 읽는다.** `self_integrity` 가 없는 줄은 2026-09-02
    /// 이전의 기록이고, 그것을 못 읽으면 그때의 사고를 밝힐 수 없다.
    /// 없는 것을 `unknown` 으로 접지도 않는다 — 그쪽은 "검사했는데 몰랐다"
    /// 는 다른 사실이다.
    #[test]
    fn a_start_line_without_the_new_field_still_reads() {
        let line = r#"{"rec":"start","run_id":"r1","plugin_id":"p","plan_sha256":"aa","created":"2026-08-21T00:00:00Z"}"#;
        let r: Record = serde_json::from_str(line).expect("옛 기록을 읽지 못했다");
        let Record::Start { self_integrity, .. } = r else {
            panic!("start 가 아니다")
        };
        assert_eq!(self_integrity, None, "없는 것을 값으로 채웠다");
    }

    /// 값이 없으면 **줄에 나타나지도 않는다.** 빈 칸을 남기면 읽는 쪽이
    /// "검사했는데 비었다" 로 읽는다.
    #[test]
    fn no_value_means_no_field() {
        let r = Record::Start {
            run_id: "r1".into(),
            plugin_id: "p".into(),
            plan_sha256: "a".repeat(64),
            created: "2026-08-21T00:00:00Z".into(),
            self_integrity: None,
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(!j.contains("self_integrity"), "{j}");
    }

    #[test]
    fn our_own_autorun_is_recorded_before_the_end() {
        // **우리가 심은 자동실행이 감사 로그에 남는다** (설계-03 §8 규칙 3 · P12).
        // 그리고 그 줄은 `End` 앞이어야 한다 — 뒤에 오면 끝난 회차가 이어받기
        // 대상으로 되살아난다. 두 번째 절반이 그 위험을 그대로 잰다.
        let scheduled = Record::VerifyScheduled {
            location: Some("/etc/systemd/system/remedy-verify.service".into()),
            removed_by: Some("itself".into()),
            command: "\"/usr/local/bin/remedy\" verify --run r1 --plugin \"/p.yaml\" --lang ko"
                .into(),
        };
        let line = serde_json::to_string(&scheduled).unwrap();
        assert!(line.contains("\"rec\":\"verify_scheduled\""), "{line}");
        let refused = Record::VerifyNotScheduled {
            reason: "systemd 가 이 기계의 init 이 아니다".into(),
        };
        assert!(serde_json::to_string(&refused)
            .unwrap()
            .contains("\"rec\":\"verify_not_scheduled\""));

        let end = Record::End {
            run_id: "r1".into(),
            at: "2026-09-23T00:00:01Z".into(),
        };
        let p = tmp("autorun");
        {
            let mut j = Journal::open(&p).unwrap();
            j.append(&start()).unwrap();
            j.append(&scheduled).unwrap();
            j.append(&end).unwrap();
        }
        let r = Journal::read(&p).unwrap();
        assert_eq!(r.records, vec![start(), scheduled.clone(), end]);
        assert!(r.finished(), "End 앞의 예약 기록이 끝남을 가렸다");

        // End 뒤에 적으면 — **끝난 회차가 끝나지 않은 것으로 읽힌다.**
        {
            let mut j = Journal::open(&p).unwrap();
            j.append(&refused).unwrap();
        }
        assert!(
            !Journal::read(&p).unwrap().finished(),
            "이 성질이 바뀌었다면 실행기가 End 앞에 쓰는 이유도 다시 볼 것"
        );
    }

    #[test]
    fn records_round_trip() {
        let p = tmp("round");
        {
            let mut j = Journal::open(&p).unwrap();
            j.append(&start()).unwrap();
            j.append(&Record::Intent {
                seq: 1,
                op: Op::FileDelete,
                target: "c:\\x".into(),
            })
            .unwrap();
            j.append(&Record::Backup {
                seq: 1,
                entry_id: "e0".into(),
            })
            .unwrap();
            j.append(&Record::Outcome {
                seq: 1,
                outcome: Outcome::Done,
            })
            .unwrap();
            j.append(&Record::End {
                run_id: "r1".into(),
                at: "2026-08-21T00:00:01Z".into(),
            })
            .unwrap();
        }
        let r = Journal::read(&p).unwrap();
        assert_eq!(r.records.len(), 5);
        assert!(!r.truncated);
        assert!(r.finished());
        assert!(r.undecided().is_empty());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn appending_does_not_erase() {
        // 이어 쓰기가 아니면 재기동 때마다 이전 기록이 사라진다.
        let p = tmp("append");
        Journal::open(&p).unwrap().append(&start()).unwrap();
        Journal::open(&p)
            .unwrap()
            .append(&Record::End {
                run_id: "r1".into(),
                at: "t".into(),
            })
            .unwrap();
        assert_eq!(Journal::read(&p).unwrap().records.len(), 2);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn a_half_written_line_is_dropped_and_reported() {
        // **크래시는 쓰기 도중에 온다.** 마지막 줄을 버리되 그 앞은 살아야 한다.
        let p = tmp("halfline");
        {
            let mut j = Journal::open(&p).unwrap();
            j.append(&start()).unwrap();
            j.append(&Record::Intent {
                seq: 1,
                op: Op::FileDelete,
                target: "c:\\x".into(),
            })
            .unwrap();
        }
        // 개행 없이 반쯤 쓰다 만 줄을 덧붙인다.
        {
            let mut f = OpenOptions::new().append(true).open(&p).unwrap();
            f.write_all(br#"{"rec":"backup","seq":1,"entry"#).unwrap();
        }
        let r = Journal::read(&p).unwrap();
        assert_eq!(r.records.len(), 2, "앞의 온전한 줄은 살아야 한다");
        assert!(r.truncated, "잘렸다는 사실을 말해야 한다");
        assert!(r.complete_bytes > 0);
        assert!(!r.finished());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn a_broken_line_stops_the_read_instead_of_skipping_it() {
        // 깨진 줄을 건너뛰고 계속 읽으면 크래시 이전과 이후가 섞인 것을
        // 온전한 기록으로 오해한다.
        let p = tmp("broken");
        {
            let mut j = Journal::open(&p).unwrap();
            j.append(&start()).unwrap();
        }
        {
            let mut f = OpenOptions::new().append(true).open(&p).unwrap();
            f.write_all(b"{\"rec\":\"bac\n").unwrap();
            f.write_all(b"{\"rec\":\"end\",\"run_id\":\"r1\",\"at\":\"t\"}\n")
                .unwrap();
        }
        let r = Journal::read(&p).unwrap();
        assert_eq!(r.records.len(), 1);
        assert!(r.truncated);
        assert!(!r.finished(), "깨진 줄 뒤의 end 를 믿으면 안 된다");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn backup_without_outcome_is_undecided() {
        // 백업은 끝났는데 결과가 없다 = 크래시가 정확히 그 사이에 왔다.
        // 되돌릴 수는 있지만 **수행됐는지 알 수 없다.**
        let p = tmp("undecided");
        {
            let mut j = Journal::open(&p).unwrap();
            j.append(&start()).unwrap();
            for seq in [1u32, 2] {
                j.append(&Record::Intent {
                    seq,
                    op: Op::FileDelete,
                    target: format!("c:\\{seq}"),
                })
                .unwrap();
                j.append(&Record::Backup {
                    seq,
                    entry_id: format!("e{seq}"),
                })
                .unwrap();
            }
            j.append(&Record::Outcome {
                seq: 1,
                outcome: Outcome::Done,
            })
            .unwrap();
        }
        assert_eq!(Journal::read(&p).unwrap().undecided(), vec![2]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn the_journal_path_is_a_convention_not_a_choice() {
        // 실행기가 제 마음대로 정하면 재기동한 코드가 찾지 못한다.
        let dir = std::path::Path::new("C:\\state");
        assert_eq!(
            journal_path(dir, "r1"),
            dir.join("journal").join("r1.jsonl")
        );
    }

    #[test]
    fn only_unfinished_runs_come_back_for_resume() {
        // 재기동한 실행기가 **이어서 수행할 것**만 봐야 한다. 끝난 실행을 다시
        // 집으면 사용자가 승인한 것을 두 번 수행하게 된다.
        let base = std::env::temp_dir().join("remedy-journal-unfinished");
        let _ = std::fs::remove_dir_all(&base);

        let done = journal_path(&base, "run-done");
        {
            let mut j = Journal::open(&done).unwrap();
            j.append(&start()).unwrap();
            j.append(&Record::End {
                run_id: "run-done".into(),
                at: "t".into(),
            })
            .unwrap();
        }
        let open_run = journal_path(&base, "run-open");
        {
            let mut j = Journal::open(&open_run).unwrap();
            j.append(&start()).unwrap();
            j.append(&Record::Intent {
                seq: 1,
                op: Op::FileDelete,
                target: "c:\\x".into(),
            })
            .unwrap();
        }

        let left = unfinished(&base).unwrap();
        assert_eq!(left.len(), 1, "{left:?}");
        assert_eq!(left[0].0, "run-open");
        assert!(!left[0].1.finished());

        // 저널이 아직 없는 상태도 오류가 아니다 — 첫 실행이 그렇다.
        let empty = std::env::temp_dir().join("remedy-journal-none");
        let _ = std::fs::remove_dir_all(&empty);
        assert!(unfinished(&empty).unwrap().is_empty());

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn resuming_cuts_the_broken_tail_so_what_follows_is_readable() {
        // **이것이 없으면 이어서 수행한 기록이 통째로 사라진다.** 이어 쓴 첫 줄이
        // 쓰다 만 줄 뒤에 그대로 붙어 한 줄로 깨지고, `read` 는 거기서 멈춘다.
        let p = tmp("resume-tail");
        {
            let mut j = Journal::open(&p).unwrap();
            j.append(&start()).unwrap();
        }
        {
            let mut f = OpenOptions::new().append(true).open(&p).unwrap();
            f.write_all(br#"{"rec":"backup","seq":1,"entry"#).unwrap();
        }

        let crashed = Journal::read(&p).unwrap();
        assert!(crashed.truncated);

        let mut j = Journal::resume(&p, &crashed).unwrap();
        j.append(&Record::Resumed {
            run_id: "r1".into(),
            at: "2026-08-21T00:00:05Z".into(),
            after_records: crashed.records.len(),
        })
        .unwrap();
        j.append(&Record::End {
            run_id: "r1".into(),
            at: "2026-08-21T00:00:06Z".into(),
        })
        .unwrap();

        let after = Journal::read(&p).unwrap();
        assert_eq!(after.records.len(), 3, "{:?}", after.records);
        assert!(!after.truncated, "잘린 흔적이 남아 있다");
        assert!(after.finished(), "이어 쓴 end 가 읽혀야 한다");
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn resuming_an_intact_journal_keeps_every_byte() {
        // 자를 것이 없는데 자르면 온전한 기록을 지운다.
        let p = tmp("resume-intact");
        {
            let mut j = Journal::open(&p).unwrap();
            j.append(&start()).unwrap();
            j.append(&Record::Backup {
                seq: 1,
                entry_id: "e0".into(),
            })
            .unwrap();
        }
        let before = Journal::read(&p).unwrap();
        assert!(!before.truncated);
        let _ = Journal::resume(&p, &before).unwrap();
        assert_eq!(Journal::read(&p).unwrap().records.len(), 2);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn a_second_backup_of_the_same_action_is_one_action_not_two() {
        // 이어받은 실행이 백업 단계를 다시 돌면 같은 seq 의 Backup 이 두 번
        // 적힌다. 그것을 두 건으로 세면 "무엇이 미결인가" 가 틀어진다.
        let p = tmp("rebackup");
        {
            let mut j = Journal::open(&p).unwrap();
            j.append(&start()).unwrap();
            for _ in 0..2 {
                j.append(&Record::Backup {
                    seq: 1,
                    entry_id: "e0".into(),
                })
                .unwrap();
            }
        }
        let r = Journal::read(&p).unwrap();
        assert_eq!(r.backed_up(), BTreeSet::from([1]));
        assert_eq!(r.undecided(), vec![1]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn the_journal_says_which_plan_it_was_opened_for() {
        // run_id 는 같은데 내용이 다른 계획으로 이어받으면, 수행된 결과는
        // 사용자가 승인한 어느 계획과도 다른 것이 된다.
        let p = tmp("plandigest");
        Journal::open(&p).unwrap().append(&start()).unwrap();
        assert_eq!(
            Journal::read(&p).unwrap().plan_sha256(),
            Some(&*"a".repeat(64))
        );
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn decided_keeps_the_later_record() {
        let p = tmp("decided");
        {
            let mut j = Journal::open(&p).unwrap();
            j.append(&start()).unwrap();
            j.append(&Record::Outcome {
                seq: 1,
                outcome: Outcome::Failed {
                    reason: "잠겨 있다".into(),
                },
            })
            .unwrap();
            j.append(&Record::Outcome {
                seq: 1,
                outcome: Outcome::Done,
            })
            .unwrap();
        }
        let d = Journal::read(&p).unwrap().decided();
        assert_eq!(d.len(), 1);
        assert_eq!(d[&1], Outcome::Done);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn a_missing_journal_is_empty_not_an_error() {
        // 첫 실행에는 저널이 없다. 그것을 오류로 다루면 아무것도 시작할 수 없다.
        let p = tmp("absent");
        let r = Journal::read(&p).unwrap();
        assert!(r.records.is_empty());
        assert!(!r.truncated);
    }
}

/// 레코드를 JSON 한 줄로 만들되, 시각 필드가 없으면 `at` 을 넣는다.
fn stamp(rec: &Record, at: &str) -> serde_json::Result<Vec<u8>> {
    let mut v = serde_json::to_value(rec)?;
    if let serde_json::Value::Object(map) = &mut v {
        let has_time = map.contains_key("at") || map.contains_key("created");
        if !has_time {
            map.insert("at".to_string(), serde_json::Value::String(at.to_string()));
        }
    }
    serde_json::to_vec(&v)
}

/// 지금 시각, RFC 3339 UTC. (`remedy-core` 에도 같은 것이 있지만 저널은 그 아래
/// 크레이트라 여기서 다시 계산한다 — 의존 방향을 지키기 위해.)
fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod stamp_tests {
    use super::*;

    #[test]
    fn every_line_carries_a_time_and_old_lines_still_read() {
        let d = std::env::temp_dir().join(format!("remedy-journal-stamp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let path = d.join("j.jsonl");
        let mut j = Journal::open(&path).unwrap();
        j.append(&Record::Start {
            run_id: "r".into(),
            plugin_id: "p".into(),
            plan_sha256: "s".into(),
            created: "2026-01-01T00:00:00Z".into(),
            self_integrity: None,
        })
        .unwrap();
        j.append(&Record::Intent {
            seq: 1,
            op: Op::FileDelete,
            target: "x".into(),
        })
        .unwrap();
        j.append(&Record::Note { text: "n".into() }).unwrap();
        drop(j);
        // 옛 저널의 줄(시각 없음)을 손으로 덧붙인다 — 그래도 읽혀야 한다.
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(br#"{"rec":"backup","seq":1,"entry_id":"e1"}"#)
                .unwrap();
            f.write_all(b"\n").unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 4);
        // Start 는 created 를 가졌으니 at 이 덧붙지 않는다.
        assert!(lines[0].get("at").is_none(), "{}", lines[0]);
        for l in &lines[1..3] {
            let at = l.get("at").and_then(|v| v.as_str()).unwrap_or("");
            assert!(
                at.len() == 20 && at.ends_with('Z') && &at[10..11] == "T",
                "{l}"
            );
        }
        assert!(lines[3].get("at").is_none());
        let r = Journal::read(&path).unwrap();
        assert_eq!(r.intended().len(), 1);
        assert_eq!(r.backed_up().len(), 1, "시각 없는 옛 줄도 읽힌다");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn stamp_never_overwrites_an_existing_time() {
        let v = stamp(
            &Record::End {
                run_id: "r".into(),
                at: "2026-01-01T00:00:00Z".into(),
            },
            "2030-01-01T00:00:00Z",
        )
        .unwrap();
        let s = String::from_utf8(v).unwrap();
        assert!(
            s.contains("2026-01-01T00:00:00Z") && !s.contains("2030"),
            "{s}"
        );
    }
}
