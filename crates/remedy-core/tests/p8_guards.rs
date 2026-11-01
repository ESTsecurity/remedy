//! P8 고위험 Op 의 **가드** (설계-09 P8).
//!
//! 여기서 재는 것은 대부분 **하지 않은 일**이다. 보호 프로세스를 죽이지
//! 않았는가, 상한을 넘었을 때 하나도 죽이지 않았는가, 보호 키를 통째로 지우지
//! 않았는가, 서명을 확인할 수 없을 때 재귀 삭제를 멈췄는가.
//!
//! **VM 실증을 대신하지 않는다.** 워치독 쌍·SCM 재생성·부팅 영향은 실제
//! 기계에서만 잴 수 있고, 그것이 P8 게이트의 조건이다. 여기서 잴 수 있는 것은
//! "계획과 술어가 지목한 것 중 무엇을 손대고 무엇을 손대지 않는가" 다.

use remedy_apply::{Executor, Resume, Silent, VerifyRequest};
use remedy_platform::write::{
    FileMeta, KillPredicate, PlatformWrite, RegKeyIndex, RegistryValueBackup, RestoreReport, Target,
};
use remedy_platform::PlatformError;
use remedy_sdk::artifact::{Action, CoreInfo, Envelope, HostInfo, PlanBody, PlanEnvelope};
use remedy_sdk::catalog::{Op, Risk};
use std::cell::RefCell;
use std::collections::BTreeMap;

// ───────────────────────────────────────────────── 실험대

#[derive(Default)]
struct Lab {
    /// 돌고 있는 프로세스 `(pid, 이미지, 명령줄)`.
    procs: RefCell<Vec<(u32, String, String)>>,
    /// 부모 관계 `자식 pid → 부모 pid`. `include_descendants` 만 본다.
    kin: RefCell<BTreeMap<u32, u32>>,
    /// 계보를 걷지 못하는 백엔드를 흉내 낸다.
    kin_unsupported: std::cell::Cell<bool>,
    /// 실제로 종료된 pid. **무엇을 손댔는가**가 여기 남는다.
    killed: RefCell<Vec<u32>>,
    reg: RefCell<BTreeMap<String, RegistryValueBackup>>,
    /// 지워진 키. 손대지 않았어야 할 것이 여기 있으면 실패다.
    deleted_keys: RefCell<Vec<String>>,
    /// 복원 지점을 만들라는 요청이 왔는가.
    restore_point: RefCell<Vec<String>>,
    /// 복원 지점 생성이 실패하는가.
    restore_point_fails: std::cell::Cell<bool>,
    /// 재부팅 뒤 재검사를 **예약하다가** 죽는가 — 꼬리에서 멈춘 회차를 진짜로 낸다.
    dies_while_scheduling: std::cell::Cell<bool>,
}

impl Lab {
    fn with_procs(list: &[(u32, &str, &str)]) -> Self {
        let lab = Self::default();
        *lab.procs.borrow_mut() = list
            .iter()
            .map(|(p, i, c)| (*p, i.to_string(), c.to_string()))
            .collect();
        lab
    }
    /// `(pid, 부모 pid, 이미지, 명령줄)`. 부모가 없으면 0.
    fn with_tree(list: &[(u32, u32, &str, &str)]) -> Self {
        let lab = Self::default();
        *lab.procs.borrow_mut() = list
            .iter()
            .map(|(p, _, i, c)| (*p, i.to_string(), c.to_string()))
            .collect();
        *lab.kin.borrow_mut() = list.iter().map(|(p, pp, _, _)| (*p, *pp)).collect();
        lab
    }
    fn set_reg(&self, target: &str, value: &str) {
        self.reg
            .borrow_mut()
            .insert(target.into(), RegistryValueBackup::from_string(1, value));
    }
    fn alive(&self) -> Vec<u32> {
        self.procs.borrow().iter().map(|(p, _, _)| *p).collect()
    }
}

impl PlatformWrite for Lab {
    fn backend_name(&self) -> &'static str {
        "p8-lab"
    }
    fn plan_restore(&self, _d: &str, _m: &FileMeta) -> RestoreReport {
        RestoreReport::default()
    }
    fn restore_file(
        &self,
        _d: &str,
        _c: &[u8],
        _m: &FileMeta,
    ) -> Result<RestoreReport, PlatformError> {
        Err(PlatformError::Unsupported("파일은 다루지 않는다"))
    }
    fn quarantine_read(&self, _p: &str) -> Result<(Vec<u8>, FileMeta), PlatformError> {
        Err(PlatformError::Unsupported("파일은 다루지 않는다"))
    }
    fn destroy_file(&self, _p: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported("파일은 다루지 않는다"))
    }
    fn exists(&self, _p: &str) -> bool {
        true
    }
    fn is_dir(&self, _p: &str) -> bool {
        true
    }

    fn registry_key_read(&self, key: &str) -> Result<(Vec<u8>, RegKeyIndex), PlatformError> {
        let mut index = RegKeyIndex::default();
        let mut body = Vec::new();
        for (k, v) in self.reg.borrow().iter() {
            let Some(name) = k.strip_prefix(&format!("{key}\\")) else {
                continue;
            };
            index.values.push(remedy_platform::write::RegValueEntry {
                key: String::new(),
                name: name.to_string(),
                vtype: v.vtype,
                size: v.bytes.len() as u64,
            });
            body.extend_from_slice(&v.bytes);
        }
        if index.values.is_empty() {
            return Err(PlatformError::Unsupported("그런 키가 없다"));
        }
        Ok((body, index))
    }
    fn registry_key_delete(&self, key: &str) -> Result<(), PlatformError> {
        self.deleted_keys.borrow_mut().push(key.to_string());
        self.reg
            .borrow_mut()
            .retain(|k, _| !k.starts_with(&format!("{key}\\")));
        Ok(())
    }
    fn registry_key_exists(&self, key: &str) -> bool {
        self.reg
            .borrow()
            .keys()
            .any(|k| k.starts_with(&format!("{key}\\")))
    }

    /// **일부러 관대하다.** 빈 술어를 여기서도 막으면 실행기의 검사가 실제로
    /// 도는지 잴 수 없다 — 역검증에서 그렇게 샜다. 가짜가 제품보다 방어적이면
    /// 이 시험이 재는 것은 제품이 아니라 가짜의 관대함이다.
    ///
    /// (진짜 백엔드는 두 곳 다 막는다. 실행기 쪽은 "어느 백엔드든 빈 술어로는
    /// 아무것도 죽지 않는다" 를, 백엔드 쪽은 "이 문이 임의 열거가 되지
    /// 않는다" 를 지킨다 — 서로 다른 것을 지킨다.)
    fn processes_matching(&self, p: &KillPredicate) -> Result<Vec<Target>, PlatformError> {
        Ok(self
            .procs
            .borrow()
            .iter()
            .filter(|(_, img, cmd)| {
                p.image_path
                    .as_ref()
                    .is_none_or(|w| img.eq_ignore_ascii_case(w))
                    && p.cmdline_contains.as_ref().is_none_or(|n| cmd.contains(n))
            })
            .map(|(pid, img, cmd)| Target {
                pid: *pid,
                image_path: img.clone(),
                cmdline: cmd.clone(),
            })
            .collect())
    }
    /// **일부러 관대하다** — `processes_matching` 과 같은 이유다. 진짜 백엔드는
    /// 여기서 시작 시각으로 재사용된 PID 를 걸러 내지만, 그 방어는
    /// `remedy-platform` 쪽 시험이 잰다. 여기서 재는 것은 실행기가 계보를
    /// **언제 요청하고 무엇을 집합에 넣는가** 다.
    fn process_descendants(&self, roots: &[u32]) -> Result<Vec<Target>, PlatformError> {
        if self.kin_unsupported.get() {
            return Err(PlatformError::Unsupported("이 백엔드는 계보를 걷지 않는다"));
        }
        let kin = self.kin.borrow();
        let mut out: Vec<u32> = Vec::new();
        let mut frontier: Vec<u32> = roots.to_vec();
        while !frontier.is_empty() {
            let mut next = Vec::new();
            for parent in &frontier {
                for (child, p) in kin.iter() {
                    if p == parent && !roots.contains(child) && !out.contains(child) {
                        out.push(*child);
                        next.push(*child);
                    }
                }
            }
            frontier = next;
        }
        Ok(self
            .procs
            .borrow()
            .iter()
            .filter(|(pid, _, _)| out.contains(pid))
            .map(|(pid, img, cmd)| Target {
                pid: *pid,
                image_path: img.clone(),
                cmdline: cmd.clone(),
            })
            .collect())
    }
    fn process_kill(&self, pids: &[u32]) -> Result<(), PlatformError> {
        self.killed.borrow_mut().extend_from_slice(pids);
        self.procs
            .borrow_mut()
            .retain(|(p, _, _)| !pids.contains(p));
        Ok(())
    }

    fn create_restore_point(&self, label: &str) -> Result<(), PlatformError> {
        self.restore_point.borrow_mut().push(label.to_string());
        if self.restore_point_fails.get() {
            return Err(PlatformError::Refused("복원 서비스가 꺼져 있다".into()));
        }
        Ok(())
    }

    fn schedule_verify_after_reboot(
        &self,
        _run_id: &str,
        _exe: &std::path::Path,
        _plugin: &std::path::Path,
        _state_dir: Option<&std::path::Path>,
        _lang: remedy_sdk::i18n::Lang,
    ) -> Result<(), PlatformError> {
        assert!(
            !self.dies_while_scheduling.get(),
            "[시험] 여기서 전원이 나갔다고 친다"
        );
        Ok(())
    }
}

// ───────────────────────────────────────────────── 계획

fn plan_of(run: &str, actions: Vec<Action>) -> PlanEnvelope {
    Envelope {
        schema_version: 1,
        kind: remedy_sdk::artifact::ArtifactKind::Plan,
        run_id: run.to_string(),
        created: "2026-08-22T00:00:00Z".into(),
        host: HostInfo {
            hostname: "T".into(),
            os: "windows".into(),
            version: "10".into(),
            arch: "amd64".into(),
        },
        core: CoreInfo {
            version: "0".into(),
            build: "dev".into(),
        },
        plugins: Vec::new(),
        body: PlanBody {
            actions,
            verdicts: vec!["g0".into()],
            observation: Default::default(),
            deferred: Vec::new(),
            verify_after_reboot: false,
            submit_hint: None,
        },
    }
}

fn act(op: Op, target: Option<&str>) -> Action {
    Action {
        seq: 1,
        op,
        target: target.map(str::to_string),
        r#match: None,
        max_targets: None,
        max_retries: None,
        // 계획기는 재귀 삭제에 언제나 상한을 각인한다(설계-03 §4). 헬퍼가
        // 그것을 빠뜨리면 시험이 **다른 이유로** 거부되어 재려던 것을 못 잰다.
        max_children: Some(500),
        max_depth: Some(8),
        include_descendants: None,
        sha256: None,
        size: None,
        strip: None,
        because: vec!["e#0".into()],
        backup: None,
        reversible: op.info().reversible,
        risk: op.info().risk,
        user_impact: None,
    }
}

fn kill(predicate: serde_json::Value, max: Option<u32>) -> Action {
    let mut a = act(Op::ProcessKill, None);
    a.r#match = Some(predicate);
    a.max_targets = max;
    a
}

fn state(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("remedy-p8-{name}"));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// 저널에 남은 사유 줄. **진행 이벤트는 저장되지 않는다** — "왜 이렇게
/// 되었는가" 를 나중에 물으면 답할 곳이 여기뿐이다 (설계-03 §7).
fn notes_of(journal: &std::path::Path) -> Vec<String> {
    use remedy_journal::{Journal, Record};
    Journal::read(journal)
        .expect("저널")
        .records
        .into_iter()
        .filter_map(|r| match r {
            Record::Note { text } => Some(text),
            _ => None,
        })
        .collect()
}

fn run(lab: &Lab, name: &str, actions: Vec<Action>) -> (usize, usize, Vec<String>) {
    let rep = Executor::new(lab, state(name))
        .with_progress(&Silent)
        .with_clock("2026-08-22T00:00:00Z")
        .apply(&plan_of(name, actions))
        .expect("수행");
    let errs = rep
        .body
        .results
        .iter()
        .filter_map(|r| r.error.clone())
        .collect();
    (rep.done(), rep.failed(), errs)
}

// ───────────────────────────────────── process.kill

#[test]
fn a_protected_process_is_never_killed_even_when_the_predicate_names_it() {
    // **계획기의 검사와 겹치는 것이 아니다.** 계획기는 술어에 *적힌* 이미지
    // 경로를 보고, 여기서는 술어가 *실제로 지목한 것*을 본다. 술어가 명령줄
    // 하나뿐이면 계획 시점에는 무엇이 걸릴지 알 수 없다 (설계-03 §3).
    let lab = Lab::with_procs(&[
        (4, "C:\\Windows\\System32\\ntoskrnl.exe", "system evil"),
        (600, "C:\\Windows\\System32\\lsass.exe", "lsass evil"),
        (900, "C:\\a\\evil.exe", "evil"),
    ]);
    let (done, failed, errs) = run(
        &lab,
        "protected",
        vec![kill(
            serde_json::json!({ "cmdline_contains": "evil" }),
            None,
        )],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert_eq!(*lab.killed.borrow(), vec![900], "보호 대상을 죽였다");
    assert!(lab.alive().contains(&4), "PID 4 가 사라졌다");
    assert!(lab.alive().contains(&600), "lsass 가 사라졌다");
}

#[test]
fn a_lookalike_outside_the_system_directory_is_not_protected() {
    // **이름만 보면 위장이 보호를 얻는다.** 그러면 악성코드가 시스템 프로세스
    // 이름을 쓰는 것만으로 치료를 회피하고, 보호 목록이 공격자의 도구가 된다.
    let lab = Lab::with_procs(&[(900, "C:\\Temp\\lsass.exe", "evil")]);
    let (done, failed, errs) = run(
        &lab,
        "lookalike",
        vec![kill(
            serde_json::json!({ "image_path": "C:\\Temp\\lsass.exe" }),
            None,
        )],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert_eq!(*lab.killed.borrow(), vec![900], "위장을 보호했다");
}

#[test]
fn going_over_the_ceiling_kills_nothing_at_all() {
    // **몇 개를 죽인 뒤 멈추면 폭주를 막은 것이 아니라 절반만 폭주한 것이다**
    // (설계-03 §4).
    let lab = Lab::with_procs(&[
        (901, "C:\\a\\evil.exe", "evil"),
        (902, "C:\\a\\evil.exe", "evil"),
        (903, "C:\\a\\evil.exe", "evil"),
    ]);
    let (done, failed, errs) = run(
        &lab,
        "ceiling",
        vec![kill(
            serde_json::json!({ "image_path": "C:\\a\\evil.exe" }),
            Some(2),
        )],
    );
    assert_eq!((done, failed), (0, 1), "{errs:?}");
    // 기대값도 같은 언어로 짓는다 — 시험은 영어로 돈다(`i18n::current` 기본값).
    assert!(
        errs[0].contains(remedy_sdk::i18n::t("상한", "limit")),
        "{errs:?}"
    );
    assert!(lab.killed.borrow().is_empty(), "하나라도 죽였다");
    assert_eq!(lab.alive().len(), 3);
}

#[test]
fn the_ceiling_lets_through_what_fits() {
    // 위 시험이 "상한이 있으면 언제나 막는다" 로 통과하면 안 된다.
    let lab = Lab::with_procs(&[(901, "C:\\a\\evil.exe", "evil")]);
    let (done, failed, errs) = run(
        &lab,
        "fits",
        vec![kill(
            serde_json::json!({ "image_path": "C:\\a\\evil.exe" }),
            Some(2),
        )],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert_eq!(*lab.killed.borrow(), vec![901]);
}

#[test]
fn an_empty_predicate_is_refused_rather_than_matching_everything() {
    let lab = Lab::with_procs(&[(901, "C:\\a\\evil.exe", "evil")]);
    let (done, failed, errs) = run(&lab, "nopredicate", vec![kill(serde_json::json!({}), None)]);
    assert_eq!((done, failed), (0, 1), "{errs:?}");
    assert!(
        errs[0].contains(remedy_sdk::i18n::t("술어", "predicate")),
        "{errs:?}"
    );
    // **실험대는 빈 술어를 막지 않는다.** 막은 것이 실행기여야 한다 —
    // 가짜가 함께 막으면 실행기의 검사를 빼도 이 시험이 통과한다.
    assert!(lab.killed.borrow().is_empty(), "전부 죽였다");
    assert_eq!(lab.alive().len(), 1);
}

#[test]
fn nothing_matching_is_not_a_failure() {
    // 목표 상태는 이미 이루어졌다. 재기동한 실행기가 같은 Action 을 다시 만난다.
    let lab = Lab::with_procs(&[(901, "C:\\a\\good.exe", "good")]);
    let (done, failed, errs) = run(
        &lab,
        "nomatch",
        vec![kill(
            serde_json::json!({ "image_path": "C:\\a\\evil.exe" }),
            None,
        )],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert!(lab.killed.borrow().is_empty());
}

#[test]
fn a_skipped_protected_process_leaves_its_reason_in_the_audit_log() {
    // **진행 이벤트만으로는 부족하다** (설계-03 §7). 그것은 화면과 무인 배포가
    // 읽는 스트림이고 저장되지 않는다 — "왜 이 프로세스는 살아남았는가" 를
    // 나중에 물으면 답할 곳이 저널뿐이다.
    let lab = Lab::with_procs(&[
        (600, r"C:\Windows\System32\lsass.exe", "lsass evil"),
        (900, r"C:\a\evil.exe", "evil"),
    ]);
    let dir = state("audit");
    let rep = Executor::new(&lab, dir)
        .with_progress(&Silent)
        .with_clock("2026-08-23T00:00:00Z")
        .apply(&plan_of(
            "audit",
            vec![kill(
                serde_json::json!({ "cmdline_contains": "evil" }),
                None,
            )],
        ))
        .expect("수행");

    let skipped: Vec<String> = notes_of(&rep.journal)
        .into_iter()
        .filter(|t| t.contains("보호 대상"))
        .collect();
    assert_eq!(skipped.len(), 1, "{skipped:?}");
    assert!(skipped[0].contains("600"), "{skipped:?}");
    assert!(skipped[0].contains("lsass.exe"), "{skipped:?}");
    // 죽인 것은 그대로 죽였다.
    assert_eq!(*lab.killed.borrow(), vec![900]);
}

#[test]
fn nothing_skipped_means_nothing_in_the_audit_log() {
    // 위 시험이 "언제나 한 줄 남긴다" 로 통과하면 안 된다.
    let lab = Lab::with_procs(&[(900, r"C:\a\evil.exe", "evil")]);
    let dir = state("audit-none");
    let rep = Executor::new(&lab, dir)
        .with_progress(&Silent)
        .with_clock("2026-08-23T00:00:00Z")
        .apply(&plan_of(
            "audit-none",
            vec![kill(
                serde_json::json!({ "cmdline_contains": "evil" }),
                None,
            )],
        ))
        .expect("수행");
    assert!(
        !notes_of(&rep.journal)
            .iter()
            .any(|t| t.contains("보호 대상")),
        "제외한 것이 없는데 사유가 남았다"
    );
}

#[test]
fn the_skipped_suspend_step_is_recorded_in_the_audit_log() {
    // **설계-03 §2 가 고정한 규칙은 `해소 → 전부 정지 → 전부 종료 → 재평가`
    // 인데 이 코어는 정지를 못 한다** (설계-01 D13). 말하지 않으면 저널은
    // 규칙이 다 돈 것처럼 읽힌다 — 관측이 불완전할 수 있듯 실행도 불완전할
    // 수 있고, 둘 다 말하지 않으면 완전한 것으로 읽힌다.
    let lab = Lab::with_procs(&[(900, r"C:\a\evil.exe", "evil")]);
    let rep = Executor::new(&lab, state("suspend-note"))
        .with_progress(&Silent)
        .with_clock("2026-08-23T00:00:00Z")
        .apply(&plan_of(
            "suspend-note",
            vec![kill(
                serde_json::json!({ "cmdline_contains": "evil" }),
                None,
            )],
        ))
        .expect("수행");
    let notes = notes_of(&rep.journal);
    let n: Vec<&String> = notes.iter().filter(|t| t.contains("정지")).collect();
    assert_eq!(
        n.len(),
        1,
        "정지 강등이 저널에 정확히 한 줄이어야 한다: {notes:?}"
    );
    assert!(n[0].contains("D13"), "{n:?}");
    // 죽이기는 그대로 했다. 적어 두는 것과 안 하는 것은 다르다.
    assert_eq!(*lab.killed.borrow(), vec![900]);
}

#[test]
fn a_refused_kill_never_claims_a_suspend_that_could_not_happen() {
    // 위 시험이 "언제나 한 줄" 로 통과하면 안 된다. 술어가 없어 거절되면
    // 종료 자체가 없었으므로 정지 이야기를 꺼낼 자리도 없다.
    let lab = Lab::with_procs(&[(900, r"C:\a\evil.exe", "evil")]);
    let rep = Executor::new(&lab, state("suspend-none"))
        .with_progress(&Silent)
        .with_clock("2026-08-23T00:00:00Z")
        .apply(&plan_of(
            "suspend-none",
            vec![kill(serde_json::json!({}), None)],
        ))
        .expect("수행");
    assert!(
        !notes_of(&rep.journal).iter().any(|t| t.contains("정지")),
        "아무것도 종료하지 않았는데 정지 강등을 적었다"
    );
    assert!(lab.killed.borrow().is_empty());
}

// ───────────────────────────── process.kill · include_descendants

/// 술어는 뿌리 하나만 잡는다. 감시자는 그 자식이고, 이름도 명령줄도 다르다 —
/// **계보로만 식별된다** (설계-03 §2).
fn watched_tree() -> Lab {
    Lab::with_tree(&[
        (900, 0, r"C:\a\evil.exe", "evil root"),
        (901, 900, r"C:\a\helper.exe", "helper"),
        (902, 901, r"C:\a\deep.exe", "deep"),
        (950, 0, r"C:\a\stranger.exe", "stranger"),
    ])
}

fn kill_kin(predicate: serde_json::Value, max: Option<u32>) -> Action {
    let mut a = kill(predicate, max);
    a.include_descendants = Some(true);
    a
}

#[test]
fn descendants_join_the_set_when_the_plan_asks_for_them() {
    let lab = watched_tree();
    let (done, failed, errs) = run(
        &lab,
        "kin-on",
        vec![kill_kin(
            serde_json::json!({ "cmdline_contains": "evil" }),
            None,
        )],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    // 손자까지 간다. 한 겹만 걷으면 902 가 살아남는다.
    let mut killed = lab.killed.borrow().clone();
    killed.sort_unstable();
    assert_eq!(killed, vec![900, 901, 902]);
    // 남남은 건드리지 않는다.
    assert_eq!(lab.alive(), vec![950]);
}

#[test]
fn without_the_flag_a_descendant_survives() {
    // 위 시험이 "언제나 계보를 편다" 로 통과하면 안 된다. 계보 확장은 술어가
    // 지목하지 못한 것까지 죽이는 일이라 **계획이 켜야만** 일어난다.
    let lab = watched_tree();
    let (done, failed, errs) = run(
        &lab,
        "kin-off",
        vec![kill(
            serde_json::json!({ "cmdline_contains": "evil" }),
            None,
        )],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert_eq!(*lab.killed.borrow(), vec![900]);
    let mut alive = lab.alive();
    alive.sort_unstable();
    assert_eq!(alive, vec![901, 902, 950]);
}

#[test]
fn the_ceiling_counts_descendants_too() {
    // 설계-03 §2: "자손 확장에도 `max_targets` 상한이 그대로 걸린다."
    // 뿌리는 하나뿐이라 상한 2 를 술어만으로는 절대 넘지 못한다 — 넘는다면
    // 그것은 계보로 더해진 것이 세어졌다는 뜻이다.
    let lab = watched_tree();
    let (done, failed, errs) = run(
        &lab,
        "kin-ceiling",
        vec![kill_kin(
            serde_json::json!({ "cmdline_contains": "evil" }),
            Some(2),
        )],
    );
    assert_eq!((done, failed), (0, 1), "{errs:?}");
    assert!(
        errs[0].contains(remedy_sdk::i18n::t("상한", "limit")),
        "{errs:?}"
    );
    // **어디서 온 몇 개인지 말한다.** "술어가 3개를 지목했다" 만 읽으면 술어를
    // 고치러 가는데, 실제로 넘긴 것은 자손이다.
    assert!(
        errs[0].contains(remedy_sdk::i18n::t("술어 1개", "1 by predicate"))
            && errs[0].contains(remedy_sdk::i18n::t("자손 2개", "2 descendant(s)")),
        "상한 초과가 어디서 왔는지 말하지 않는다: {errs:?}"
    );
    // **하나도 죽이지 않는다.** 절반만 죽이면 폭주를 막은 것이 아니다.
    assert!(lab.killed.borrow().is_empty(), "{:?}", lab.killed.borrow());
}

#[test]
fn the_ceiling_lets_a_lineage_through_when_it_fits() {
    // 위 시험이 "상한이 있으면 언제나 막는다" 로 통과하면 안 된다.
    let lab = watched_tree();
    let (done, failed, errs) = run(
        &lab,
        "kin-fits",
        vec![kill_kin(
            serde_json::json!({ "cmdline_contains": "evil" }),
            Some(3),
        )],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert_eq!(lab.killed.borrow().len(), 3);
}

#[test]
fn a_protected_root_does_not_open_its_children_to_the_kill() {
    // 술어가 보호 대상을 지목했다면 **술어가 빗나간 것**이고, 빗나간 자리에서
    // 계보를 펼치면 실수가 트리 하나만큼 커진다.
    let lab = Lab::with_tree(&[
        (600, 0, r"C:\Windows\System32\lsass.exe", "evil"),
        (601, 600, r"C:\Windows\System32\child.exe", "innocent child"),
    ]);
    let (done, failed, errs) = run(
        &lab,
        "kin-protected-root",
        vec![kill_kin(
            serde_json::json!({ "cmdline_contains": "evil" }),
            None,
        )],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert!(
        lab.killed.borrow().is_empty(),
        "보호 대상의 자식을 열었다: {:?}",
        lab.killed.borrow()
    );
}

#[test]
fn a_protected_descendant_is_left_alone_and_said_so() {
    let lab = Lab::with_tree(&[
        (900, 0, r"C:\a\evil.exe", "evil root"),
        (601, 900, r"C:\Windows\System32\lsass.exe", "borrowed"),
    ]);
    let rep = Executor::new(&lab, state("kin-protected-child"))
        .with_progress(&Silent)
        .with_clock("2026-08-23T00:00:00Z")
        .apply(&plan_of(
            "kin-protected-child",
            vec![kill_kin(
                serde_json::json!({ "cmdline_contains": "evil" }),
                None,
            )],
        ))
        .expect("수행");
    assert_eq!(*lab.killed.borrow(), vec![900]);
    let notes = notes_of(&rep.journal);
    assert!(
        notes
            .iter()
            .any(|t| t.contains("자손") && t.contains("보호 대상") && t.contains("601")),
        "{notes:?}"
    );
}

#[test]
fn the_lineage_that_was_added_is_named_in_the_audit_log() {
    // 뿌리가 모두 죽고 나면 자손은 계보로 다시 찾을 수 없다 — 부모가 없으므로.
    // 재평가가 확인하지 못하는 것이므로 **무엇을 더했는지는 저널이 말해야 한다.**
    let lab = watched_tree();
    let rep = Executor::new(&lab, state("kin-audit"))
        .with_progress(&Silent)
        .with_clock("2026-08-23T00:00:00Z")
        .apply(&plan_of(
            "kin-audit",
            vec![kill_kin(
                serde_json::json!({ "cmdline_contains": "evil" }),
                None,
            )],
        ))
        .expect("수행");
    let notes = notes_of(&rep.journal);
    let added: Vec<&String> = notes.iter().filter(|t| t.contains("계보로")).collect();
    assert_eq!(added.len(), 1, "{notes:?}");
    assert!(
        added[0].contains("901") && added[0].contains("902"),
        "{added:?}"
    );
}

#[test]
fn a_backend_that_cannot_walk_lineage_fails_instead_of_ignoring_the_flag() {
    // **"자손이 없다" 와 "자손을 못 봤다" 가 같은 값이 되면 안 된다**
    // (설계-00 §5-1). 조용히 무시하면 계획이 요구한 것의 일부가 사라진다.
    let lab = watched_tree();
    lab.kin_unsupported.set(true);
    let (done, failed, errs) = run(
        &lab,
        "kin-unsupported",
        vec![kill_kin(
            serde_json::json!({ "cmdline_contains": "evil" }),
            None,
        )],
    );
    assert_eq!((done, failed), (0, 1), "{errs:?}");
    assert!(errs[0].contains("계보"), "{errs:?}");
    assert!(
        lab.killed.borrow().is_empty(),
        "계보를 못 걷는데 뿌리를 죽였다"
    );
}

// ───────────────────────────────── registry.delete_key

#[test]
fn a_protected_registry_key_cannot_be_deleted_whole() {
    // 값 하나를 지우는 것과 키 아래 전부를 지우는 것은 **무엇이 함께
    // 사라지느냐**가 다르다 (설계-03 §3).
    let lab = Lab::default();
    for key in [
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        r"HKLM\SYSTEM\CurrentControlSet\Services",
        r"HKLM\SOFTWARE\Microsoft\SystemCertificates",
        r"HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot",
    ] {
        lab.set_reg(&format!("{key}\\아무값"), "x");
        let e = Executor::new(&lab, state("protkey"))
            .with_progress(&Silent)
            .with_clock("2026-08-22T00:00:00Z")
            .apply(&plan_of(
                "protkey",
                vec![act(Op::RegistryDeleteKey, Some(key))],
            ))
            .expect("수행");
        assert_eq!((e.done(), e.failed()), (0, 1), "{key}: 통과했다");
        assert!(
            lab.deleted_keys.borrow().is_empty(),
            "{key}: 지워졌다 {:?}",
            lab.deleted_keys.borrow()
        );
    }
}

#[test]
fn a_child_of_a_protected_key_can_be_deleted() {
    // **하위는 지울 수 있어야 한다.** 악성코드는 실제로 이 아래에 자기 항목을
    // 만든다 — IFEO 하이재킹이 그것이고, 부모를 통째로 막으면 첫 플러그인부터
    // 동작하지 않는다.
    let lab = Lab::default();
    let child =
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\evil.exe";
    lab.set_reg(&format!("{child}\\Debugger"), "C:\\a\\evil.exe");
    let (done, failed, errs) = run(
        &lab,
        "ifeochild",
        vec![act(Op::RegistryDeleteKey, Some(child))],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert_eq!(*lab.deleted_keys.borrow(), vec![child.to_string()]);
}

// ───────────────────────────── dir.delete_recursive

#[test]
fn a_recursive_delete_stops_when_signatures_cannot_be_checked() {
    // **확인하지 못한 것을 통과로 읽으면 가드가 없는 것과 같다.**
    // `FileRecord.signature` 도 같은 논리로 `None` 을 "서명 없음" 으로 읽지
    // 말라고 적어 두었다.
    // 거부는 **백업보다 먼저**다. 담고 나서 거부하면 파괴는 막히지만 그
    // 디렉터리가 통째로 격리소에 복사된 뒤다.
    let lab = Lab::default();
    let e = Executor::new(&lab, state("sig"))
        .with_progress(&Silent)
        .with_clock("2026-08-22T00:00:00Z")
        .apply(&plan_of(
            "sig",
            vec![act(Op::DirDeleteRecursive, Some("C:\\a\\evil"))],
        ))
        .expect_err("거부해야 한다");
    // 기대값도 같은 언어로 — 시험은 영어로 돈다(`i18n::current` 기본값).
    assert!(
        e.to_string()
            .contains(remedy_sdk::i18n::t("서명", "signatures")),
        "{e}"
    );
}

#[test]
fn a_recursive_delete_without_its_limits_is_refused() {
    // **손으로 고친 계획이 들어올 수 있다.** 계획기는 언제나 상한을 각인하므로
    // 없다는 것은 낡은 계획이거나 손댄 계획이다 — 재귀 삭제가 상한 없이 도는
    // 것은 그 Op 의 정상 상태가 아니다 (설계-03 §4).
    //
    // 거부는 **백업보다 먼저**다. 담고 나서 거부하면 그 디렉터리가 통째로
    // 격리소에 복사된 뒤다.
    let lab = Lab::default();
    let mut a = act(Op::DirDeleteRecursive, Some(r"C:\a\evil"));
    a.max_children = None;
    a.max_depth = None;
    let e = Executor::new(&lab, state("nolimit"))
        .with_progress(&Silent)
        .with_clock("2026-08-22T00:00:00Z")
        .apply(&plan_of("nolimit", vec![a]))
        .expect_err("거부해야 한다");
    assert!(
        e.to_string()
            .contains(remedy_sdk::i18n::t("규모 상한", "size ceiling")),
        "{e}"
    );
}

// ─────────────────────────────────── 복원 지점

#[test]
fn a_high_risk_plan_asks_for_a_restore_point_first() {
    let lab = Lab::default();
    lab.set_reg(r"HKCU\Software\Evil\A", "x");
    let (_, _, _) = run(
        &lab,
        "rp",
        vec![act(Op::RegistryDeleteKey, Some(r"HKCU\Software\Evil"))],
    );
    assert_eq!(lab.restore_point.borrow().len(), 1, "시도하지 않았다");
    assert!(lab.restore_point.borrow()[0].starts_with("remedy-"));
}

#[test]
fn a_failed_restore_point_does_not_stop_the_treatment() {
    // **대체재가 아니라 추가 안전망이다** (설계-00 §5-2). 치명적으로 다루면
    // 복원 지점을 만들 수 없는 환경에서 치료 자체가 막힌다.
    let lab = Lab::default();
    lab.restore_point_fails.set(true);
    lab.set_reg(r"HKCU\Software\Evil\A", "x");
    let (done, failed, errs) = run(
        &lab,
        "rpfail",
        vec![act(Op::RegistryDeleteKey, Some(r"HKCU\Software\Evil"))],
    );
    assert_eq!((done, failed), (1, 0), "{errs:?}");
    assert_eq!(
        *lab.deleted_keys.borrow(),
        vec![r"HKCU\Software\Evil".to_string()]
    );
}

#[test]
fn a_plan_without_high_risk_ops_does_not_ask() {
    // 위 시험이 "언제나 시도한다" 로 통과하면 안 된다. 복원 지점 생성은
    // 느리고 디스크를 쓴다 — 값어치가 있는 자리에서만 한다.
    let lab = Lab::with_procs(&[(901, "C:\\a\\evil.exe", "evil")]);
    let _ = run(
        &lab,
        "norp",
        vec![kill(
            serde_json::json!({ "image_path": "C:\\a\\evil.exe" }),
            None,
        )],
    );
    assert!(
        lab.restore_point.borrow().is_empty(),
        "고위험이 없는데 시도했다"
    );
}

#[test]
fn finishing_only_the_tail_does_not_ask_for_a_restore_point_again() {
    // 마지막 결과를 적은 뒤 7단계에서 죽으면 파괴는 끝난 것이다. 이어받으며
    // 복원 지점을 또 만들면 **치료 뒤의 상태를 담는 쓸모없는 지점**이 하나 는다 —
    // 위 시험대로 값어치가 있는 자리에서만 한다 (결정 자료 다1).
    let lab = Lab::default();
    lab.set_reg(r"HKCU\Software\Evil\A", "x");
    let mut p = plan_of(
        "rptail",
        vec![act(Op::RegistryDeleteKey, Some(r"HKCU\Software\Evil"))],
    );
    p.body.verify_after_reboot = true;
    let dir = state("rptail");
    let ex = || {
        Executor::new(&lab, dir.clone())
            .with_progress(&Silent)
            .with_clock("2026-08-22T00:00:00Z")
            .with_verify_after_reboot(Ok(VerifyRequest {
                exe: "/usr/local/bin/remedy".into(),
                plugin: "/opt/plugins/x/plugin.yaml".into(),
                state_dir: None,
                lang: remedy_sdk::i18n::Lang::Ko,
            }))
    };

    lab.dies_while_scheduling.set(true);
    let died = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ex().apply(&p)));
    assert!(died.is_err(), "죽지 않았다 — 크래시 지점이 틀렸다");
    assert_eq!(
        lab.restore_point.borrow().len(),
        1,
        "첫 수행은 시도해야 한다"
    );
    assert_eq!(lab.deleted_keys.borrow().len(), 1);

    lab.dies_while_scheduling.set(false);
    let rep = ex().apply(&p).expect("꼬리를 마저 해야 한다");
    assert_eq!(rep.resumed, Some(Resume::Tail), "{rep:?}");
    assert_eq!(
        lab.restore_point.borrow().len(),
        1,
        "꼬리만 남았는데 복원 지점을 또 만들었다"
    );
    assert_eq!(lab.deleted_keys.borrow().len(), 1, "지운 키를 또 지웠다");
}

// ───────────────────────────────────────── 위험 등급

#[test]
fn the_catalog_and_the_design_agree_on_what_is_high_risk() {
    // 설계-03 §2 가 **고** 로 적은 넷이다. 이 표가 어긋나면 복원 지점 시도의
    // 조건이 조용히 달라진다.
    let high: Vec<&str> = Op::ALL
        .into_iter()
        .filter(|o| o.info().risk == Risk::High)
        .map(|o| o.info().id)
        .collect();
    assert_eq!(
        high,
        vec![
            "dir.delete_recursive",
            "registry.delete_key",
            "cert_store.remove",
            "boot.restore_default",
        ]
    );
}
