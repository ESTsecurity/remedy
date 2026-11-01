//! 폭주 차단 상한 (설계-03 §4).
//!
//! **상한은 계획 단계에서 평가한다.** 100개를 지운 뒤 상한에 걸려 중단하면 이미
//! 사고다. 초과 시 무인 모드는 프롬프트 없이 중단(fail-closed)하고, 대화형은
//! 계획 전문을 보여주고 명시적 승인을 받는다.
//!
//! 초기값은 실측치가 아니라 **출발점**이다. 첫 플러그인의 실제 감염 스냅샷에서
//! 관측된 값으로 조정하고 근거를 설계-03 §4 에 기록한다. 값 자체보다 "계획
//! 단계에서 fail-closed" 라는 성질이 안전장치의 본체다.

use remedy_sdk::catalog::Op;

/// 실행 하나에 걸리는 상한 전종.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    // ── 실행 전체 ────────────────────────────────────────
    /// 총 삭제 파일 수.
    pub total_files: u32,
    /// 동일 해시 반복 항목. 랜섬노트처럼 **판정 근거가 한 번만 필요했던** 대상은
    /// 위험이 개수에 비례하지 않으므로 별도 상한을 받는다.
    pub same_hash_items: u32,
    /// 총 삭제 바이트.
    pub total_bytes: u64,
    /// 서로 다른 최상위 디렉터리 수. 확산 탐지용이다.
    pub distinct_top_dirs: u32,
    /// 증거 그룹 수. 룰이 과광범위한지 보는 신호다.
    pub evidence_groups: u32,

    // ── Action 1건 ──────────────────────────────────────
    /// 재귀 삭제 1건당 하위 항목 수.
    pub recursive_children: u32,
    /// 재귀 삭제 최대 깊이.
    pub recursive_depth: u32,
    /// `process.kill` 술어당 대상 수.
    ///
    /// **이 상한만은 계획 단계에서 판정할 수 없다** — 술어가 몇 개의 프로세스를
    /// 지목할지는 실행 시점에야 안다. apply 시작 직후, 백업과 파괴 **이전**에
    /// 판정한다(설계-03 §4). 판정 시점이 파괴 이전이므로 "폭주를 실행 전에
    /// 막는다" 는 성질은 유지된다.
    pub kill_targets: u32,
}

impl Default for Limits {
    fn default() -> Self {
        // 설계-03 §4 의 표.
        Self {
            total_files: 1000,
            same_hash_items: 20_000,
            total_bytes: 512 * 1024 * 1024,
            distinct_top_dirs: 5,
            evidence_groups: 50,
            recursive_children: 500,
            recursive_depth: 8,
            kill_targets: 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitConfigError {
    pub message: String,
}

impl std::fmt::Display for LimitConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Limits {
    /// 상한 사이의 부등식을 검사한다. **위반하면 기동을 거부한다** (설계-03 §4).
    ///
    /// 개별 Action 상한이 실행 전체 상한을 넘으면 총계가 무의미해지고, 어느 쪽이
    /// 먼저 걸리는지가 **계획 순서에 따라 달라져 재현되지 않는다.** 재현되지 않는
    /// 안전장치는 안전장치가 아니다.
    ///
    /// 짝지을 수 있는 것은 하나뿐이다. `recursive_depth` 와 `kill_targets` 에는
    /// 대응하는 실행 전체 상한이 없다 — 깊이는 개수가 아니고, 프로세스 종료는
    /// 파일 삭제로 세지 않는다.
    pub fn check(&self) -> Result<(), LimitConfigError> {
        if self.recursive_children > self.total_files {
            return Err(LimitConfigError {
                message: format!(
                    "재귀 삭제 1건당 하위 항목 상한({})이 총 삭제 파일 상한({})보다 큽니다.\n\
                     개별 상한이 총계를 넘으면 총계가 무의미해지고, 어느 쪽이 먼저 걸리는지가\n\
                     계획 순서에 따라 달라져 재현되지 않습니다 (설계-03 §4).",
                    self.recursive_children, self.total_files
                ),
            });
        }
        if self.total_files > 0 && self.total_bytes == 0 {
            return Err(LimitConfigError {
                message: format!(
                    "총 삭제 파일 상한은 {}인데 총 삭제 바이트 상한이 0이입니다.\n\
                     0바이트 파일 말고는 아무것도 지울 수 없으므로 파일 상한이 거짓말이 됩니다.",
                    self.total_files
                ),
            });
        }
        Ok(())
    }

    /// 이 Op 가 재귀적 파괴인가. 상한 적용 대상을 가른다.
    ///
    /// `registry.delete_key` 는 값이 아니라 **하위 트리 전체**를 지우므로
    /// `dir.delete_recursive` 와 같은 성격이다 (설계-03 §4).
    pub fn is_recursive(op: Op) -> bool {
        matches!(op, Op::DirDeleteRecursive | Op::RegistryDeleteKey)
    }

    /// 이 Op 이 **파일을 없애는가.** 파일 개수·해시·바이트 상한이 세는 대상이다.
    ///
    /// # `file.quarantine_only` 가 여기 있는 이유
    ///
    /// **이름과 달리 파일을 지운다** — 실행기가 `destroy_file(target)` 을 부른다.
    /// "격리만" 은 *"지우지 않는다"* 가 아니라 *"폴더째가 아니라 그 파일만"* 이다.
    ///
    /// 그리고 `file.delete` 는 계획에 **나올 수 없는 Op** 이다
    /// (`derive::NOT_PLANNABLE_YET` — *"격리가 언제나 먼저 뽑힌다"*). 그래서 상한이
    /// 삭제 계열만 세던 동안 **파일 개수·해시·바이트 상한은 어떤 계획에도 걸리지
    /// 않았다.** 실측(2026-09-08): `total_files` 를 2 로 낮추고 파일 6개를 지우는
    /// 계획을 세워도 그대로 통과했다.
    ///
    /// 되돌릴 수 있다는 것과 한 번에 수만 개를 건드려도 좋다는 것은 다른 이야기다
    /// (결정 2026-09-08).
    pub fn removes_a_file(op: Op) -> bool {
        matches!(
            op,
            Op::FileQuarantineOnly | Op::FileDelete | Op::FileDeleteOnReboot
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **계획에 실제로 나오는 Op 을 세는가.** 이 시험이 없던 동안 상한은
    /// 나올 수 없는 Op 만 세고 있었다 (2026-09-08).
    #[test]
    fn 파일을_없애는_동작에는_격리가_들어간다() {
        assert!(Limits::removes_a_file(Op::FileQuarantineOnly));
        assert!(Limits::removes_a_file(Op::FileDelete));
        assert!(Limits::removes_a_file(Op::FileDeleteOnReboot));
        // 폴더째와 스트림 하나는 각자의 상한이 따로 있다.
        assert!(!Limits::removes_a_file(Op::DirDeleteRecursive));
        assert!(!Limits::removes_a_file(Op::FileDeleteStream));
        assert!(!Limits::removes_a_file(Op::ProcessKill));
    }

    /// 세는 Op 중 **적어도 하나는 계획에 나올 수 있어야 한다.** 전부
    /// `NOT_PLANNABLE_YET` 이면 그 상한은 죽은 규칙이다.
    #[test]
    fn 세는_동작이_전부_나올_수_없는_것은_아니다() {
        let dead: Vec<Op> = crate::derive::NOT_PLANNABLE_YET
            .iter()
            .map(|(op, _)| *op)
            .collect();
        let counted = [
            Op::FileQuarantineOnly,
            Op::FileDelete,
            Op::FileDeleteOnReboot,
        ];
        assert!(
            counted.iter().any(|op| !dead.contains(op)),
            "파일 상한이 세는 Op 이 전부 계획에 나올 수 없다 — 상한이 죽었다"
        );
    }

    #[test]
    fn defaults_satisfy_their_own_inequalities() {
        // 기본값이 부등식을 어기면 기동 자체가 안 된다. 가장 먼저 깨질 수 있는 곳이다.
        Limits::default().check().expect("기본값은 성립해야 한다");
    }

    #[test]
    fn per_action_limit_above_total_is_refused() {
        let l = Limits {
            recursive_children: 2000,
            total_files: 1000,
            ..Default::default()
        };
        let e = l.check().expect_err("기동을 거부해야 한다");
        assert!(
            e.message.contains("재현되지 않습니다"),
            "이유를 말해야 한다"
        );
    }

    #[test]
    fn zero_byte_limit_with_nonzero_file_limit_is_refused() {
        // 파일 1000개를 허용한다고 적고 바이트 0 을 걸면, 실제로는 아무것도
        // 지울 수 없는데 설정만 보면 넉넉해 보인다.
        let l = Limits {
            total_bytes: 0,
            ..Default::default()
        };
        assert!(l.check().is_err());
    }

    #[test]
    fn registry_key_delete_counts_as_recursive() {
        // 값 하나가 아니라 하위 트리 전체를 지운다. 같은 가드를 받아야 한다.
        assert!(Limits::is_recursive(Op::DirDeleteRecursive));
        assert!(Limits::is_recursive(Op::RegistryDeleteKey));
        assert!(!Limits::is_recursive(Op::FileDelete));
        assert!(!Limits::is_recursive(Op::RegistryDeleteValue));
    }
}
