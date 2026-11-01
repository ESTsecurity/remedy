//! 설정 파일 (설계-01 §7 "설정 파일 1개 + 명령행 인자", 설계-03 §4).
//!
//! # 왜 설정이 필요한가
//!
//! 상한은 정책 파라미터다. 초기값은 실측치가 아니라 출발점이고, 첫 플러그인의
//! 실제 감염 스냅샷을 보고 조정하게 된다(설계-03 §4). 그때마다 코어를 다시
//! 빌드해야 한다면 조정이 일어나지 않는다.
//!
//! # 검증은 로드 시점에 끝난다
//!
//! **부등식을 어긴 설정이면 기동을 거부한다.** 개별 Action 상한이 실행 전체
//! 상한을 넘으면 총계가 무의미해지고, 어느 쪽이 먼저 걸리는지가 계획 순서에
//! 따라 달라져 재현되지 않는다. 재현되지 않는 안전장치는 안전장치가 아니다.
//!
//! 잘못된 설정을 조용히 무시하고 기본값으로 도는 길은 두지 않았다. 그러면
//! 운영자는 자신이 설정한 상한이 걸려 있다고 믿는데 실제로는 다른 값이 돈다.
//!
//! # 형태
//!
//! YAML 이다. 파서가 이미 트리에 있고(`plugin.yaml`), 팀이 이미 쓰는 형식이다.
//! 파서를 하나 더 들이는 비용이 형식 취향보다 크다.
//!
//! 기본 경로는 두지 않는다. 암묵적으로 읽히는 설정은 "왜 이 값이 걸렸는가" 를
//! 추적 불가능하게 만든다. 경로는 `--config` 로 명시한다.

use remedy_plan::Limits;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_yaml_ng::Error,
    },
    /// 설정이 스스로 모순이다. **기동을 거부한다.**
    #[error("{msg} ({path})\n{message}", msg = remedy_sdk::i18n::t("설정이 스스로 모순입니다", "the configuration contradicts itself"))]
    Invalid { path: String, message: String },
}

/// 설정 파일 전체.
///
/// `deny_unknown_fields` 를 건다. 오타 난 키를 조용히 무시하면 운영자는 값을
/// 바꿨다고 믿는데 아무것도 바뀌지 않는다 — 상한 설정에서 가장 위험한 실패다.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub limits: LimitsConfig,
}

/// 상한 재정의. **적지 않은 항목은 기본값을 쓴다.**
///
/// 전부 `Option` 인 이유: 하나만 바꾸려고 여덟 개를 다 적게 만들면, 옮겨 적는
/// 과정에서 나머지 일곱 개가 낡는다.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    pub total_files: Option<u32>,
    pub same_hash_items: Option<u32>,
    pub total_bytes: Option<u64>,
    pub distinct_top_dirs: Option<u32>,
    pub evidence_groups: Option<u32>,
    pub recursive_children: Option<u32>,
    pub recursive_depth: Option<u32>,
    pub kill_targets: Option<u32>,
}

impl LimitsConfig {
    /// 기본값 위에 덮어쓴다.
    pub fn apply(&self, base: Limits) -> Limits {
        Limits {
            total_files: self.total_files.unwrap_or(base.total_files),
            same_hash_items: self.same_hash_items.unwrap_or(base.same_hash_items),
            total_bytes: self.total_bytes.unwrap_or(base.total_bytes),
            distinct_top_dirs: self.distinct_top_dirs.unwrap_or(base.distinct_top_dirs),
            evidence_groups: self.evidence_groups.unwrap_or(base.evidence_groups),
            recursive_children: self.recursive_children.unwrap_or(base.recursive_children),
            recursive_depth: self.recursive_depth.unwrap_or(base.recursive_depth),
            kill_targets: self.kill_targets.unwrap_or(base.kill_targets),
        }
    }
}

impl Config {
    /// 파일에서 읽고 **곧바로 검증한다.**
    ///
    /// 로드와 검증을 나누면 검증을 부르지 않는 호출자가 생기고, 그 경로에서는
    /// 모순된 설정이 그대로 돈다.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let p = path.display().to_string();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: p.clone(),
            source,
        })?;
        let cfg: Config = serde_yaml_ng::from_str(&text).map_err(|source| ConfigError::Parse {
            path: p.clone(),
            source,
        })?;
        cfg.limits().map_err(|message| ConfigError::Invalid {
            path: p,
            message: message.to_string(),
        })?;
        Ok(cfg)
    }

    /// 검증까지 끝난 상한.
    pub fn limits(&self) -> Result<Limits, remedy_plan::limits::LimitConfigError> {
        let l = self.limits.apply(Limits::default());
        l.check()?;
        Ok(l)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(name: &str, body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("remedy-core-config");
        std::fs::create_dir_all(&dir).expect("디렉터리");
        let p = dir.join(name);
        std::fs::write(&p, body).expect("쓰기");
        p
    }

    #[test]
    fn an_empty_config_is_the_defaults() {
        let p = write("empty.yaml", "{}\n");
        let c = Config::load(&p).expect("로드");
        assert_eq!(c.limits().unwrap(), Limits::default());
    }

    #[test]
    fn one_field_can_be_overridden_without_restating_the_rest() {
        // 하나 바꾸려고 여덟 개를 다 적게 만들면 나머지가 낡는다.
        let p = write("one.yaml", "limits:\n  total_files: 2000\n");
        let l = Config::load(&p).expect("로드").limits().unwrap();
        assert_eq!(l.total_files, 2000);
        assert_eq!(l.same_hash_items, Limits::default().same_hash_items);
    }

    #[test]
    fn lowering_only_the_total_trips_the_inequality() {
        // **운영자가 실제로 낼 실수다.** "더 안전하게 하려고" 총 삭제 상한만
        // 250 으로 낮추면, 기본값 그대로인 재귀 삭제 하위 항목 상한(500)이
        // 총계를 넘는다. 조용히 통과시키면 어느 쪽이 먼저 걸리는지가 계획
        // 순서에 따라 달라져 재현되지 않는다.
        //
        // 이 테스트를 쓰다가 실제로 걸렸다 — 그래서 남긴다.
        let p = write("lowered.yaml", "limits:\n  total_files: 250\n");
        let e = Config::load(&p).expect_err("거부해야 한다");
        let text = e.to_string();
        assert!(text.contains("250") && text.contains("500"), "{text}");
        // 무엇을 함께 낮춰야 하는지 알 수 있어야 한다.
        assert!(text.contains("재귀 삭제"), "{text}");
    }

    #[test]
    fn a_self_contradictory_config_refuses_to_start() {
        // **기동 거부** (설계-03 §4). 개별 상한이 총계를 넘으면 어느 쪽이 먼저
        // 걸리는지가 계획 순서에 따라 달라져 재현되지 않는다.
        let p = write(
            "bad.yaml",
            "limits:\n  total_files: 100\n  recursive_children: 500\n",
        );
        let e = Config::load(&p).expect_err("거부해야 한다");
        let text = e.to_string();
        assert!(
            text.contains("재현되지 않습니다"),
            "이유를 말해야 한다: {text}"
        );
        assert!(
            text.contains("100") && text.contains("500"),
            "두 값을 보여야 한다: {text}"
        );
    }

    #[test]
    fn a_typo_in_a_key_is_refused_not_ignored() {
        // 조용히 무시하면 운영자는 값을 바꿨다고 믿는데 아무것도 바뀌지 않는다.
        // 상한 설정에서 가장 위험한 실패다.
        let p = write("typo.yaml", "limits:\n  total_file: 250\n");
        assert!(Config::load(&p).is_err(), "오타 난 키는 거부되어야 한다");
    }

    #[test]
    fn a_missing_file_is_an_error_not_a_silent_default() {
        // 경로를 명시했는데 없으면 오타다. 기본값으로 조용히 도는 것이 가장 나쁘다.
        let p = std::env::temp_dir().join("remedy-core-config/없는파일.yaml");
        assert!(Config::load(&p).is_err());
    }
}
