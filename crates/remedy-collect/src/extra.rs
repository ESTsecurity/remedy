//! `collect_extra` — 분석에 필요한 것을 플러그인이 선언한다 (설계-02 §6-1).
//!
//! **파괴가 아니다.** 계획에 나타나지 않고, 승인 게이트를 거치지 않는다.
//! 그래서 상한이 더 중요하다 — `scan_roots` 밖은 담지 않고, 총 용량에 상한이 있다.
//!
//! # 왜 본문을 담는가
//!
//! 평가기는 `remedy-platform` 을 의존할 수 없다(설계-04 §1). YARA 가 훑을 바이트는
//! **수집 시점에 스냅샷에 담겨 있어야** 한다. 여기가 그 바이트가 들어오는 유일한
//! 문이고, 그래서 "아무 파일이나 담기지 않는다" 가 성립한다.
//!
//! # `ref` 형은 두 번째 패스에서 풀린다
//!
//! `{ ref: dropped-payload, content: true }` 는 **증거를 가리킨다.** 증거는
//! 평가가 만들고, 평가는 수집 뒤에 온다. 그래서 수집 시점에는 그 이름이 무엇을
//! 가리키는지 알 수 없다.
//!
//! 해소는 [`resolve_refs`] 가 **평가 뒤에** 한다. `collect` 단독 실행에는 증거가
//! 없으므로 풀 수 없고, 그 사실을 미해소로 보고한다 — 조용히 건너뛰면 그 본문에
//! 걸린 YARA 규칙이 영영 미평가인데 판정은 "안 맞았다" 로 나간다.

use remedy_artifacts::{FileRecord, Observations, Scope};
use remedy_platform::read::FsRead;
use remedy_sdk::artifact::{ArtifactsEnvelope, Evidence};
use remedy_sdk::catalog::{Platform, Subject};
use remedy_sdk::manifest::{CollectExtra, PluginManifest};
use remedy_sdk::normalize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// 본문 하나의 상한. `max_size` 가 없을 때 쓴다.
const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// 스냅샷에 담는 본문의 총합 상한.
///
/// 상한이 없으면 룰 하나가 `%APPDATA%` 를 통째로 담을 수 있다. 스냅샷은
/// 사내 분석 시스템으로 오가는 물건이고(설계-05), 개인정보가 그만큼 실려 간다.
const TOTAL_BUDGET: u64 = 64 * 1024 * 1024;

/// 해소하지 못한 `collect_extra` 항목.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unresolved {
    /// `collect_extra[0]` 형태.
    pub at: String,
    pub reason: String,
}

/// 본문을 담을 자리. 세 값이 늘 함께 움직인다.
///
/// 따로 넘기면 예산만 갱신하고 blob 을 안 넣거나, blob 만 넣고 레코드를 안 잇는
/// 조합이 생긴다. 앞의 것은 상한을 새게 하고 뒤의 것은 훑을 수 없는 본문을 만든다.
struct Sink<'a> {
    /// 이미 담긴 본문의 총 바이트.
    spent: u64,
    blobs: &'a mut BTreeMap<String, String>,
    files: &'a mut Vec<FileRecord>,
}

/// `ref` 형을 지금 보고할 것인가, 뒤에서 풀 것인가.
///
/// **두 실행 경로가 다르기 때문에 필요하다.** `collect` 단독은 증거가 없어서
/// 영영 풀 수 없고 그 사실이 보고되어야 한다. `scan`·`run` 은 평가 뒤에
/// [`resolve_refs`] 가 푼다 — 거기서 풀릴 것을 여기서 미리 "미해소" 라고 적으면
/// **해소된 항목이 미해소로 보고된다.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefPolicy {
    /// 증거가 생길 일이 없다. 지금 보고한다.
    ReportNow,
    /// 평가 뒤에 [`resolve_refs`] 가 푼다. 여기서는 건드리지 않는다.
    ResolveLater,
}

/// 선언된 추가 수집을 수행한다.
///
/// 담은 본문은 `Observations::blobs` 에, 그 참조는 해당 `file` 레코드의
/// `content_ref` 에 들어간다. 대상이 아직 `file` 로 수집되지 않았다면 레코드를
/// 만들어 넣는다 — 본문만 있고 그것이 어느 파일인지 모르는 상태를 만들지 않는다.
pub fn collect_extra<P: FsRead>(
    fs: &P,
    manifest: &PluginManifest,
    scope: &Scope,
    obs: &mut Observations,
    refs: RefPolicy,
) -> Vec<Unresolved> {
    // 이 사유들은 `scan`·`run` 의 stderr 로 그대로 나간다.
    let lang = remedy_sdk::i18n::current();
    let mut unresolved = Vec::new();
    let mut files: Vec<FileRecord> = obs.files();
    // **이미 담긴 것부터 센다.** 이진 레지스트리 값도 스냅샷에 실리고, 총량
    // 상한은 "스냅샷이 얼마나 커지는가" 에 대한 것이지 이 함수가 담은 양에
    // 대한 것이 아니다.
    let mut sink = Sink {
        spent: blob_bytes(&obs.blobs),
        blobs: &mut obs.blobs,
        files: &mut files,
    };

    for (i, item) in manifest.collect_extra.iter().enumerate() {
        let at = format!("collect_extra[{i}]");
        match item {
            CollectExtra::Ref(r) if refs == RefPolicy::ResolveLater => {
                let _ = r;
            }
            CollectExtra::Ref(r) => unresolved.push(Unresolved {
                at,
                reason: lang.pick(
                    format!(
                        "'{}' 는 증거 참조인데 이 실행에는 증거가 없습니다. 증거는 평가가 \
                         만들므로 `scan` 이나 `run` 으로 돌려야 이 항목이 해소됩니다",
                        r.rule_ref
                    ),
                    format!(
                        "'{}' is an evidence reference, but this run has no evidence. \
                         Evidence comes from evaluation, so run `scan` or `run` to resolve \
                         this item",
                        r.rule_ref
                    ),
                ),
            }),
            CollectExtra::Subject(s) => {
                // subject 형은 "이 경로를 이 subject 로도 보라" 는 뜻이다.
                // 파일 본문을 담는 형태가 아니므로 여기서 할 일은 경로 확인뿐이고,
                // 실제 수집은 그 subject 의 수집기가 `scan_roots` 안에서 한다.
                let path = normalize::for_record(&fs_expand(fs, &s.path), scope.platform);
                if !scope.allows(&path) {
                    unresolved.push(Unresolved {
                        at,
                        reason: lang.pick(
                            format!("'{path}' 가 scan_roots 밖입니다"),
                            format!("'{path}' is outside scan_roots"),
                        ),
                    });
                    continue;
                }
                if !scope.subjects.contains(&s.subject) {
                    unresolved.push(Unresolved {
                        at,
                        reason: lang.pick(
                            format!(
                                "subject '{}' 가 선언되지 않았습니다 — subjects 에 넣어야 수집됩니다",
                                s.subject.id()
                            ),
                            format!(
                                "subject '{}' is not declared — add it to subjects to have it \
                                 collected",
                                s.subject.id()
                            ),
                        ),
                    });
                }
            }
            CollectExtra::Path(p) => {
                let path = normalize::for_record(&fs_expand(fs, &p.path), scope.platform);
                let cap = parse_size(p.max_size.as_deref()).unwrap_or(DEFAULT_MAX_BYTES);
                if let Err(reason) = take_body(fs, &path, cap, scope, &mut sink) {
                    unresolved.push(Unresolved { at, reason });
                }
            }
            CollectExtra::Glob(g) => {
                let pattern = normalize::for_record(&fs_expand(fs, &g.glob), scope.platform);
                let cap = parse_size(g.max_size.as_deref()).unwrap_or(DEFAULT_MAX_BYTES);
                let Some((dir, name)) = split_glob(&pattern) else {
                    unresolved.push(Unresolved {
                        at,
                        reason: lang.pick(
                            format!(
                                "'{pattern}' 가 폴더와 이름 꼴로 나뉘지 않습니다 — \
                                 와일드카드는 마지막 성분에만 둡니다"
                            ),
                            format!(
                                "'{pattern}' does not split into a folder and a name \
                                 pattern — wildcards go in the last component only"
                            ),
                        ),
                    });
                    continue;
                };
                // 폴더가 상한 밖이면 고를 레코드가 없어 **조용히 0건**이 된다 — 말한다.
                if !scope.allows(dir) {
                    unresolved.push(Unresolved {
                        at,
                        reason: lang.pick(
                            format!("'{dir}' 가 scan_roots 밖입니다"),
                            format!("'{dir}' is outside scan_roots"),
                        ),
                    });
                    continue;
                }
                // 폴더가 없으면 고를 것이 없다 — 없는 것이지 못 본 것이 아니다.
                for path in globbed(sink.files, dir, name, scope.platform) {
                    if let Err(reason) = take_body(fs, &path, cap, scope, &mut sink) {
                        unresolved.push(Unresolved {
                            at: at.clone(),
                            reason,
                        });
                    }
                }
            }
        }
    }

    if !manifest.collect_extra.is_empty() && scope.subjects.contains(&Subject::File) {
        files.sort_by(|a, b| a.path.cmp(&b.path));
        obs.put(Subject::File, &files);
    }
    unresolved
}

/// 몇 건을 담았는가와, 못 담은 것들.
#[derive(Debug, Default)]
pub struct RefPass {
    /// 새로 담긴 본문 수. **0 이면 다시 평가할 이유가 없다.**
    pub taken: usize,
    pub unresolved: Vec<Unresolved>,
}

/// 증거를 가리키는 `ref` 형을 해소한다. **평가 뒤에 부른다.**
///
/// # 왜 두 번째 패스인가
///
/// `{ ref: dropped-payload, content: true }` 는 증거를 가리키고, 증거는 평가가
/// 만든다. 수집 시점에는 이 이름이 무엇을 가리키는지 알 수 없다.
///
/// # 한 번만 돈다
///
/// 두 번째 평가가 만든 증거로 또 `ref` 를 풀면 패스 수가 데이터에 좌우된다.
/// 그러면 "이 실행이 무엇을 읽는가" 를 미리 말할 수 없고, 수집 예산의 상한도
/// 사라진다. 한 번 돌고 **남은 것은 보고**한다.
///
/// # 결정성은 유지된다
///
/// 저장되는 `artifacts.json` 은 **이 함수가 끝난 뒤의 것**이다. 그러므로
/// `evaluate(저장된 artifacts.json)` 은 저장된 `scan.json` 을 재현한다
/// (설계-01 D9 결정 2).
pub fn resolve_refs<P: FsRead>(
    fs: &P,
    manifest: &PluginManifest,
    scope: &Scope,
    evidence: &[Evidence],
    env: &mut ArtifactsEnvelope,
) -> RefPass {
    let lang = remedy_sdk::i18n::current();
    let mut out = RefPass::default();
    let mut files: Vec<FileRecord> = env
        .body
        .observations
        .get(Subject::File.id())
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let mut sink = Sink {
        spent: blob_bytes(&env.body.blobs),
        blobs: &mut env.body.blobs,
        files: &mut files,
    };

    for (i, item) in manifest.collect_extra.iter().enumerate() {
        let CollectExtra::Ref(r) = item else { continue };
        let at = format!("collect_extra[{i}]");

        // **가리키는 룰이 아예 없는 것과, 있는데 안 맞은 것은 다르다.**
        // 앞의 것은 영영 해소되지 않는 선언이고 아무도 모른 채 지나간다.
        // 뒤의 것은 담을 것이 없는 것이 정상이다.
        if !manifest.detect.iter().any(|d| d.id == r.rule_ref) {
            out.unresolved.push(Unresolved {
                at,
                reason: lang.pick(
                    format!("'{}' 라는 detect 룰이 없습니다", r.rule_ref),
                    format!("there is no detect rule named '{}'", r.rule_ref),
                ),
            });
            continue;
        }
        // `content` 를 켜지 않았으면 담을 것이 없다. 선언대로 한 것이므로
        // 미해소가 아니다 — 이 항목은 `submit_hint` 가 볼 표식이다.
        if !r.content {
            continue;
        }
        if !scope.subjects.contains(&Subject::File) {
            out.unresolved.push(Unresolved {
                at,
                reason: lang
                    .t(
                        "subject 'file' 이 선언되지 않아 본문을 이을 레코드가 없습니다 — \
                         본문만 담으면 그것이 어느 파일인지 알 수 없습니다",
                        "subject 'file' is not declared, so there is no record to attach a \
                         body to — a body on its own does not say which file it came from",
                    )
                    .into(),
            });
            continue;
        }

        for e in evidence.iter().filter(|e| e.rule == r.rule_ref) {
            // **파일만 본문이 있다.** 다른 subject 의 `source`·`id` 는 경로처럼
            // 보여도 파일이 아닐 수 있다(레지스트리 키 등).
            let Some(path) = e.target.get("path").and_then(|v| v.as_str()) else {
                out.unresolved.push(Unresolved {
                    at: at.clone(),
                    reason: lang.pick(
                        format!(
                            "증거 '{}'(subject '{}')에는 담을 본문이 없습니다",
                            e.id,
                            e.subject.id()
                        ),
                        format!(
                            "evidence '{}' (subject '{}') has no body to capture",
                            e.id,
                            e.subject.id()
                        ),
                    ),
                });
                continue;
            };
            let path = normalize::for_record(path, scope.platform);
            match take_body(fs, &path, DEFAULT_MAX_BYTES, scope, &mut sink) {
                Ok(()) => out.taken += 1,
                Err(reason) => out.unresolved.push(Unresolved {
                    at: at.clone(),
                    reason,
                }),
            }
        }
    }

    if out.taken > 0 {
        files.sort_by(|a, b| a.path.cmp(&b.path));
        env.body.observations.insert(
            Subject::File.id().to_string(),
            serde_json::to_value(&files).expect("레코드 직렬화는 실패할 수 없다"),
        );
    }
    out
}

/// 본문 하나를 담는다. 못 담았으면 **왜 못 담았는지**를 돌려준다.
///
/// 조용히 빠지면 그 대상에 걸린 YARA 규칙이 영영 미평가인데 아무도 모르고,
/// 판정은 "안 맞았다" 로 나간다.
fn take_body<P: FsRead>(
    fs: &P,
    path: &str,
    cap: u64,
    scope: &Scope,
    sink: &mut Sink<'_>,
) -> Result<(), String> {
    // **상한 밖은 담지 않는다.** 플러그인이 적은 경로든 증거에서 파생된
    // 경로든 승인 게이트를 거치지 않으며, 파생 경로는 공격자가 영향을 줄 수
    // 있는 값이다 (설계-02 §4).
    let lang = remedy_sdk::i18n::current();
    if !scope.allows(path) {
        return Err(lang.pick(
            format!("'{path}' 가 scan_roots 밖입니다"),
            format!("'{path}' is outside scan_roots"),
        ));
    }
    if sink.spent >= TOTAL_BUDGET {
        let mb = TOTAL_BUDGET / (1024 * 1024);
        return Err(lang.pick(
            format!("본문 총량 상한 {mb}MB 에 도달했습니다 — 이 항목은 담기지 않았습니다"),
            format!("the total body cap of {mb}MB was reached — this item was not captured"),
        ));
    }
    let bytes = match fs.read_file(path, cap.min(TOTAL_BUDGET - sink.spent)) {
        Ok(Some(b)) => b,
        Ok(None) => {
            return Err(lang.pick(
                format!("'{path}' 가 상한 {cap} 바이트를 넘어 담지 않았습니다"),
                format!("'{path}' exceeds the {cap}-byte cap and was not captured"),
            ))
        }
        Err(e) => {
            return Err(lang.pick(
                format!("'{path}' 를 읽지 못했습니다: {e}"),
                format!("'{path}' could not be read: {e}"),
            ))
        }
    };
    sink.spent += bytes.len() as u64;

    // 키가 내용 해시라 같은 파일이 여러 자리에 있어도 한 번만 담긴다.
    let key = format!("sha256:{:x}", Sha256::digest(&bytes));
    if !sink.blobs.contains_key(&key) {
        use base64::Engine;
        sink.blobs.insert(
            key.clone(),
            base64::engine::general_purpose::STANDARD.encode(&bytes),
        );
    }
    attach(sink.files, path, &key, &bytes);
    Ok(())
}

/// 이미 담긴 본문의 원본 바이트 총합.
///
/// **디코딩하지 않는다.** 예산을 세자고 최대 64MB 를 다시 디코딩할 이유가 없고,
/// 표준 base64 는 길이만으로 원본 크기가 정해진다.
fn blob_bytes(blobs: &BTreeMap<String, String>) -> u64 {
    blobs
        .values()
        .map(|b| {
            let n = b.len() as u64;
            if n < 4 {
                return 0;
            }
            let pad = b.bytes().rev().take_while(|c| *c == b'=').count() as u64;
            n / 4 * 3 - pad
        })
        .sum()
}

/// 담은 본문을 그 파일의 레코드에 잇는다.
///
/// 레코드가 없으면 만든다. 본문만 있고 그것이 어느 파일인지 모르는 상태를
/// 만들지 않기 위해서다 — 룰은 `path` 로 대상을 고르고 `content_ref` 로 훑는다.
fn attach(files: &mut Vec<FileRecord>, path: &str, key: &str, bytes: &[u8]) {
    let sha = key.trim_start_matches("sha256:").to_string();
    if let Some(rec) = files.iter_mut().find(|f| f.path.eq_ignore_ascii_case(path)) {
        rec.content_ref = Some(key.to_string());
        // 해시 상한 때문에 비어 있었다면 여기서 채운다. 이미 있으면 건드리지
        // 않는다 — 본문을 담은 시점과 해시를 뜬 시점이 다를 수 있다.
        if rec.sha256.is_none() {
            rec.sha256 = Some(sha);
        }
        // 버전도 같다 (C-1b). 주 수집이 상한 때문에 읽지 못한 파일을 여기서
        // 담았다면 그 바이트에 버전이 있다 — `max_size` 로 상한을 올린 `path`
        // 형이 정확히 그 자리다. 이미 있으면 건드리지 않는다.
        if rec.version.is_none() {
            rec.version = crate::peversion::of(path, bytes);
        }
        return;
    }
    files.push(FileRecord {
        path: path.to_string(),
        size: bytes.len() as u64,
        // 수집 시각을 여기서 읽지 않는다. 이 레코드는 본문을 잇기 위한 것이고,
        // 시각을 지어내면 diff 가 매번 달라진다.
        mtime: String::new(),
        ctime: None,
        sha256: Some(sha),
        // 주 수집에 없던 파일이다(있었으면 위에서 돌아갔다). 그쪽과 같은 규칙으로
        // 채워야 같은 파일이 경로에 따라 다른 값을 갖지 않는다.
        signature: crate::signature::of(path, false),
        version: crate::peversion::of(path, bytes),
        zone: None,
        streams: Vec::new(),
        content_ref: Some(key.to_string()),
    });
}

/// `<폴더>/<이름 꼴>` 로 나눈다. 와일드카드가 폴더 쪽에 있으면 `None` — 한 폴더 안만
/// 고르므로 담는 범위가 선언에서 바로 읽힌다.
fn split_glob(pattern: &str) -> Option<(&str, &str)> {
    let cut = pattern.rfind(['/', '\\'])?;
    let (dir, name) = (&pattern[..cut], &pattern[cut + 1..]);
    if dir.is_empty() || name.is_empty() || dir.contains(['*', '?']) {
        return None;
    }
    Some((dir, name))
}

/// 주 수집이 걸은 레코드 가운데 `dir` 바로 아래에서 이름이 `name` 꼴인 것.
///
/// **해시가 있는 것만** 고른다 — 주 수집은 링크와 해시 상한을 넘는 파일을 해시하지
/// 않는다. 링크를 고르면 대상의 바이트가 링크의 경로에 적힌다(설계-02 §4 가 걷기에서
/// 막은 것이다).
fn globbed(files: &[FileRecord], dir: &str, name: &str, platform: Platform) -> Vec<String> {
    let dir = normalize::for_compare(dir, platform);
    let name = normalize::for_compare(name, platform);
    files
        .iter()
        .filter(|f| f.sha256.is_some())
        .filter(|f| {
            let p = normalize::for_compare(&f.path, platform);
            p.rfind(['/', '\\'])
                .is_some_and(|cut| p[..cut] == dir && name_matches(&p[cut + 1..], &name))
        })
        .map(|f| f.path.clone())
        .collect()
}

/// 이름 하나에 `*`(아무 길이) · `?`(한 글자)를 맞춘다. 되돌아가기는 마지막 별에서만
/// 하므로 이름 길이 × 꼴 길이를 넘지 않는다 — 정규식처럼 터지지 않는다.
fn name_matches(text: &str, pattern: &str) -> bool {
    let t: Vec<char> = text.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    let (mut ti, mut pi) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || (p[pi] != '*' && p[pi] == t[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi + 1, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

fn fs_expand<P: FsRead>(_fs: &P, s: &str) -> String {
    // `FsRead` 는 전개를 모른다. 토큰 전개는 `Scope` 를 만들 때 이미 끝났고,
    // 여기 오는 경로는 매니페스트 원문이므로 남은 토큰만 그대로 둔다.
    s.to_string()
}

/// `1MB` · `512KB` · `2048` 같은 표기를 바이트로.
fn parse_size(s: Option<&str>) -> Option<u64> {
    let s = s?.trim();
    let upper = s.to_ascii_uppercase();
    let (num, mul) = if let Some(n) = upper.strip_suffix("KB") {
        (n, 1024)
    } else if let Some(n) = upper.strip_suffix("MB") {
        (n, 1024 * 1024)
    } else if let Some(n) = upper.strip_suffix("GB") {
        (n, 1024 * 1024 * 1024)
    } else if let Some(n) = upper.strip_suffix('B') {
        (n, 1)
    } else {
        (upper.as_str(), 1)
    };
    num.trim().parse::<u64>().ok()?.checked_mul(mul)
}

#[cfg(test)]
mod tests {
    use super::*;
    use remedy_platform::read::{FsEntry, WalkResult};
    use remedy_platform::PlatformError;
    use std::collections::BTreeMap;

    /// **데이터는 빼고 우리 문구만 본다.** `'…'` 안은 플러그인이 적은 경로나
    /// 룰 이름이고, 그것이 한국어인 것은 우리가 고칠 수 있는 일이 아니다 —
    /// §3 이 캡처에서 "입력 에코는 우리 문구가 아니다" 로 가른 것과 같다.
    fn 우리_문구만(s: &str) -> String {
        let mut out = String::new();
        let mut inside = false;
        for c in s.chars() {
            match c {
                '\'' => inside = !inside,
                _ if !inside => out.push(c),
                _ => {}
            }
        }
        out
    }

    fn 한글이_있는가(s: &str) -> bool {
        우리_문구만(s).chars().any(|c| ('가'..='힣').contains(&c))
    }

    /// **해소되지 않은 사유는 `scan`·`run` 의 stderr 로 그대로 나간다** —
    /// `main.rs` 의 `warn_unresolved_extra` 가 `at: reason` 으로 찍는다. 틀은 이미
    /// 두 언어인데 사유가 한국어면 한 줄 안에서 언어가 섞인다(§3 이 복원 화면에서
    /// 본 것과 같은 모양).
    ///
    /// **이름을 그대로 둔 것**은 아래 시험 아홉을 고치지 않기 위해서다 —
    /// `use super::*` 로 들어온 이름을 로컬 정의가 가린다.
    fn collect_extra<P: FsRead>(
        fs: &P,
        manifest: &PluginManifest,
        scope: &Scope,
        obs: &mut Observations,
        refs: RefPolicy,
    ) -> Vec<Unresolved> {
        let v = super::collect_extra(fs, manifest, scope, obs, refs);
        for u in &v {
            assert!(
                !한글이_있는가(&u.reason),
                "해소 실패 사유가 영어 회차에서 한글로 나온다 ({}): {}",
                u.at,
                u.reason
            );
        }
        v
    }

    /// 두 번째 패스도 같은 자리로 나간다.
    fn resolve_refs<P: FsRead>(
        fs: &P,
        manifest: &PluginManifest,
        scope: &Scope,
        evidence: &[Evidence],
        env: &mut ArtifactsEnvelope,
    ) -> RefPass {
        let p = super::resolve_refs(fs, manifest, scope, evidence, env);
        for u in &p.unresolved {
            assert!(
                !한글이_있는가(&u.reason),
                "해소 실패 사유가 영어 회차에서 한글로 나온다 ({}): {}",
                u.at,
                u.reason
            );
        }
        p
    }

    /// 두 번째 칸은 **마지막으로 받은 읽기 상한**이다.
    ///
    /// 예산이 실제로 쓰이는지 재려면 64MB 짜리 blob 을 만들어야 하는데, 그것을
    /// 시험마다 만들 이유가 없다. 상한이 어떻게 계산되어 내려오는지를 보면
    /// 같은 것을 정확히 잴 수 있다.
    struct FakeFs(BTreeMap<String, Vec<u8>>, std::cell::Cell<u64>);

    impl FsRead for FakeFs {
        fn walk(&self, _root: &str, _limit: usize) -> Result<WalkResult, PlatformError> {
            Ok(WalkResult {
                entries: Vec::<FsEntry>::new(),
                truncated: false,
                denied: 0,
                denied_paths: Vec::new(),
            })
        }
        fn read_file(&self, path: &str, max: u64) -> Result<Option<Vec<u8>>, PlatformError> {
            self.1.set(max);
            match self.0.get(path) {
                Some(b) if b.len() as u64 > max => Ok(None),
                Some(b) => Ok(Some(b.clone())),
                None => Err(PlatformError::Unsupported("없는 파일")),
            }
        }
        fn look(&self, path: &str) -> remedy_platform::read::Seen {
            if self.0.contains_key(path) {
                remedy_platform::read::Seen::Present
            } else {
                remedy_platform::read::Seen::Absent
            }
        }
    }

    fn manifest(extra: &str) -> PluginManifest {
        let yaml = format!(
            r#"
schema_version: 1
id: t
version: 1.0.0
min_core: "1.0.0"
platforms: [windows]
name: {{ ko: "t", en: "t" }}
scan_roots: ['c:\app']
subjects: [file]
detect:
  - id: r
    subject: file
    where:
      - {{ field: path, op: ends_with, value: '\x.dat' }}
verdict: {{ require: "r" }}
collect_extra:
{extra}
"#
        );
        serde_yaml_ng::from_str(&yaml).expect("매니페스트")
    }

    fn scope() -> Scope {
        let mut s = Scope::diagnostic(
            vec!["c:\\app".into()],
            remedy_sdk::catalog::Platform::Windows,
        );
        s.subjects = vec![Subject::File];
        s
    }

    fn fs(files: &[(&str, &[u8])]) -> FakeFs {
        FakeFs(
            files
                .iter()
                .map(|(p, b)| (p.to_string(), b.to_vec()))
                .collect(),
            std::cell::Cell::new(u64::MAX),
        )
    }

    /// 이 크기의 본문이 이미 담긴 스냅샷.
    fn with_blob(bytes: usize) -> BTreeMap<String, String> {
        use base64::Engine;
        [(
            "sha256:기존".to_string(),
            base64::engine::general_purpose::STANDARD.encode(vec![9u8; bytes]),
        )]
        .into_iter()
        .collect()
    }

    /// 예산을 **다 쓴** 스냅샷.
    ///
    /// 실제로 64MB 를 인코딩하지 않는다. `blob_bytes` 는 설계상 **길이만 보므로**
    /// 그 길이의 문자열이면 충분하다 — 여기서 64MB 를 진짜로 만들면 이 시험
    /// 하나가 나머지 전부보다 오래 걸린다.
    fn blobs_at_budget() -> BTreeMap<String, String> {
        let len = (TOTAL_BUDGET as usize).div_ceil(3) * 4;
        let m: BTreeMap<String, String> = [("sha256:가득".to_string(), "A".repeat(len))]
            .into_iter()
            .collect();
        assert!(blob_bytes(&m) >= TOTAL_BUDGET, "재료가 예산에 못 미친다");
        m
    }

    /// 주 수집이 남긴 레코드 — `hashed` 가 거짓이면 링크처럼 해시가 없다.
    fn walked(paths: &[(&str, bool)]) -> Observations {
        let records: Vec<FileRecord> = paths
            .iter()
            .map(|(p, hashed)| FileRecord {
                path: p.to_string(),
                size: 1,
                mtime: "2026-11-06T00:00:00Z".into(),
                ctime: None,
                sha256: hashed.then(|| "00".repeat(32)),
                signature: None,
                version: None,
                zone: None,
                streams: Vec::new(),
                content_ref: None,
            })
            .collect();
        let mut obs = Observations::default();
        obs.put(Subject::File, &records);
        obs
    }

    fn linux_scope() -> Scope {
        let mut s = Scope::diagnostic(
            vec!["/usr/lib64".into()],
            remedy_sdk::catalog::Platform::Linux,
        );
        s.subjects = vec![Subject::File];
        s
    }

    #[test]
    fn a_glob_takes_the_hashed_files_of_one_folder_whose_names_match() {
        // 이름이 감염마다 다른 파일을 규칙 없이 담는 자리다. 링크 · 다른 이름 · 하위
        // 폴더는 고르지 않는다.
        let f = fs(&[
            ("/usr/lib64/libkeyutils.so.1.5", b"clean"),
            ("/usr/lib64/libkeyutils.so.1.5.2", b"fake"),
            ("/usr/lib64/libkeyutils.so.1", b"fake"),
            ("/usr/lib64/libcrypt.so.1", b"other"),
            ("/usr/lib64/sub/libkeyutils.so.9", b"deeper"),
        ]);
        let m = manifest("  - { glob: '/usr/lib64/libkeyutils*' }");
        let mut obs = walked(&[
            ("/usr/lib64/libkeyutils.so.1.5", true),
            ("/usr/lib64/libkeyutils.so.1.5.2", true),
            ("/usr/lib64/libkeyutils.so.1", false),
            ("/usr/lib64/libcrypt.so.1", true),
            ("/usr/lib64/sub/libkeyutils.so.9", true),
        ]);
        let un = collect_extra(&f, &m, &linux_scope(), &mut obs, RefPolicy::ReportNow);
        assert!(un.is_empty(), "{un:?}");
        let taken: Vec<String> = obs
            .files()
            .into_iter()
            .filter(|r| r.content_ref.is_some())
            .map(|r| r.path)
            .collect();
        assert_eq!(
            taken,
            [
                "/usr/lib64/libkeyutils.so.1.5",
                "/usr/lib64/libkeyutils.so.1.5.2"
            ],
            "링크 · 다른 이름 · 하위 폴더를 골랐거나 맞는 것을 빠뜨렸다"
        );
        assert_eq!(obs.blobs.len(), 2);
    }

    #[test]
    fn a_glob_over_a_missing_folder_takes_nothing_and_reports_nothing() {
        // 그 배포판에 그 자리가 없는 것은 정상이다 — 못 본 것이 아니다.
        let m = manifest("  - { glob: '/usr/lib64/libkeyutils*' }");
        let mut obs = walked(&[]);
        let un = collect_extra(&fs(&[]), &m, &linux_scope(), &mut obs, RefPolicy::ReportNow);
        assert!(un.is_empty(), "{un:?}");
        assert!(obs.blobs.is_empty());
    }

    #[test]
    fn a_glob_folder_outside_scan_roots_is_reported() {
        // 상한 밖 폴더에는 레코드가 없어 조용히 0건이 된다 — 그것을 말한다.
        let m = manifest("  - { glob: '/etc/libkeyutils*' }");
        let mut obs = walked(&[]);
        let un = collect_extra(&fs(&[]), &m, &linux_scope(), &mut obs, RefPolicy::ReportNow);
        assert_eq!(un.len(), 1, "{un:?}");
        assert!(
            un[0]
                .reason
                .contains(remedy_sdk::i18n::t("scan_roots 밖", "outside scan_roots")),
            "{:?}",
            un[0]
        );
    }

    #[test]
    fn a_wildcard_in_the_folder_part_is_reported_not_guessed() {
        let m = manifest("  - { glob: '/usr/*/libkeyutils*' }");
        let mut obs = walked(&[("/usr/lib64/libkeyutils.so.1.5", true)]);
        let f = fs(&[("/usr/lib64/libkeyutils.so.1.5", b"clean")]);
        let un = collect_extra(&f, &m, &linux_scope(), &mut obs, RefPolicy::ReportNow);
        assert_eq!(un.len(), 1, "{un:?}");
        assert!(obs.blobs.is_empty(), "폴더를 짐작해 담았다");
    }

    #[test]
    fn a_windows_glob_folds_case_like_the_rest_of_the_paths() {
        let f = fs(&[("c:\\app\\Payload.DLL", b"x")]);
        let m = manifest("  - { glob: 'C:\\APP\\payload.*' }");
        let mut obs = walked(&[("c:\\app\\Payload.DLL", true)]);
        let un = collect_extra(&f, &m, &scope(), &mut obs, RefPolicy::ReportNow);
        assert!(un.is_empty(), "{un:?}");
        assert_eq!(obs.blobs.len(), 1, "대소문자만 다른 이름을 놓쳤다");
    }

    #[test]
    fn names_match_stars_and_question_marks_only() {
        for (t, p, want) in [
            ("libkeyutils.so.1.5.2", "libkeyutils*", true),
            ("libkeyutils.so.1", "libkeyutils.so.?", true),
            ("libkeyutils.so.10", "libkeyutils.so.?", false),
            ("x.dll", "*.dll", true),
            ("a.b.c", "*.*", true),
            ("abc", "a*c*", true),
            ("abd", "a*c", false),
            ("", "*", true),
            ("", "?", false),
            ("aaaaaaaaaaaaaaaaaaaaaaab", "*a*a*a*a*b", true),
        ] {
            assert_eq!(name_matches(t, p), want, "{t:?} ~ {p:?}");
        }
    }

    #[test]
    fn a_declared_path_lands_in_blobs_and_is_linked_from_the_record() {
        // 본문만 있고 그것이 어느 파일인지 모르는 상태를 만들지 않는다.
        let f = fs(&[("c:\\app\\payload.js", b"console.log('x')")]);
        let m = manifest("  - { path: 'c:\\app\\payload.js' }");
        let mut obs = Observations::default();
        let un = collect_extra(&f, &m, &scope(), &mut obs, RefPolicy::ReportNow);

        assert!(un.is_empty(), "{un:?}");
        assert_eq!(obs.blobs.len(), 1);
        let files = obs.files();
        assert_eq!(files.len(), 1);
        let key = files[0].content_ref.clone().expect("content_ref");
        assert!(
            obs.blobs.contains_key(&key),
            "참조가 blobs 를 가리키지 않는다"
        );
        assert!(key.starts_with("sha256:"));
    }

    #[test]
    fn the_same_bytes_are_stored_once() {
        let f = fs(&[("c:\\app\\a.js", b"same"), ("c:\\app\\b.js", b"same")]);
        let m = manifest("  - { path: 'c:\\app\\a.js' }\n  - { path: 'c:\\app\\b.js' }");
        let mut obs = Observations::default();
        collect_extra(&f, &m, &scope(), &mut obs, RefPolicy::ReportNow);
        assert_eq!(obs.blobs.len(), 1, "같은 바이트가 두 번 담겼다");
        assert_eq!(obs.files().len(), 2, "파일은 둘 다 기록되어야 한다");
    }

    #[test]
    fn a_path_outside_scan_roots_is_refused_and_reported() {
        // 이 경로는 플러그인이 적은 것이고 승인 게이트를 거치지 않는다.
        let f = fs(&[("c:\\문서\\비밀.docx", b"x")]);
        let m = manifest("  - { path: 'c:\\문서\\비밀.docx' }");
        let mut obs = Observations::default();
        let un = collect_extra(&f, &m, &scope(), &mut obs, RefPolicy::ReportNow);
        assert_eq!(un.len(), 1);
        assert!(
            un[0]
                .reason
                .contains(remedy_sdk::i18n::t("scan_roots 밖", "outside scan_roots")),
            "{:?}",
            un[0]
        );
        assert!(obs.blobs.is_empty());
    }

    #[test]
    fn a_ref_form_in_a_collect_only_run_says_to_use_scan() {
        // `collect` 단독에는 증거가 없다. 조용히 건너뛰면 그 본문에 걸린 YARA
        // 규칙이 영영 미평가인데 아무도 모른다 — 그리고 **무엇을 해야 하는지**
        // 까지 말해야 작성자가 그 자리에서 고친다.
        let m = manifest("  - { ref: r, content: true }");
        let mut obs = Observations::default();
        let un = collect_extra(&fs(&[]), &m, &scope(), &mut obs, RefPolicy::ReportNow);
        assert_eq!(un.len(), 1);
        assert!(
            un[0]
                .reason
                .contains(remedy_sdk::i18n::t("증거", "evidence")),
            "{:?}",
            un[0]
        );
        assert!(
            un[0].reason.contains("scan"),
            "할 일을 안 알려준다: {:?}",
            un[0]
        );
    }

    #[test]
    fn a_ref_form_is_left_alone_when_it_will_be_resolved_later() {
        // 뒤에서 풀릴 것을 여기서 "미해소" 라고 적으면 **해소된 항목이
        // 미해소로 보고된다.**
        let m = manifest("  - { ref: r, content: true }");
        let mut obs = Observations::default();
        let un = collect_extra(&fs(&[]), &m, &scope(), &mut obs, RefPolicy::ResolveLater);
        assert!(un.is_empty(), "{un:?}");
    }

    // ─────────────────────────────────────────── 두 번째 패스

    /// 증거 하나. `target.path` 가 본문을 담을 자리를 가리킨다.
    fn evidence(rule: &str, path: Option<&str>) -> Evidence {
        Evidence {
            id: format!("{rule}#0"),
            rule: rule.into(),
            subject: if path.is_some() {
                Subject::File
            } else {
                Subject::RegistryValue
            },
            score: None,
            target: match path {
                Some(p) => serde_json::json!({ "path": p }),
                None => serde_json::json!({ "hive": "HKLM", "key": "SOFTWARE\\X" }),
            },
            captures: Default::default(),
            matched: Vec::new(),
        }
    }

    fn envelope(scope: &Scope, obs: Observations) -> ArtifactsEnvelope {
        remedy_artifacts::assemble(
            "r".into(),
            "2026-08-22T00:00:00Z".into(),
            remedy_sdk::artifact::HostInfo {
                hostname: "T".into(),
                os: "windows".into(),
                version: "10".into(),
                arch: "amd64".into(),
            },
            remedy_sdk::artifact::CoreInfo {
                version: "0".into(),
                build: "dev".into(),
            },
            scope,
            obs,
        )
    }

    #[test]
    fn a_ref_pulls_the_body_of_what_its_rule_matched() {
        // 이것이 `ref` 형의 존재 이유다 — 매니페스트를 쓸 때는 경로를 모르고,
        // 평가가 그 경로를 찾아낸다.
        let f = fs(&[("c:\\app\\dropped.js", b"eval(atob('...'))")]);
        let m = manifest("  - { ref: r, content: true }");
        let sc = scope();
        let mut env = envelope(&sc, Observations::default());

        let pass = resolve_refs(
            &f,
            &m,
            &sc,
            &[evidence("r", Some("c:\\app\\dropped.js"))],
            &mut env,
        );
        assert_eq!(pass.taken, 1, "{:?}", pass.unresolved);
        assert!(pass.unresolved.is_empty(), "{:?}", pass.unresolved);
        assert_eq!(env.body.blobs.len(), 1);

        // 본문만 담고 끝나면 룰이 그것을 훑을 길이 없다. `content_ref` 가
        // 이어져 있어야 한다.
        let files: Vec<FileRecord> =
            serde_json::from_value(env.body.observations["file"].clone()).unwrap();
        let key = files[0].content_ref.clone().expect("content_ref");
        assert!(env.body.blobs.contains_key(&key));
    }

    #[test]
    fn a_ref_to_a_rule_that_matched_nothing_is_not_an_error() {
        // 그 룰이 안 맞은 것은 정상이다. 담을 것이 없을 뿐이다.
        let m = manifest("  - { ref: r, content: true }");
        let sc = scope();
        let mut env = envelope(&sc, Observations::default());
        let pass = resolve_refs(&fs(&[]), &m, &sc, &[], &mut env);
        assert_eq!(pass.taken, 0);
        assert!(pass.unresolved.is_empty(), "{:?}", pass.unresolved);
    }

    #[test]
    fn a_ref_to_a_rule_that_does_not_exist_is_reported() {
        // **없는 룰을 가리키는 것과 안 맞은 것은 다르다.** 앞의 것은 영영
        // 해소되지 않는 선언이고, 조용히 두면 아무도 모른 채 지나간다.
        let m = manifest("  - { ref: 없는룰, content: true }");
        let sc = scope();
        let mut env = envelope(&sc, Observations::default());
        let pass = resolve_refs(&fs(&[]), &m, &sc, &[], &mut env);
        assert_eq!(pass.unresolved.len(), 1);
        assert!(
            pass.unresolved[0]
                .reason
                .contains(remedy_sdk::i18n::t("없습니다", "no detect rule")),
            "{pass:?}"
        );
    }

    #[test]
    fn a_derived_path_outside_scan_roots_is_refused() {
        // 파생 경로는 **공격자가 영향을 줄 수 있는 값**이다. 그것이 상한을
        // 넘게 만들 수 있다면 상한이 아니다 (설계-02 §4).
        let f = fs(&[("c:\\문서\\비밀.docx", b"x")]);
        let m = manifest("  - { ref: r, content: true }");
        let sc = scope();
        let mut env = envelope(&sc, Observations::default());
        let pass = resolve_refs(
            &f,
            &m,
            &sc,
            &[evidence("r", Some("c:\\문서\\비밀.docx"))],
            &mut env,
        );
        assert_eq!(pass.taken, 0);
        assert_eq!(pass.unresolved.len(), 1);
        assert!(
            pass.unresolved[0]
                .reason
                .contains(remedy_sdk::i18n::t("scan_roots 밖", "outside scan_roots")),
            "{pass:?}"
        );
        assert!(env.body.blobs.is_empty());
    }

    #[test]
    fn evidence_with_no_file_body_is_reported_not_skipped() {
        let m = manifest("  - { ref: r, content: true }");
        let sc = scope();
        let mut env = envelope(&sc, Observations::default());
        let pass = resolve_refs(&fs(&[]), &m, &sc, &[evidence("r", None)], &mut env);
        assert_eq!(pass.unresolved.len(), 1);
        assert!(
            pass.unresolved[0].reason.contains(remedy_sdk::i18n::t(
                "담을 본문이 없다",
                "no body to capture"
            )),
            "{pass:?}"
        );
    }

    #[test]
    fn content_false_takes_nothing_and_complains_about_nothing() {
        // 선언대로 한 것이므로 미해소가 아니다 — 이 항목은 `submit_hint` 가
        // 볼 표식이다.
        let f = fs(&[("c:\\app\\dropped.js", b"body")]);
        let m = manifest("  - { ref: r }");
        let sc = scope();
        let mut env = envelope(&sc, Observations::default());
        let pass = resolve_refs(
            &f,
            &m,
            &sc,
            &[evidence("r", Some("c:\\app\\dropped.js"))],
            &mut env,
        );
        assert_eq!(pass.taken, 0);
        assert!(pass.unresolved.is_empty(), "{pass:?}");
        assert!(env.body.blobs.is_empty());
    }

    #[test]
    fn the_second_pass_starts_from_the_budget_already_spent() {
        // **역검증에서 이것이 샜다.** `blob_bytes` 만 따로 시험하고 있었고,
        // `resolve_refs` 가 그것을 실제로 쓰는지는 아무도 보지 않았다. `spent` 를
        // 0 으로 바꿔도 시험 455건이 전부 통과했다.
        //
        // 예산이 새면 두 패스가 각각 상한만큼 담아 스냅샷이 두 배가 된다.
        let f = fs(&[("c:\\app\\dropped.js", b"x")]);
        let m = manifest("  - { ref: r, content: true }");
        let sc = scope();
        let mut env = envelope(&sc, Observations::default());
        env.body.blobs = blobs_at_budget();

        let pass = resolve_refs(
            &f,
            &m,
            &sc,
            &[evidence("r", Some("c:\\app\\dropped.js"))],
            &mut env,
        );
        assert_eq!(pass.taken, 0, "예산을 다 썼는데 더 담았다");
        assert_eq!(pass.unresolved.len(), 1);
        assert!(
            pass.unresolved[0]
                .reason
                .contains(remedy_sdk::i18n::t("총량 상한", "total body cap")),
            "{pass:?}"
        );
    }

    #[test]
    fn the_first_pass_also_counts_what_the_collectors_already_put() {
        // 이진 레지스트리 값도 스냅샷에 실린다. 세지 않으면 상한이 그만큼 샌다.
        //
        // `max_size` 를 총량보다 크게 줘서 **총량 쪽이 상한을 정하게** 만든다.
        // 그러지 않으면 파일당 상한이 늘 먼저 걸려 예산 계산이 보이지 않는다.
        const ALREADY: usize = 2 * 1024 * 1024;
        let f = fs(&[("c:\\app\\a.js", b"x")]);
        let m = manifest("  - { path: 'c:\\app\\a.js', max_size: 999MB }");
        let mut obs = Observations {
            blobs: with_blob(ALREADY),
            ..Default::default()
        };
        let un = collect_extra(&f, &m, &scope(), &mut obs, RefPolicy::ReportNow);
        assert!(un.is_empty(), "{un:?}");
        assert_eq!(
            f.1.get(),
            TOTAL_BUDGET - ALREADY as u64,
            "수집기가 담아 둔 본문을 예산에서 빼지 않았다"
        );
    }

    #[test]
    fn the_budget_is_shared_with_what_is_already_in_the_snapshot() {
        // 총량 상한은 "스냅샷이 얼마나 커지는가" 에 대한 것이다. 패스마다
        // 새로 세면 두 패스가 각각 상한만큼 담아 두 배가 된다.
        use base64::Engine;
        let mut obs = Observations::default();
        let big = vec![7u8; 3 * 1024 * 1024];
        obs.blobs.insert(
            "sha256:기존".into(),
            base64::engine::general_purpose::STANDARD.encode(&big),
        );
        assert_eq!(
            blob_bytes(&obs.blobs),
            big.len() as u64,
            "원본 크기를 잘못 셌다"
        );

        // 패딩이 붙는 길이들에서도 정확해야 한다.
        for n in [0usize, 1, 2, 3, 4, 5, 6, 7, 100] {
            let enc = base64::engine::general_purpose::STANDARD.encode(vec![0u8; n]);
            let one: BTreeMap<String, String> = [("k".to_string(), enc)].into_iter().collect();
            assert_eq!(blob_bytes(&one), n as u64, "{n} 바이트를 잘못 셌다");
        }
    }

    #[test]
    fn a_file_over_its_max_size_is_reported_not_silently_dropped() {
        let f = fs(&[("c:\\app\\big.bin", &[0u8; 4096])]);
        let m = manifest("  - { path: 'c:\\app\\big.bin', max_size: 1KB }");
        let mut obs = Observations::default();
        let un = collect_extra(&f, &m, &scope(), &mut obs, RefPolicy::ReportNow);
        assert_eq!(un.len(), 1);
        assert!(
            un[0].reason.contains(remedy_sdk::i18n::t("상한", "cap")),
            "{:?}",
            un[0]
        );
        assert!(obs.blobs.is_empty());
    }

    #[test]
    fn sizes_are_read_with_their_unit() {
        assert_eq!(parse_size(Some("1MB")), Some(1024 * 1024));
        assert_eq!(parse_size(Some("512kb")), Some(512 * 1024));
        assert_eq!(parse_size(Some("2048")), Some(2048));
        assert_eq!(parse_size(Some("2048B")), Some(2048));
        assert_eq!(parse_size(Some("헛소리")), None);
        assert_eq!(parse_size(None), None);
    }

    #[test]
    fn a_subject_form_needs_that_subject_declared() {
        let m = manifest("  - { subject: text_config, path: 'c:\\app\\a.ini' }");
        let mut obs = Observations::default();
        let un = collect_extra(&fs(&[]), &m, &scope(), &mut obs, RefPolicy::ReportNow);
        assert_eq!(un.len(), 1, "{un:?}");
        assert!(
            un[0].reason.contains(remedy_sdk::i18n::t(
                "선언되지 않았습니다",
                "is not declared"
            )),
            "{:?}",
            un[0]
        );
    }

    #[test]
    fn an_existing_file_record_keeps_its_metadata() {
        // 본문을 담는다고 이미 뜬 관찰을 덮어쓰면 안 된다.
        let f = fs(&[("c:\\app\\x.dat", b"body")]);
        let m = manifest("  - { path: 'c:\\app\\x.dat' }");
        let mut obs = Observations::default();
        obs.put(
            Subject::File,
            &[FileRecord {
                path: "c:\\app\\x.dat".into(),
                size: 4,
                mtime: "2026-08-21T00:00:00Z".into(),
                ctime: None,
                sha256: Some("기존해시".into()),
                signature: None,
                version: None,
                zone: None,
                streams: Vec::new(),
                content_ref: None,
            }],
        );
        collect_extra(&f, &m, &scope(), &mut obs, RefPolicy::ReportNow);
        let files = obs.files();
        assert_eq!(files.len(), 1, "레코드가 중복됐다");
        assert_eq!(files[0].mtime, "2026-08-21T00:00:00Z");
        assert_eq!(files[0].sha256.as_deref(), Some("기존해시"));
        assert!(files[0].content_ref.is_some());
    }

    /// **본문을 담으면 버전도 채워진다** (C-1b).
    ///
    /// 주 수집은 `max_hash_bytes` 를 넘는 파일을 읽지 않으므로 `version` 이 빈다.
    /// 그 상태에서 `collect_extra` 의 `path` 형이 본문을 담으면 그 바이트에
    /// 버전이 있다 — 이 줄이 없으면 **큰 바이너리의 버전 점검이 조용히 거짓이
    /// 된다**(실측 36 MB PE 로 종료 2 를 확인했다).
    ///
    /// 실물 PE 가 필요해 Windows 에서만 돈다. 합성 PE 를 짜면 그것이 맞는지를
    /// 다시 증명해야 하고, 그 대조는 `tests/peversion_real.rs` 가 맡는다.
    #[cfg(windows)]
    #[test]
    fn 본문을_담으면_버전이_채워진다() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let src = format!("{root}\\System32\\kernel32.dll");
        let Ok(bytes) = std::fs::read(&src) else {
            return;
        };
        let want = crate::peversion::of("x.dll", &bytes).expect("실물 PE 의 버전");

        let path = "c:\\app\\big.dll";
        let f = fs(&[(path, &bytes)]);
        let m = manifest(&format!("  - {{ path: '{path}', max_size: 99MB }}"));
        let mut obs = Observations::default();
        // 주 수집이 상한 때문에 읽지 못한 모양 — 해시도 버전도 비어 있다.
        obs.put(
            Subject::File,
            &[FileRecord {
                path: path.into(),
                size: bytes.len() as u64,
                mtime: "2026-08-21T00:00:00Z".into(),
                ctime: None,
                sha256: None,
                signature: None,
                version: None,
                zone: None,
                streams: Vec::new(),
                content_ref: None,
            }],
        );
        collect_extra(&f, &m, &scope(), &mut obs, RefPolicy::ReportNow);
        let files = obs.files();
        assert_eq!(files.len(), 1);
        assert_eq!(
            files[0].version.as_deref(),
            Some(want.as_str()),
            "본문을 담았는데 버전이 비었다 — 큰 바이너리의 버전 점검이 조용히 거짓이 된다"
        );
    }
}
