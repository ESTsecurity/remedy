//! 배포 꾸러미를 만든다 — **받는 사람이 푸는 그 폴더** (설계-09 P10 후속).
//!
//! # 왜 필요한가
//!
//! `docs/operator.md` §0 은 배포물을 *"`remedy.exe` · `plugin.yaml` · 그 옆
//! `rules/*.yar`"* 라고 적어 두었지만, **그것을 만드는 자리가 없었다.** 사람이
//! 손으로 모으면 회차마다 담기는 것이 달라지고, 무엇이 빠졌는지는 받는 사람이
//! 발견한다.
//!
//! # 위협 하나당 꾸러미 하나
//!
//! 전용백신의 본래 모습이다 — 특정 위협이 돌 때 그것만 담은 꾸러미를 내린다.
//! 받는 사람이 고를 일이 없고(안내 모드의 "여럿이면 고르게 한다" 는 예외 경로가
//! 된다), 사건마다 따로 배포한다. 자기에게 없는 위협까지 검사하며 시간을 쓰지
//! 않는다 (결정 2026-09-08).
//!
//! # 서명된 것만 담는다
//!
//! 담기 전에 [`remedy_trust`] 로 확인한다 — 매니페스트가 있고, 서명이 맞고,
//! 파일 목록이 실제와 같아야 한다. **미서명 플러그인을 꾸러미에 넣지 않는다**:
//! 넣으면 받는 사람의 `plugin verify` 가 실패하고, 그때 그것이 배포 사고인지
//! 변조인지 아무도 모른다.
//!
//! 앵커를 확인하는 것은 여기가 아니다 — 그것은 **바이너리를 만들 때** 박히고,
//! 이 명령은 이미 만들어진 바이너리를 담을 뿐이다. 대신 담는 바이너리에 앵커가
//! 박혀 있는지는 `README.txt` 에 적어 사람이 알 수 있게 한다.
//!
//! # 플러그인은 여럿일 수 있다 (A-2 · 2026-10-26)
//!
//! `--plugin` 을 여러 번 준다. 사고 하나에 역할이 둘인 꾸러미 — **점검과 치료** —
//! 를 한 번에 내리기 위한 것이다(사고-대응 설계 §4).
//!
//! **두 번 불러 같은 폴더에 담는 방식은 쓸 수 없다.** 아래 `out.exists()` 검사가
//! 출력 경로에 무엇이든 있으면 거부하기 때문이다. 그 규칙을 느슨하게 하는 쪽이
//! 아니라 한 번에 여럿을 받는 쪽을 골랐다 — 규칙은 *"무엇이 담겼는지 알 수
//! 있게"* 있는 것이고, 두 번 부르기를 허용하면 첫 회차의 파일이 남았는지를
//! 다시 알 수 없게 된다.
//!
//! 받는 사람 쪽은 이미 여럿을 받는다 — 안내 모드가 *"하나면 그것, 여럿이면
//! 고르게 한다"*(2026-09-08 결정 · `discover`). 그래서 코어는 한 줄도 바뀌지
//! 않는다.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub fn run(root: &Path, args: &[String]) -> Result<(), String> {
    let plugin_dirs = all_of(args, "--plugin")?;
    if plugin_dirs.is_empty() {
        return Err(usage("--plugin"));
    }
    let bin = PathBuf::from(need(args, "--bin")?);
    let out = PathBuf::from(need(args, "--out")?);
    let pubkey = PathBuf::from(need(args, "--public-key")?);

    if !bin.is_file() {
        return Err(format!(
            "{} 가 없다 — 먼저 빌드할 것 (앵커를 박으려면 \
             REMEDY_TRUST_ANCHOR=<base64> cargo build --release)",
            bin.display()
        ));
    }

    // ── 1. 서명이 맞는가 ─────────────────────────────────────────
    //
    // **꾸러미를 만드는 자리에서 막는다.** 여기서 통과시키면 그다음 방어선은
    // 고객의 화면이고, 거기서 실패하면 배포 사고와 변조를 구별할 수 없다.
    //
    // **붓기 전에 전부 확인한다.** 하나씩 확인하며 부으면 두 번째가 미서명일 때
    // 첫 번째만 담긴 꾸러미가 남는다 — 반쯤 만들어진 꾸러미가 가장 나쁘다.
    let mut plugins = Vec::new();
    for dir in &plugin_dirs {
        let (id, version, tree) = verified_identity(dir, &pubkey)?;
        let name = dir
            .file_name()
            .ok_or_else(|| format!("{} 의 폴더 이름이 없다", dir.display()))?
            .to_string_lossy()
            .to_string();
        plugins.push(Packed {
            dir: dir.clone(),
            name,
            id,
            version,
            tree,
        });
    }

    // **부딪히는 것을 먼저 거부한다.** 폴더 이름이 같으면 `plugins/<이름>/` 에서
    // 덮어써 뒤의 것만 남고, 그래도 README 는 둘을 적는다 — 받는 사람이 없는
    // 플러그인을 찾게 된다.
    //
    // id 가 같으면 **기록이 둘을 가려 세우지 못한다.** `plugin_id` 는 저널
    // (`Event::Start`) · 검증 기록 · 격리물 매니페스트 · 복원 계획이 쓰는 유일한
    // 플러그인 신원이고, `plugin verify` 의 폐기·하한 판정도 `(id, version)` 으로
    // 묻는다 — 같은 id 가 둘이면 어느 룰이 남긴 기록인지, 폐기 항목이 어느 쪽을
    // 겨눈 것인지 되물을 수 없다. (안내 모드의 목록은 id 를 쓰지 않는다 —
    // 매니페스트의 사람 읽는 이름과 번호로 고른다.)
    for (i, a) in plugins.iter().enumerate() {
        for b in &plugins[i + 1..] {
            if same_folder(&a.name, &b.name) {
                return Err(format!(
                    "플러그인 폴더 이름이 같다: {} · {}\n\
                     꾸러미 안에서 plugins\\{} 하나로 겹친다 — 폴더 이름을 달리할 것.\n\
                     **대소문자만 다른 이름도 같은 폴더다** (끝의 '.' · 공백도) — \
                     글자를 바꿔야 한다",
                    a.dir.display(),
                    b.dir.display(),
                    a.name
                ));
            }
            if a.id == b.id {
                return Err(format!(
                    "플러그인 id 가 같다: {} ({} · {})\n\
                     기록·격리물·복원 지점이 어느 룰에서 나온 것인지 구별되지 않고 \
                     폐기 판정도 둘을 한 플러그인으로 본다 — 한 꾸러미에 담지 않는다",
                    a.id,
                    a.dir.display(),
                    b.dir.display()
                ));
            }
        }
    }

    // ── 2. 붓는다 ────────────────────────────────────────────────
    if out.exists() {
        return Err(format!(
            "{} 가 이미 있다 — 지우고 다시 만들 것. 덮어쓰면 앞 회차의 파일이 \
             남아 무엇이 담겼는지 알 수 없게 된다",
            out.display()
        ));
    }
    std::fs::create_dir_all(&out)
        .map_err(|e| format!("{} 를 만들지 못했다: {e}", out.display()))?;

    let exe_name = bin
        .file_name()
        .ok_or_else(|| format!("{} 의 파일 이름이 없다", bin.display()))?;
    copy(&bin, &out.join(exe_name))?;

    // ── 플러그인은 **자기 폴더**에 둔다 ─────────────────────────
    //
    // 실행 파일과 나란히 놓으면 `plugin verify` 가 통과하지 못한다. 그 검사는
    // 디렉터리의 **모든** 파일이 매니페스트에 있기를 요구하고(설계의 핵심인
    // "몰래 추가한 룰" 방어 — `TreeDiff::Extra`), `remedy.exe` 와 `README.txt` 는
    // 플러그인 서명에 들어 있지 않다.
    //
    // 2026-09-08 에 실제로 밟았다. 첫 판이 나란히 놓았고, 받는 사람 흉내를 내
    // `plugin verify --dir .` 를 돌리자 **꾸러미가 자기 검증에 실패했다**
    // (`README.txt`·`remedy.exe`: 서명되지 않은 파일이 들어 있습니다, 종료 5).
    //
    // 폴더를 나누면 검증 경계와 꾸러미 경계가 갈린다. `discover::beside` 가
    // 보는 두 자리 중 `plugins/<이름>/plugin.yaml` 이 바로 이 모양이다.
    //
    // **붓는 목록은 검증이 쓴 그 목록이다.** 전에는 여기서 `collect` 를 다시
    // 불렀는데, 그러면 검증한 트리와 붓는 트리가 갈린다 — 두 호출 사이에 생긴
    // 파일이 서명 없이 꾸러미에 들어가고 아무도 다시 묻지 않는다. 실측으로
    // 결정적인 입력이 있었다(2026-10-26): `--out` 을 `--plugin` 디렉터리 **안**에
    // 두면 방금 만든 출력 폴더 자신이 두 번째 `collect` 에 잡혀 꾸러미에 담기고,
    // 받는 사람의 `plugin verify` 가 *"서명되지 않은 파일이 들어 있습니다"* 로
    // 종료 5 를 낸다. 검증 목록을 쓰면 그 구멍이 닫힌다 — 목록이 만들어진 시점이
    // 출력 폴더가 생기기 **전**이다. 트리를 두 번 읽고 해시하지도 않는다.
    let mut files = Vec::new();
    for p in &plugins {
        let nest = PathBuf::from("plugins").join(&p.name);
        let carry = |rel: &str| -> Result<(), String> {
            copy(&p.dir.join(rel), &out.join(nest.join(rel)))?;
            Ok(())
        };
        for rel in p.tree.keys() {
            carry(rel)?;
            files.push(nest.join(rel).to_string_lossy().to_string());
        }
        // 서명 자체도 담는다 — 받는 사람이 `plugin verify` 로 다시 물을 수 있어야 한다.
        for name in [remedy_trust::MANIFEST_NAME, remedy_trust::SIGNATURE_NAME] {
            carry(name)?;
            files.push(nest.join(name).to_string_lossy().to_string());
        }
    }

    let readme = readme(
        root,
        &plugins,
        exe_name.to_string_lossy().as_ref(),
        &files,
        std::env::var("REMEDY_TRUST_ANCHOR").is_ok(),
    );
    std::fs::write(out.join("README.txt"), readme.as_bytes())
        .map_err(|e| format!("README.txt 를 쓰지 못했다: {e}"))?;

    println!("꾸러미: {}", out.display());
    for p in &plugins {
        println!("  위협  {} {}", p.id, p.version);
    }
    println!("  담은 것  {} 개 + README.txt", files.len() + 1);
    println!();
    println!("받는 사람이 `plugin verify --dir <이 폴더>` 로 다시 물을 수 있다.");
    Ok(())
}

/// 꾸러미에 담기로 확인된 플러그인 하나.
struct Packed {
    dir: PathBuf,
    /// 꾸러미 안의 폴더 이름 — `plugins/<name>/`.
    name: String,
    id: String,
    version: String,
    /// **서명과 대조가 끝난** 파일 목록(상대 경로 → 해시). 붓는 것은 이 목록이다 —
    /// 다시 훑으면 그 사이에 생긴 파일이 서명 없이 들어간다.
    tree: BTreeMap<String, String>,
}

/// 서명을 확인하고 (id, version, 확인된 파일 목록) 을 돌려준다.
///
/// **공개키를 인자로 받는다.** 꾸러미를 만드는 사람은 방금 그 키로 서명했으므로
/// 손에 갖고 있고, 여기서 확인하지 않으면 서명이 **우리 키의 것인지**를 아무도
/// 묻지 않은 채 배포된다. 앵커를 박은 바이너리의 `plugin verify` 가 뒤에서 다시
/// 묻지만, 그때는 이미 꾸러미가 만들어진 뒤다.
fn verified_identity(
    dir: &Path,
    pubkey: &Path,
) -> Result<(String, String, BTreeMap<String, String>), String> {
    let manifest_path = dir.join(remedy_trust::MANIFEST_NAME);
    let sig_path = dir.join(remedy_trust::SIGNATURE_NAME);
    for p in [&manifest_path, &sig_path] {
        if !p.is_file() {
            return Err(format!(
                "{} 가 없다 — 서명되지 않은 플러그인은 꾸러미에 담지 않는다.\n  \
                 cargo xtask sign plugin --dir {} --secret-key <키> --signed-at <RFC3339>",
                p.display(),
                dir.display()
            ));
        }
    }
    let key_text = std::fs::read_to_string(pubkey)
        .map_err(|e| format!("{} 를 읽지 못했다: {e}", pubkey.display()))?;
    let anchor =
        remedy_trust::Anchor::from_public_key_file(&key_text).map_err(|e| e.to_string())?;

    let manifest = std::fs::read(&manifest_path)
        .map_err(|e| format!("{} 를 읽지 못했다: {e}", manifest_path.display()))?;
    let signature = std::fs::read_to_string(&sig_path)
        .map_err(|e| format!("{} 를 읽지 못했다: {e}", sig_path.display()))?;

    let verified = remedy_trust::verify_manifest(&anchor, &manifest, &signature)
        .map_err(|e| format!("서명이 이 키의 것이 아니다: {e}"))?;
    let actual = remedy_trust::collect(dir).map_err(|e| e.to_string())?;
    verified
        .check_tree(&actual)
        .map_err(|e| format!("서명한 뒤 파일이 바뀌었다: {e}"))?;

    // 서명 주석의 id·version 이 곧 이 꾸러미의 정체다. plugin.yaml 을 다시 읽어
    // 비교하지 않는다 — 서명이 그 둘을 이미 묶었다.
    let c = verified.comment();
    Ok((c.id.clone(), c.version.clone(), actual))
}

/// 받는 사람이 처음 여는 파일.
///
/// **무엇이 담겼고 무엇을 하면 되는지만 적는다.** 운영 문서를 여기 옮겨 적으면
/// 두 자리가 갈라지고, 갈라지면 어느 쪽이 참인지 알 수 없다.
///
/// # 왜 `anchored_ok` 를 인자로 받는가
///
/// 전에는 이 함수가 `REMEDY_TRUST_ANCHOR` 를 직접 읽었다. 그러면 **두 갈래를
/// 시험으로 잠글 수 없다** — 환경 변수를 바꾸는 시험은 한 프로세스에서 나란히
/// 도는 다른 시험까지 흔들고, 이 크레이트는 `forbid(unsafe_code)` 라 edition
/// 2024 의 `set_var` 를 쓸 수도 없다. 그래서 읽는 자리를 부르는 쪽으로 올렸다.
fn readme(
    root: &Path,
    plugins: &[Packed],
    exe: &str,
    files: &[String],
    anchored_ok: bool,
) -> String {
    // 받는 사람의 말로 적는다 — '신뢰 앵커' 는 내부 낱말이다(v1.1.0 적대적 검토). 배포 잡의
    // `ci/release.sh readme` 가 이 문장으로 앵커 판인지 잰다 — 고치면 함께 고친다.
    let anchored = if anchored_ok {
        "이 실행 파일에는 룰 서명을 확인하는 ESTsecurity 공개키가 들어 있습니다."
    } else {
        "주의: 이 바이너리에는 신뢰 앵커가 박혀 있지 않습니다 \
         (개발 빌드). plugin verify 에 --public-key 를 주어야 합니다."
    };

    // ── 어느 플랫폼의 글인가 — **`--bin` 의 이름이 말한다** (결정 10-2) ──
    //
    // 가려야 하는 것은 **이 꾸러미가 풀리는 자리**다. 호스트가 아니다 — 같은
    // 파일의 다른 주석이 *"리눅스에서 만든 꾸러미도 Windows 에서 풀린다"* 고
    // 적고 그래서 플랫폼을 가리지 않는 검사를 넣어 두었는데, **안내문만 한쪽을
    // 전제했다**(2026-10-29 실측 — 우클릭 · SmartScreen · 역슬래시 · CRLF).
    // 리눅스 꾸러미를 내면 **되지 않는 일을 하라고 적는 글**이 함께 나갔다.
    //
    // 신호는 담아 가는 실행 파일의 이름뿐이다. `--target` 은 이 명령에 없고,
    // 호스트의 `cfg!(windows)` 는 교차 빌드에서 반대를 말한다.
    let win = exe.to_ascii_lowercase().ends_with(".exe");
    // **셋을 따로 둔다.** 하나로 묶어 두면 한 자리가 조용히 Windows 꼴로
    // 남는다 — 지금까지가 그 상태였다.
    let sep = if win { "\\" } else { "/" };
    let here = if win { ".\\" } else { "./" };
    // 관리자로 올리는 법이 다르다. Windows 는 **창을** 그렇게 열고, 리눅스는
    // **명령에** 붙인다. `plugin verify` 에도 붙인다 — 준 파일 말고 이 기계의 폐기
    // 목록(기본 상태 폴더)도 읽고, root 가 명령으로 한 번 돌린 뒤의 그 폴더는 root 만
    // 연다(2026-11-07 실측: sudo 없이 `revocations.sig … Permission denied` · 종료 4).
    let sudo = if win { "" } else { "sudo " };
    let core = std::fs::read_to_string(root.join("Cargo.toml"))
        .ok()
        .and_then(|t| {
            t.lines()
                .find(|l| l.trim_start().starts_with("version"))
                .and_then(|l| l.split('"').nth(1).map(str::to_string))
        })
        .unwrap_or_else(|| "?".into());

    let mut s = String::new();
    s.push_str("ESTsecurity 전용백신 — 사용 방법\r\n");
    s.push_str("========================================\r\n\r\n");
    s.push_str(&format!("프로그램  {core}\r\n"));
    // **하나일 때의 글자는 그대로 둔다.** `docs/operator.md` 와 화면 캡처가 그 꼴로
    // 돌고 있고, 여럿을 담을 수 있게 되었다는 사실이 하나짜리 꾸러미의 안내문을
    // 바꿀 이유는 없다.
    for p in plugins {
        s.push_str(&format!("검사 항목 {} {}\r\n", p.id, p.version));
    }
    s.push_str(&format!("{anchored}\r\n\r\n"));

    // **쉬운 길을 먼저 적는다.** 앞서 이 절은 관리자 터미널을 열고 폴더로
    // 이동해 긴 명령을 치라고만 했다 — 홈페이지에서 받은 사람에게는 세 단계
    // 모두가 벽이다. 안내 모드가 서면서(2026-09-09) 그럴 필요가 없어졌다:
    // 실행 파일을 우클릭해 관리자로 띄우면 옆의 꾸러미를 스스로 찾는다.
    //
    // **앵커가 없으면 그 길이 막힌다.** 안내 모드는 검증을 통과한 꾸러미만
    // 쓰므로, 앵커 없는 개발 빌드에서는 우클릭해도 "확인할 수 없습니다" 로
    // 끝난다. 그래서 위의 `anchored` 와 같은 갈래로 적는다 — 여기서 갈라
    // 적지 않으면 README 가 되지 않는 일을 하라고 말하게 된다.
    s.push_str("쓰는 법\r\n");
    s.push_str("--------\r\n");
    s.push_str("1. 이 폴더를 통째로 풉니다. 파일을 따로 옮기면 동작하지 않습니다\r\n");
    s.push_str(&format!(
        "   (룰이 plugin.yaml 옆의 rules{sep} 에 있어야 합니다).\r\n"
    ));
    // **기계마다 그 기계의 디스크에.** 메뉴는 치료 기록 · 격리한 파일을 이 폴더에 두고, 재시작 뒤
    // 검사도 이 폴더의 절대 경로로 예약한다 — USB 에서 돌리고 빼면 둘 다 길을 잃는다(2026-11-07 검토).
    s.push_str("   USB · 공유 폴더가 아니라 그 기계의 로컬 디스크에 풀어 실행합니다.\r\n");
    if anchored_ok {
        if win {
            s.push_str(&format!(
                "2. {exe} 를 마우스 오른쪽 단추로 누르고 '관리자 권한으로 실행' 을\r\n"
            ));
            s.push_str("   고릅니다. 이 폴더의 룰을 스스로 찾습니다.\r\n");
        } else {
            // **리눅스에는 우클릭 실행이 없다.** 터미널이 곧 그 자리이고,
            // 관리자는 명령에 붙는다. `stdin` 이 터미널이므로 메뉴는 그대로
            // 열린다(`sudo` 는 tty 를 물려준다).
            s.push_str(&format!(
                "2. 터미널에서 이 폴더로 이동한 뒤 {sudo}{here}{exe} 로 띄웁니다.\r\n"
            ));
            s.push_str("   (시스템을 검사하고 치료하는 도구라 관리자 권한이 필요합니다.)\r\n");
            s.push_str("   이 폴더의 룰을 스스로 찾습니다.\r\n");
        }
        // **묻는다는 것을 미리 알린다.** 안내 모드는 찾은 것이 둘 이상이면 번호를
        // 묻는다(`guided::choose` — 하나면 바로 그것). 그 사실을 적지 않으면 받는
        // 사람은 답을 기다리며 멈춘 화면을 고장으로 본다. 실측으로 드러난
        // 자리다(2026-10-26). 그 질문은 **작업 메뉴보다 먼저** 선다(2026-10-30
        // 진짜 콘솔 실측 — `choose` 가 `menu::run` 앞이다).
        //
        // 그 질문의 1번은 **전부로 검사만**이다(목표 remedy_출시_20261111 기준 3) — 무엇을 노린
        // 위협인지 모르는 사람이 항목을 하나씩 골라 다시 띄우지 않게. 작업이 끝나면 그 질문으로
        // 돌아오므로 *"한 번 더 실행해 고릅니다"* 는 이제 틀린 말이다.
        if plugins.len() > 1 {
            let n = plugins.len();
            s.push_str(&format!(
                "   이 폴더에는 검사 항목이 {n}개 들어 있어, 먼저 어느 것을 볼지\r\n"
            ));
            s.push_str("   번호로 묻습니다.\r\n");
            s.push_str(&format!(
                "     1번 '{n}개 모두 검사만 하기' 는 전부 검사하고 결과를 한 번에\r\n"
            ));
            s.push_str(
                "     보여 줍니다(아무것도 바꾸지 않습니다). 치료는 항목을 골라서 합니다.\r\n",
            );
            s.push_str("   항목을 고르면 무엇을 할지 번호로 묻습니다.\r\n");
        } else {
            s.push_str("   그다음 무엇을 할지 번호로 묻습니다.\r\n");
        }
        // **여기가 메뉴보다 먼저 적혀 있던 자리다.** 2026-10-29 에 작업 메뉴가
        // 서기 전까지 이 절은 *"룰을 스스로 찾아 검사를 시작하고, 무엇을 할지
        // 먼저 보여 준 뒤 승인을 기다립니다"* 라고 적었다 — 그때는 참이었다.
        // 지금은 **검사가 아니라 질문이 먼저** 뜨므로, 고치지 않으면 받는 사람이
        // 가장 먼저 읽는 글이 가장 먼저 보는 화면과 다르다.
        s.push_str("     '검사하고 치료하기' 는 계획을 보여 준 뒤 승인을 기다립니다.\r\n");
        s.push_str("     '검사만 하기' 는 아무것도 바꾸지 않습니다.\r\n");
        s.push_str("     치료한 뒤에는 '치료 전으로 복원하기' 줄을 고를 수 있습니다.\r\n");
        s.push_str("   작업이 끝나면 처음 질문으로 돌아옵니다. 끝내려면 0 을 고릅니다.\r\n");
        // **되돌리기의 전제를 적는다.** 메뉴는 치료 기록 · 격리한 파일을 실행 파일 옆
        // `state` 에 남긴다(menu_state). 다 쓴 도구라고 폴더를 지우면 되돌릴 길이
        // 없어진다 — 새로 푼 폴더의 메뉴는 *"치료한 기록이 없습니다"* 를 띄운다(2026-11-07 실측).
        s.push_str("   치료한 기록과 격리한 파일은 이 폴더의 state 에 남습니다. 되돌릴 일이\r\n");
        s.push_str("   없다고 판단할 때까지 이 폴더를 지우지 마십시오.\r\n");
        s.push_str("\r\n");
        if win {
            s.push_str(
                "   명령 창에서 돌리려면 시작 단추를 오른쪽 단추로 눌러 '터미널(관리자)'\r\n",
            );
            s.push_str("   또는 'Windows PowerShell(관리자)' 를 열고 이 폴더로 이동한 뒤:\r\n\r\n");
        } else {
            s.push_str("   하나만 명령으로 돌리려면:\r\n\r\n");
        }
    } else if win {
        s.push_str("2. 이 바이너리에는 신뢰 앵커가 없어 우클릭 실행만으로는 폴더의 룰을\r\n");
        s.push_str("   확인하지 못합니다. 시작 단추를 마우스 오른쪽 단추로 누르고\r\n");
        s.push_str("   '터미널(관리자)' 또는 'Windows PowerShell(관리자)' 를 고른 뒤\r\n");
        s.push_str("   이 폴더로 이동해:\r\n\r\n");
    } else {
        s.push_str("2. 이 바이너리에는 신뢰 앵커가 없어 띄우기만으로는 폴더의 룰을\r\n");
        s.push_str("   확인하지 못합니다. 터미널에서 이 폴더로 이동해:\r\n\r\n");
    }
    // **여럿이면 줄도 여럿이다.** 한 줄에 둘을 적으면 받는 사람이 그것을 한 번에
    // 돌리는 명령으로 읽는다 — `run` 은 `--plugin` 하나를 받는다. 우클릭으로 띄우면
    // 안내 모드가 *"여럿이면 고르게 한다"* 로 번호를 묻는다(2026-09-08 결정).
    for p in plugins {
        s.push_str(&format!(
            "     {sudo}{here}{exe} run --plugin {here}plugins{sep}{}{sep}plugin.yaml\r\n",
            p.name
        ));
    }
    s.push_str("\r\n");
    s.push_str("   계획을 보여 주고 승인을 기다립니다. --yes 를 붙이면 묻지 않습니다.\r\n\r\n");

    // **첫 벽이 플랫폼마다 다르다.** Windows 는 SmartScreen 이고 리눅스는
    // 실행 권한이다 — 둘 다 "받자마자 막힌다" 는 같은 자리이고, 둘 다 이 글이
    // 없으면 사람이 도구를 의심한다. 상대 플랫폼의 벽을 적으면 잡음이다.
    if win {
        s.push_str("받자마자 파란 창이 뜨면\r\n");
        s.push_str("--------------------------\r\n");
        s.push_str("Windows SmartScreen 입니다. 이 도구가 낸 것이 아니라, 인터넷에서 받은\r\n");
        s.push_str("실행 파일 중 평판이 쌓이지 않은 것에 뜹니다. 배포처에서 받은 것이\r\n");
        s.push_str("맞다면 [추가 정보] -> [실행] 을 누릅니다.\r\n\r\n");
    } else {
        // **tar.gz 는 실행 권한을 담는다**(0755). 빠지는 것은 PC 에서 풀어 파일을 서버로
        // 옮긴 경우이고, chmod 로도 안 되면 실행을 막는 마운트(noexec)다(2026-11-07 실측 —
        // tmpfs noexec 에서 chmod 뒤에도 종료 126). 메뉴의 *"root 권한이 없습니다"* 는 다른
        // 벽이라 따로 적는다 — 같은 말로 묶으면 sudo 를 빠뜨린 사람을 chmod 로 보낸다.
        // **sudo 는 실행 권한이 빠진 파일에 'command not found' 라고 한다** — 'Permission denied'
        // 는 noexec 일 때다. 제목에 둘 다 두지 않으면 가장 흔한 경우를 겪은 사람이 이 절을 못 찾는다.
        s.push_str("띄우자마자 'command not found' 나 'Permission denied' 가 나오면\r\n");
        s.push_str("--------------------------------------------------------------\r\n");
        s.push_str("PC 에서 풀어 파일을 서버로 옮기면 실행 권한이 빠질 수 있습니다\r\n");
        s.push_str(
            "(sudo 는 이때 'command not found' 라고 합니다). 한 번만 올려 주면 됩니다.\r\n\r\n",
        );
        s.push_str(&format!("     chmod +x {here}{exe}\r\n\r\n"));
        s.push_str("그래도 같으면 이 폴더가 실행을 막는 자리(noexec — /tmp 등)에 있는\r\n");
        s.push_str("것입니다. 홈 폴더처럼 다른 자리에 다시 푸십시오.\r\n");
        s.push_str("메뉴에 'root 권한이 없습니다' 가 나오면 sudo 를 빠뜨린 것입니다 —\r\n");
        s.push_str(&format!("{sudo}{here}{exe} 로 다시 띄웁니다.\r\n\r\n"));
    }

    // **치료한 뒤 할 일은 위협마다 다르다** — 패널 되살리기 · 자격 증명 바꾸기 · 콘솔에서 할 일.
    // 서버에 남는 안내는 이 파일뿐이라 어디에 있는지와, 모든 위협에 같은 한 가지(공급사 버전을
    // 다시 설치한 뒤에는 되돌리지 않는다 — 격리한 파일이 새 파일을 덮는다)를 적는다(2026-11-07 검토).
    s.push_str("위협이 나오면\r\n");
    s.push_str("--------------\r\n");
    s.push_str("치료한 뒤 할 일(서비스 되살리기 · 비밀번호 바꾸기 · 콘솔에서 할 일)은\r\n");
    s.push_str("위협마다 다릅니다. README 의 '위협별 안내' 를 따르십시오:\r\n");
    s.push_str("  https://github.com/ESTsecurity/remedy#위협별-안내\r\n");
    s.push_str("치료한 프로그램을 공급사 버전으로 다시 설치했다면 치료를 되돌리지\r\n");
    s.push_str("마십시오 — 되돌리면 격리해 둔 파일이 새로 설치한 파일을 덮습니다.\r\n\r\n");

    s.push_str("룰의 서명을 확인하려면\r\n");
    s.push_str("------------------------\r\n");
    // **폴더 이름으로 적는다.** 전에는 `id` 로 적었는데 꾸러미의 폴더는 원본
    // 디렉터리 이름으로 만들어진다 — 둘이 다른 플러그인에서는 README 가 없는
    // 경로를 가리켰다(지금 담아 온 `evilai-locust` 는 둘이 같아 드러나지 않았다).
    for p in plugins {
        s.push_str(&format!(
            "     {sudo}{here}{exe} plugin verify --dir {here}plugins{sep}{}\r\n",
            p.name
        ));
    }
    s.push_str("\r\n");
    s.push_str("룰이 실행 파일에 든 공개키로 서명한 그대로인지 봅니다. 서명이 맞고\r\n");
    s.push_str("파일이 하나도 바뀌지 않았으면 통과하고, 한 글자라도 다르면 거부하고\r\n");
    s.push_str("어느 파일인지 말합니다. 이 기계의 폐기 목록도 함께 읽으므로 관리자\r\n");
    s.push_str("권한으로 돌립니다. 받은 파일 자체가 배포한 그 파일인지는 릴리스의\r\n");
    s.push_str("SHA256SUMS 로 확인합니다.\r\n\r\n");

    s.push_str("담긴 것\r\n");
    s.push_str("--------\r\n");
    s.push_str(&format!("  {exe}\r\n"));
    for f in files {
        // 담긴 목록은 **풀린 자리의 경로 모양**으로 적는다.
        //
        // **두 꼴이 섞여 들어온다.** 앞 토막은 `PathBuf::join` 이 만들어
        // 호스트의 구분자이고(Windows 에서 `plugins\evilai-locust`), 뒤 토막은
        // 서명 트리의 키라 늘 `/` 다(`rules/evilai.yar`). 한쪽만 바꾸면
        // `plugins\evilai-locust\rules/evilai.yar` 같은 줄이 나간다 — 2026-10-30
        // 에 실제 산출물에서 그 줄을 봤다(시험이 `/` 만 든 입력을 먹여 놓쳤다).
        //
        // 그래서 **먼저 `/` 로 모으고 그다음 목표 구분자로 쓴다.**
        let norm = f.replace('\\', "/").replace('/', sep);
        s.push_str(&format!("  {norm}\r\n"));
    }
    s.push_str("  README.txt\r\n\r\n");

    // 가이드는 이 폴더에 없다 — 경로만 적으면 받은 사람이 열 수 없는 자리를 가리킨다.
    s.push_str("자세한 것은 운영자 가이드에 있습니다:\r\n");
    s.push_str("  https://github.com/ESTsecurity/remedy/blob/main/docs/operator.md\r\n");
    // **줄바꿈도 플랫폼이다.** 본문은 `\r\n` 으로 짜고 리눅스 판에서만 되돌린다 —
    // 반대로 하면 `push_str` 마다 어느 꼴을 썼는지 세어야 하고, 한 자리를
    // 빠뜨리면 섞인 파일이 된다. 지금까지 Windows 판 하나뿐이어서 그 선택이
    // 드러나지 않았다.
    if win {
        s
    } else {
        s.replace("\r\n", "\n")
    }
}

/// 두 폴더 이름이 **같은 폴더로 떨어지는가.**
///
/// 글자 비교로는 모자란다. Windows 는 대소문자를 접어 `Check` 와 `check` 를 같은
/// 디렉터리로 열고, 이름 끝의 `.` 과 공백을 떼어 버린다. A-2 로 꾸러미에
/// `plugins/<이름>/` 이 여럿 생기면서 **그 차이가 조용한 덮어쓰기가 되었다.**
///
/// 실측(2026-10-26)으로 두 결과를 보았다. `A\Check`(id 하나)와 `B\check`(id 둘)를
/// 한 꾸러미에 담으면 종료 0 으로 *"위협 2줄 · 담은 것 12 개"* 를 찍지만 디스크에는
/// `plugins\Check` 하나만 생기고 두 플러그인이 섞인다 — 받는 사람의
/// `plugin verify` 가 종료 5 로 거부한다. **파일 이름 집합이 같으면 더 나쁘다**:
/// 덮어쓰기가 완전해져 한 플러그인이 통째로 사라지는데 `plugin verify` 는
/// **통과 도장을 찍는다.** README 와 stdout 은 둘을 약속한 채다.
///
/// 리눅스에서 만든 꾸러미도 Windows 에서 풀리므로, 플랫폼을 가리지 않고 거부한다.
/// 비용은 폴더 이름을 글자로 달리하는 것뿐이고, 그렇게 짓지 않을 이유가 없다.
fn same_folder(a: &str, b: &str) -> bool {
    let key = |s: &str| s.to_lowercase().trim_end_matches(['.', ' ']).to_string();
    key(a) == key(b)
}

fn copy(from: &Path, to: &Path) -> Result<(), String> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("{} 를 만들지 못했다: {e}", parent.display()))?;
    }
    std::fs::copy(from, to)
        .map(|_| ())
        .map_err(|e| format!("{} -> {}: {e}", from.display(), to.display()))
}

fn need(args: &[String], name: &str) -> Result<String, String> {
    let i = args
        .iter()
        .position(|a| a == name)
        .ok_or_else(|| usage(name))?;
    value_after(args, i, name)
}

/// `args[at]` 다음 토막을 값으로 집는다.
///
/// **`--` 로 시작하는 것은 값이 아니다.** 이 검사가 없으면 `--plugin --bin <파일>`
/// 이 `--bin` 을 플러그인 폴더로 읽고, 사람은 *"--bin\MANIFEST 가 없다 — 서명되지
/// 않은 플러그인은 꾸러미에 담지 않는다"* 는 엉뚱한 진단을 받는다. 빼먹은 값을
/// 서명 문제로 말하는 진단은 사람을 틀린 곳으로 보낸다(실측 2026-10-26).
fn value_after(args: &[String], at: usize, name: &str) -> Result<String, String> {
    match args.get(at + 1) {
        Some(v) if !v.starts_with("--") => Ok(v.clone()),
        Some(v) => Err(format!(
            "{name} 뒤에 값이 없다 — {v} 는 다른 옵션이다\n{}",
            usage_line()
        )),
        None => Err(format!("{name} 뒤에 값이 없다\n{}", usage_line())),
    }
}

/// **같은 이름이 여러 번 올 수 있다.** `need` 는 첫 것만 집으므로 `--plugin` 에는
/// 쓸 수 없다 — 둘을 주고 하나만 담긴 꾸러미가 조용히 나오는 것이 가장 나쁘다.
/// 준 순서를 지킨다: README 의 줄 순서가 곧 사람이 읽는 차례다.
///
/// **값 없는 것도 거부한다.** 넘기면 바로 위 문장이 거짓이 된다 —
/// `--plugin a --plugin` 이 조용히 하나짜리 꾸러미를 낸다.
fn all_of(args: &[String], name: &str) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            out.push(PathBuf::from(value_after(args, i, name)?));
            i += 2;
            continue;
        }
        i += 1;
    }
    Ok(out)
}

fn usage(name: &str) -> String {
    format!("{name} 가 없다\n{}", usage_line())
}

fn usage_line() -> String {
    "사용법: cargo xtask package --plugin <플러그인 디렉터리> [--plugin <또 하나> …] \
     --bin <실행 파일> --out <꾸러미 폴더> --public-key <공개키>"
        .to_string()
}

// ─────────────────────────────────────────────────────────────── 시험
//
// **README 문구를 잠그는 자리.** 이 파일에는 시험이 없었고 그 문구를 읽는
// 게이트도 없어서, 작업 메뉴가 선 뒤에도 README 가 *"검사를 시작하고"* 라고
// 적은 채 조용히 낡았다(2026-10-30 에 발견). `screens` 린트는 `crates/*/src/`
// 만 걷고 `xtask/` 는 보지 않으므로 그쪽도 이 글을 보지 못한다.
#[cfg(test)]
mod tests {
    use super::*;

    /// 역슬래시와 CR 을 **상수로 둔다.** 시험 본문에 리터럴로 흩뿌리면 어느
    /// 것이 escape 이고 어느 것이 글자인지 읽는 사람이 세어야 한다.
    const BSLASH: &str = "\\";
    const CR: &str = "\r";

    fn packed(name: &str) -> Packed {
        Packed {
            dir: PathBuf::from(name),
            name: name.to_string(),
            id: name.to_string(),
            version: "1.0.0".into(),
            tree: BTreeMap::new(),
        }
    }

    fn make_for(plugins: usize, anchored: bool, exe: &str) -> String {
        let ps: Vec<Packed> = (0..plugins).map(|i| packed(&format!("rule{i}"))).collect();
        // **운영과 같은 꼴로 먹인다.** `files` 에는 `PathBuf::join` 이 만든
        // 토막(호스트 구분자)과 서명 트리의 키(`/`)가 **섞여** 들어온다.
        // 처음 이 시험은 `/` 만 든 입력을 먹였고, 그래서 통과하면서도 리눅스
        // 판에 역슬래시가 남는 것을 놓쳤다 — 실제 산출물이 그것을 드러냈다
        // (2026-10-30). 시험의 입력이 운영의 입력과 다르면 통과가 거짓이다.
        let files = vec![
            format!("plugins{BSLASH}rule0{BSLASH}plugin.yaml"),
            format!("plugins{BSLASH}rule0{BSLASH}rules/evilai.yar"),
        ];
        readme(Path::new("."), &ps, exe, &files, anchored)
    }

    fn make(plugins: usize, anchored: bool) -> String {
        make_for(plugins, anchored, "remedy.exe")
    }

    /// 리눅스 판. **`--bin` 의 이름이 플랫폼을 말한다** — 호스트가 아니다.
    fn make_nix(plugins: usize, anchored: bool) -> String {
        make_for(plugins, anchored, "remedy")
    }

    /// 받는 사람이 **가장 먼저 읽는 글이 가장 먼저 보는 화면과 같아야 한다.**
    /// 우클릭으로 띄우면 검사가 아니라 질문이 먼저 뜬다.
    #[test]
    fn anchored_readme_asks_before_it_scans() {
        let r = make(1, true);
        assert!(r.contains("무엇을 할지 번호로 묻습니다"), "{r}");
        assert!(!r.contains("검사를 시작하고"), "{r}");
    }

    /// 화면의 줄을 **그 글자 그대로** 적는다 — 받는 사람이 눈으로 맞출 수 있어야
    /// 한다. 이 셋은 `menu.rs` 의 `PLUGIN_ITEMS`·`RUN_ITEMS` 라벨이다.
    #[test]
    fn anchored_readme_quotes_the_menu_lines() {
        let r = make(1, true);
        for line in ["검사하고 치료하기", "검사만 하기", "치료 전으로 복원하기"]
        {
            assert!(r.contains(line), "{line} 이 없다: {r}");
        }
    }

    /// 룰이 여럿이면 **작업 메뉴보다 먼저** 어느 룰인지 묻는다. 그것을 적지
    /// 않으면 받는 사람이 멈춘 화면을 고장으로 본다.
    #[test]
    fn two_rules_warn_that_the_rule_question_comes_first() {
        let r = make(2, true);
        assert!(r.contains("검사 항목이 2개"), "{r}");
        assert!(r.contains("먼저 어느 것을 볼지"), "{r}");
        // 1번은 전부로 검사만이다 — 화면의 그 줄(`guided::choose`)을 글자 그대로 적는다.
        assert!(r.contains("1번 '2개 모두 검사만 하기'"), "{r}");
        // 작업 뒤 그 질문으로 돌아온다 — 다시 실행하라고 하면 틀린 말이다.
        assert!(!r.contains("한 번 더 실행"), "{r}");
        assert!(r.contains("처음 질문으로 돌아옵니다"), "{r}");
        // 하나면 묻지 않으므로 그 줄을 내지 않는다.
        assert!(!make(1, true).contains("먼저 어느 것을 볼지"));
        assert!(!make(1, true).contains("모두 검사만"));
    }

    /// 앵커가 없으면 우클릭 길이 막힌다 — **메뉴를 약속하면 안 된다.**
    /// 그 빌드에서는 안내 모드가 꾸러미를 검증하지 못해 종료 5 로 끝난다.
    #[test]
    fn unanchored_readme_does_not_promise_the_menu() {
        let r = make(1, false);
        assert!(r.contains("확인하지 못합니다"), "{r}");
        assert!(!r.contains("무엇을 할지 번호로 묻습니다"), "{r}");
        assert!(r.contains("신뢰 앵커가 박혀 있지 않습니다"), "{r}");
    }

    /// 🔴 **리눅스 꾸러미에 되지 않는 일을 적지 않는다** (결정 10-2).
    ///
    /// 2026-10-29 까지 이 글은 한 판뿐이었고 우클릭·SmartScreen·역슬래시·CRLF
    /// 를 전제했다. 같은 파일의 다른 검사는 *"리눅스에서 만든 꾸러미도
    /// Windows 에서 풀린다"* 며 플랫폼을 가리지 않는데 **안내문만 한쪽을
    /// 전제했다.**
    #[test]
    fn linux_readme_does_not_tell_windows_things() {
        let r = make_nix(1, true);
        for w in [
            "마우스 오른쪽 단추",
            "SmartScreen",
            "Windows PowerShell",
            "터미널(관리자)",
        ] {
            assert!(!r.contains(w), "리눅스 판에 '{w}' 가 있다: {r}");
        }
        assert!(!r.contains(BSLASH), "역슬래시가 남았다: {r}");
        assert!(!r.contains(CR), "CRLF 가 남았다: {r}");
    }

    /// 리눅스 판은 **터미널과 `sudo`** 로 말한다. 그리고 첫 벽이 다르다 —
    /// Windows 는 SmartScreen 이고 리눅스는 실행 권한이다.
    #[test]
    fn linux_readme_says_terminal_and_sudo() {
        let r = make_nix(1, true);
        assert!(
            r.contains("터미널에서 이 폴더로 이동한 뒤 sudo ./remedy"),
            "{r}"
        );
        assert!(
            r.contains("sudo ./remedy run --plugin ./plugins/rule0/plugin.yaml"),
            "{r}"
        );
        assert!(r.contains("chmod +x ./remedy"), "{r}");
        // chmod 로도 안 되는 벽(noexec)과 sudo 를 빠뜨린 벽을 따로 적는다. 제목에는 sudo 가
        // 실행 권한이 빠진 파일에 내는 말(command not found)도 둔다.
        assert!(r.contains("noexec"), "{r}");
        assert!(
            r.contains("'command not found' 나 'Permission denied'"),
            "{r}"
        );
        assert!(r.contains("'root 권한이 없습니다' 가 나오면"), "{r}");
        // `plugin verify` 도 이 기계의 폐기 목록을 읽는다 — root 가 한 번 돌린 뒤에는
        // sudo 없이 종료 4 다(2026-11-07 실측).
        assert!(
            r.contains("sudo ./remedy plugin verify --dir ./plugins/rule0"),
            "{r}"
        );
    }

    /// 메뉴는 치료 기록을 이 폴더의 `state` 에 남긴다 — 폴더를 지우면 되돌릴 수 없다.
    /// 운영자 가이드는 꾸러미에 없으므로 주소로 적는다.
    #[test]
    fn anchored_readme_says_keep_the_folder_and_where_the_guide_is() {
        for r in [make(1, true), make_nix(2, true)] {
            assert!(r.contains("이 폴더를 지우지 마십시오"), "{r}");
            assert!(r.contains("로컬 디스크에 풀어"), "{r}");
            assert!(r.contains("remedy#위협별-안내"), "{r}");
            assert!(r.contains("치료를 되돌리지"), "{r}");
            assert!(
                r.contains("https://github.com/ESTsecurity/remedy/blob/main/docs/operator.md"),
                "{r}"
            );
            assert!(!r.contains("꾸러미"), "{r}");
        }
    }

    /// Windows 판은 전과 같은 말을 한다 — **분기가 한쪽을 바꾸지 않았다.**
    #[test]
    fn windows_readme_keeps_its_own_words() {
        let r = make(1, true);
        for w in [
            "마우스 오른쪽 단추",
            "SmartScreen",
            ".\\remedy.exe run --plugin .\\plugins\\rule0\\plugin.yaml",
            "rules\\ 에 있어야",
        ] {
            assert!(r.contains(w), "'{w}' 가 없다: {r}");
        }
        assert!(!r.contains("chmod"), "{r}");
        assert!(r.contains(CR), "Windows 판은 CRLF 다: {r}");
    }

    /// 앵커가 없는 리눅스 판도 우클릭을 말하지 않는다.
    #[test]
    fn unanchored_linux_readme_says_terminal_too() {
        let r = make_nix(1, false);
        assert!(r.contains("터미널에서 이 폴더로 이동해"), "{r}");
        assert!(!r.contains("우클릭"), "{r}");
    }
}
