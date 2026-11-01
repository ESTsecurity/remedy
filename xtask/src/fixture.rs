//! VM 검증용 격리 컨테이너를 만든다.
//!
//! # 왜 xtask 인가
//!
//! 격리물을 **만드는** 것은 `file.quarantine_only`(P6)의 몫이고, P5 에는 아직
//! 없다. 그런데 P5 의 검증은 실기기에서 "격리 → 복원 → 원본 동일" 을 봐야 한다.
//!
//! 제품 바이너리에 "컨테이너를 만드는" 명령을 넣으면 그것은 CLI 표면이 되고,
//! 설계-09 §3.4 의 Phase 별 명령 표와 어긋난다. 그래서 **개발 도구 쪽에** 둔다.
//!
//! # 왜 패스프레이즈 wrap 인가
//!
//! 호스트에서 만들어 VM 으로 옮기므로 로컬 머신 키로는 열리지 않는다. 그것이
//! 오히려 검증에 쓸모가 있다 — 같은 컨테이너로 "다른 머신에서는 로컬 키로
//! 안 열린다" 와 "패스프레이즈·조직 키로는 열린다" 를 함께 볼 수 있다.

use remedy_quarantine::{Builder, ContentKey, Entry, Header, MachineKey};
use remedy_sdk::EntryKind;
use std::path::Path;

/// 만들 픽스처 한 벌.
///
/// `dest_prefix` 아래에 복원될 항목들과, **일부러 보호 경로를 가리키는 항목**을
/// 함께 담는다. 후자는 가드 역검증용이다.
pub fn run(args: &[String]) -> Result<(), String> {
    let mut out = None;
    let mut pass_out = None;
    let mut org_out = None;
    let mut org_pub_out = None;
    let mut dest_prefix = None;
    let mut i = 0;
    while i + 1 < args.len() {
        match args[i].as_str() {
            "--out" => out = Some(args[i + 1].clone()),
            "--passphrase-out" => pass_out = Some(args[i + 1].clone()),
            "--org-secret-out" => org_out = Some(args[i + 1].clone()),
            // **공개키도 파일로 낸다** (2026-09-21). 컨테이너 안에만 있으면
            // `apply --org-public-file` 로 *제품이* org wrap 을 싣는 경로를
            // 잴 수 없다 — 지금까지 org wrap 이 붙은 컨테이너는 전부 이
            // 명령이 만든 것이었다.
            "--org-public-out" => org_pub_out = Some(args[i + 1].clone()),
            "--dest-prefix" => dest_prefix = Some(args[i + 1].clone()),
            other => return Err(format!("알 수 없는 인자: {other}")),
        }
        i += 2;
    }
    let out = out.ok_or("--out 이 필요하다")?;
    let dest_prefix = dest_prefix.ok_or("--dest-prefix 가 필요하다 (VM 안의 복원 대상 경로)")?;
    let passphrase = "remedy-p5-vm-fixture";

    let ck = ContentKey::generate().map_err(|e| e.to_string())?;
    let (org_sk, org_pk) = remedy_quarantine::generate_org_keypair().map_err(|e| e.to_string())?;
    // 로컬 wrap 도 넣는다 — **호스트의 머신 키로 감싼 것이 VM 에서 열리지 않는다**
    // 는 사실 자체가 검증 항목이다.
    let mk = MachineKey::from_bytes([0x5A; 32]);

    let header = Header {
        run_id: "01JP5VMFIXTURE0000000000".into(),
        created: "2026-08-21T00:00:00Z".into(),
        core_version: env!("CARGO_PKG_VERSION").into(),
        cipher: remedy_quarantine::key::CIPHER_ID.into(),
        wraps: vec![
            mk.wrap(&ck).map_err(|e| e.to_string())?,
            remedy_quarantine::wrap_with_passphrase(passphrase, &ck).map_err(|e| e.to_string())?,
            remedy_quarantine::wrap_with_org_key(&org_pk, &ck).map_err(|e| e.to_string())?,
        ],
    };

    let sep = if dest_prefix.contains('\\') {
        '\\'
    } else {
        '/'
    };
    let p = |name: &str| format!("{}{}{}", dest_prefix.trim_end_matches(sep), sep, name);

    let mut b = Builder::new(header, "vm-fixture").threat("Locust");
    // 1. 평범한 파일. 바이트가 그대로 나와야 한다.
    b.add(Entry {
        kind: EntryKind::File,
        origin: p("updater.exe"),
        meta: serde_json::json!({ "readonly": false }),
        content: (0u8..=255).cycle().take(4096).collect(),
    });
    // 2. 한글 이름 + 비ASCII 본문. 인코딩이 왕복에서 깨지지 않는지 본다.
    b.add(Entry {
        kind: EntryKind::File,
        origin: p("설정 파일.dat"),
        meta: serde_json::json!({ "readonly": false }),
        content: "한글 내용 · 탭\t줄바꿈\n끝".as_bytes().to_vec(),
    });
    // 3. 빈 파일. 0바이트도 파일이다.
    b.add(Entry {
        kind: EntryKind::File,
        origin: p("empty.bin"),
        meta: serde_json::json!({}),
        content: Vec::new(),
    });
    // 4. 읽기 전용으로 되돌아가야 하는 파일.
    b.add(Entry {
        kind: EntryKind::File,
        origin: p("readonly.txt"),
        meta: serde_json::json!({ "readonly": true }),
        content: b"read only".to_vec(),
    });
    // 4b. 명시적 DACL 이 되돌아가야 하는 파일.
    //
    // **잘 알려진 SID 만 쓴다.** 이 호스트에서 뜬 SDDL 을 그대로 넣으면 그 안의
    // SID 가 VM 에서 해석되지 않고, 그러면 무엇을 재는지 흐려진다 — 설계-02 §9 가
    // 다른 머신 제자리 복원을 지원 범위에서 뺀 이유가 정확히 그것이다.
    //   BA = Builtin\Administrators · SY = LocalSystem · FA = 전체 권한
    // `P` 는 상속을 끊는다. 끊지 않으면 부모에서 내려온 ACE 와 섞여
    // "되돌아왔는가" 를 판정할 수 없다.
    b.add(Entry {
        kind: EntryKind::File,
        origin: p("acl.txt"),
        meta: serde_json::json!({
            "readonly": false,
            "sddl": "D:P(A;;FA;;;BA)(A;;FA;;;SY)"
        }),
        content: b"explicit dacl".to_vec(),
    });
    // 4c. 수정 시각이 되돌아가야 하는 파일. 2001-09-09T01:46:40Z.
    b.add(Entry {
        kind: EntryKind::File,
        origin: p("mtime.txt"),
        meta: serde_json::json!({ "mtime_unix": 1_000_000_000, "mtime_nanos": 0 }),
        content: b"timestamped".to_vec(),
    });
    // 5. **보호 경로를 가리키는 항목.** 가드가 막아야 한다.
    b.add(Entry {
        kind: EntryKind::File,
        origin: "C:\\Windows\\System32\\remedy-should-never-write.dll".into(),
        meta: serde_json::json!({}),
        content: b"guard bait".to_vec(),
    });

    let bytes = b.seal(&ck).map_err(|e| e.to_string())?;
    if let Some(dir) = Path::new(&out).parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(&out, &bytes).map_err(|e| format!("{out}: {e}"))?;

    if let Some(p) = pass_out {
        std::fs::write(&p, passphrase).map_err(|e| format!("{p}: {e}"))?;
        println!("  패스프레이즈 -> {p}");
    }
    if let Some(p) = org_out {
        std::fs::write(&p, org_sk).map_err(|e| format!("{p}: {e}"))?;
        println!("  조직 개인키 -> {p}");
    }
    if let Some(p) = org_pub_out {
        std::fs::write(&p, org_pk).map_err(|e| format!("{p}: {e}"))?;
        println!("  조직 공개키 -> {p}");
    }

    println!(
        "픽스처 컨테이너 -> {out}  ({} 바이트 · 엔트리 7)",
        bytes.len()
    );
    println!("  복원 대상 접두: {dest_prefix}");
    println!("  wrap: local(호스트 키 — VM 에서 열리면 안 된다) · pass · org");
    Ok(())
}
