//! write 의 시험 — 2026-11-17 에 write.rs(3,360줄 중 시험 1,195줄)에서 떼어 냈다. 내용은 그대로이고,
//! 안에 든 모듈의 `super::` 만 `super::super::`(= write)로 바꿨다.

use super::*;

fn tmp(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("remedy-restore-test-{name}"));
    let _ = cleanup(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// 읽기 전용 파일이 남아 있으면 `remove_dir_all` 이 Windows 에서 실패한다.
/// 시험 뒷정리이므로 지우기 전에 푸는 것으로 충분하다.
#[allow(clippy::permissions_set_readonly_false)]
fn cleanup(dir: &std::path::Path) -> std::io::Result<()> {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if let Ok(md) = std::fs::metadata(&p) {
                if md.permissions().readonly() {
                    let mut perm = md.permissions();
                    perm.set_readonly(false);
                    let _ = std::fs::set_permissions(&p, perm);
                }
            }
        }
    }
    std::fs::remove_dir_all(dir)
}

#[test]
fn content_and_mtime_round_trip() {
    let dir = tmp("round");
    let src = dir.join("원본.bin");
    std::fs::write(&src, b"hello").unwrap();
    let meta = capture_meta(src.to_str().unwrap()).unwrap();
    std::fs::remove_file(&src).unwrap();

    let r = FsRestore
        .restore_file(src.to_str().unwrap(), b"hello", &meta)
        .unwrap();
    assert!(r.restored.contains(&"content".to_string()));
    assert!(r.restored.contains(&"mtime".to_string()));
    assert_eq!(std::fs::read(&src).unwrap(), b"hello");

    let back = capture_meta(src.to_str().unwrap()).unwrap();
    assert_eq!(back.mtime_unix, meta.mtime_unix);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_backend_that_does_not_walk_lineage_says_so_instead_of_saying_none() {
    // **기본 구현은 `Ok(vec![])` 이 아니라 오류여야 한다.** 빈 목록을
    // 돌려주면 계획이 켠 `include_descendants` 가 조용히 무시되고,
    // "자손이 없다" 와 "자손을 못 봤다" 가 같은 값이 된다 (설계-00 §5-1).
    //
    // 실행기 쪽 시험(`p8_guards.rs`)은 가짜가 이 메서드를 **재정의하므로**
    // 기본 구현에 닿지 않는다. 역검증에서 그 구멍이 드러났다 — 기본을
    // 빈 목록으로 바꿔도 아무 시험도 빨개지지 않았다.
    let r = FsRestore.process_descendants(&[1, 2, 3]);
    assert!(
        matches!(r, Err(PlatformError::Unsupported(_))),
        "기본 구현이 오류가 아니다: {r:?}"
    );
}

#[test]
fn a_deleted_parent_directory_is_recreated() {
    // 원본이 있던 디렉터리째 지워졌을 수 있다. 그것도 복원의 일부다.
    let dir = tmp("parent");
    let deep = dir.join("a").join("b").join("c.txt");
    let r = FsRestore
        .restore_file(deep.to_str().unwrap(), b"x", &FileMeta::default())
        .unwrap();
    assert!(r.restored.contains(&"content".to_string()));
    assert_eq!(std::fs::read(&deep).unwrap(), b"x");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_readonly_file_in_the_way_is_replaced() {
    // 읽기 전용이던 파일이 그 자리에 남아 있으면 쓰기가 막힌다.
    let dir = tmp("ro");
    let p = dir.join("ro.txt");
    std::fs::write(&p, b"old").unwrap();
    let mut perm = std::fs::metadata(&p).unwrap().permissions();
    perm.set_readonly(true);
    std::fs::set_permissions(&p, perm).unwrap();

    FsRestore
        .restore_file(p.to_str().unwrap(), b"new", &FileMeta::default())
        .unwrap();
    assert_eq!(std::fs::read(&p).unwrap(), b"new");

    cleanup(&dir).ok();
}

#[test]
fn readonly_is_set_last_so_the_write_is_not_blocked() {
    let dir = tmp("rolast");
    let p = dir.join("x.txt");
    let meta = FileMeta {
        readonly: Some(true),
        ..Default::default()
    };
    let r = FsRestore
        .restore_file(p.to_str().unwrap(), b"content", &meta)
        .unwrap();
    assert!(r.restored.contains(&"readonly".to_string()));
    assert_eq!(std::fs::read(&p).unwrap(), b"content");
    assert!(std::fs::metadata(&p).unwrap().permissions().readonly());

    cleanup(&dir).ok();
}

/// 생성 시각이 실제로 되돌아오는가 (Windows).
///
/// **1초 이상 기다린다.** NTFS 의 파일 터널링은 같은 이름·같은 디렉터리로
/// 짧은 시간 안에 다시 만든 파일에 예전 생성 시각을 물려준다. 기다리지 않으면
/// 이 시험은 우리가 되돌린 것인지 OS 가 물려준 것인지 구분하지 못한다 —
/// 실제로 P9 하네스의 G2 가 그 착시로 통과한 적이 있다 (2026-08-28 v1 점검).
#[cfg(windows)]
#[test]
fn a_windows_file_comes_back_with_its_creation_time() {
    let dir = tmp("btime");
    let p = dir.join("x");
    let s = p.to_str().unwrap();
    std::fs::write(&p, b"seed").unwrap();
    let meta = capture_meta(s).unwrap();
    let before = std::fs::metadata(&p).unwrap().created().unwrap();
    std::fs::remove_file(&p).unwrap();

    // 터널링 창을 벗어난다.
    std::thread::sleep(std::time::Duration::from_millis(1200));

    let r = FsRestore.restore_file(s, b"x", &meta).unwrap();
    assert!(
        r.restored.iter().any(|x| x == "btime"),
        "생성 시각을 되돌렸다고 말하지 않는다: {r:?}"
    );
    let after = std::fs::metadata(&p).unwrap().created().unwrap();
    // 파일 시스템의 시각 해상도만큼 차이가 날 수 있다. 1초면 터널링이 아닌
    // 것도 되돌린 것도 아닌 값을 걸러 낸다.
    let d = after
        .duration_since(before)
        .or_else(|_| before.duration_since(after));
    assert!(
        d.map(|x| x.as_secs() < 1).unwrap_or(false),
        "생성 시각이 돌아오지 않았다: {before:?} -> {after:?}"
    );
    let _ = cleanup(&dir);
}

#[test]
fn what_cannot_be_restored_is_always_reported() {
    // **"복원했습니다" 라고 뭉뚱그리지 않는다** (설계-02 §9).
    //
    // 되살릴 수 있는 것이 늘어도 이 성질은 그대로다 — ctime·btime 은 설정
    // syscall 이 아예 없고, Windows 의 SACL 은 특권 없이는 담지도 못한다.
    let dir = tmp("lost");
    let p = dir.join("x");
    let s = p.to_str().unwrap();

    // 지어낸 SDDL 대신 **실제로 있는 파일에서 뜬 값**을 쓴다. 지어낸 것은
    // 이 플랫폼에서 의미가 없을 수 있고, 그러면 무엇을 재는지 흐려진다.
    std::fs::write(&p, b"seed").unwrap();
    let meta = capture_meta(s).unwrap();
    std::fs::remove_file(&p).unwrap();

    let r = FsRestore.restore_file(s, b"x", &meta).unwrap();
    let items: Vec<&str> = r.lost.iter().map(|l| l.item.as_str()).collect();
    assert!(items.contains(&"ctime"), "{items:?}");
    // **btime 은 플랫폼이 갈린다.** Windows 에는 설정 API 가 있다 —
    // 아래 `a_windows_file_comes_back_with_its_creation_time` 이 그것을 잰다.
    #[cfg(not(windows))]
    assert!(items.contains(&"btime"), "{items:?}");

    #[cfg(windows)]
    {
        assert!(meta.sddl.is_some(), "SDDL 을 포착하지 못했다");
        assert!(
            r.restored.iter().any(|x| x == "sddl" || x == "dacl"),
            "포착한 SDDL 을 쓰지도 못하고 적지도 않았다: {r:?}"
        );
        assert!(items.contains(&"sacl"), "SACL 을 못 담았다고 말해야 한다");
    }
    #[cfg(unix)]
    {
        assert!(meta.mode.is_some(), "mode 를 포착하지 못했다");
        assert!(r.restored.iter().any(|x| x == "mode"), "{r:?}");
    }
    cleanup(&dir).ok();
}

#[test]
fn the_plan_warns_before_overwriting() {
    // 경고가 **복원 전**이라는 것이 명령의 형태를 정한다 (설계-03 §5).
    let dir = tmp("plan");
    let p = dir.join("있음.txt");
    std::fs::write(&p, "기존".as_bytes()).unwrap();
    let r = FsRestore.plan_restore(p.to_str().unwrap(), &FileMeta::default());
    // **기대값도 같은 언어로 짓는다.** 라이브러리 시험은 영어로 돌고
    // (`i18n::current` 의 기본값), `||` 로 두 언어를 받으면 어느 쪽으로
    // 돌았는지 모른 채 통과한다.
    let want = remedy_sdk::i18n::t("기존 파일", "existing file");
    assert!(
        r.lost.iter().any(|l| l.item == want),
        "덮어쓴다는 것을 미리 말해야 한다: {:?}",
        r.lost
    );
    assert_eq!(
        std::fs::read(&p).unwrap(),
        "기존".as_bytes(),
        "계산 단계가 파일을 건드렸다"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// 1.25.3 까지의 격리물은 `links` 만 든다 — 새 칸(`link_targets`)이 비어 그대로 읽히고(유닛 경로로
/// 단다), 빈 칸은 쓰지 않아 cron · Windows 의 `meta` 가 전과 같은 바이트다(이슈 #166 ⑤).
#[test]
fn a_persistence_index_from_before_link_targets_still_reads() {
    let old: PersistenceIndex = serde_json::from_value(serde_json::json!({
        "links": ["/etc/systemd/system/multi-user.target.wants/a.service"]
    }))
    .unwrap();
    assert_eq!(old.links.len(), 1);
    assert!(old.link_targets.is_empty());
    assert_eq!(
        serde_json::to_value(PersistenceIndex::default()).unwrap(),
        serde_json::json!({})
    );
}

// ─────────────────────────── P7 파일 계열 (설계-09 P7)
mod p7_tests {
    use super::super::*;

    /// 최소 `.lnk`. 실기기의 것과 같은 순서로 조립한다 —
    /// 헤더 0x4C · (IDList 없음) · (LinkInfo 없음) · StringData.
    fn lnk(flags: u32, strings: &[&str]) -> Vec<u8> {
        let mut b = vec![0u8; 0x4C];
        b[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
        b[20..24].copy_from_slice(&flags.to_le_bytes());
        for s in strings {
            let u: Vec<u16> = s.encode_utf16().collect();
            b.extend_from_slice(&(u.len() as u16).to_le_bytes());
            for c in u {
                b.extend_from_slice(&c.to_le_bytes());
            }
        }
        b
    }

    const HAS_NAME: u32 = 1 << 2;
    const HAS_RELATIVE: u32 = 1 << 3;
    const HAS_WORKDIR: u32 = 1 << 4;
    const HAS_ARGS: u32 = 1 << 5;
    const HAS_ICON: u32 = 1 << 6;
    const UNICODE: u32 = 1 << 7;

    #[test]
    fn stripping_arguments_keeps_everything_else() {
        let flags = UNICODE | HAS_NAME | HAS_RELATIVE | HAS_WORKDIR | HAS_ARGS | HAS_ICON;
        let before = lnk(
            flags,
            &["이름", "..\\a.exe", "C:\\work", "-enc BASE64", "C:\\i.ico"],
        );
        let after = strip_shortcut_arguments(&before).expect("인자가 있으니 바뀐다");

        // 인자 항목만큼 짧아진다: 길이 2바이트 + 문자 10개 * 2.
        assert_eq!(after.len(), before.len() - (2 + "-enc BASE64".len() * 2));
        // **플래그를 끄지 않으면 아이콘 경로가 인자로 읽힌다.**
        let f = u32::from_le_bytes([after[20], after[21], after[22], after[23]]);
        assert_eq!(f & HAS_ARGS, 0, "인자 플래그가 남았다");
        assert_eq!(f & HAS_ICON, HAS_ICON, "아이콘 플래그까지 껐다");
        // 남은 문자열이 밀리지 않았는지 — 아이콘 경로가 끝에 그대로 있다.
        let tail: Vec<u16> = after[after.len() - "C:\\i.ico".len() * 2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(String::from_utf16(&tail).unwrap(), "C:\\i.ico");
    }

    #[test]
    fn the_arguments_can_be_read_back_out() {
        // 읽는 쪽과 지우는 쪽이 **같은 구간 계산**을 봐야 한다. 따로 적으면
        // 한쪽만 고쳤을 때 "본 것과 지운 것이 다른" 상태가 조용히 생긴다.
        let flags = UNICODE | HAS_NAME | HAS_RELATIVE | HAS_WORKDIR | HAS_ARGS | HAS_ICON;
        let b = lnk(
            flags,
            &["이름", "..\\a.exe", "C:\\work", "-enc BASE64", "C:\\i.ico"],
        );
        assert_eq!(shortcut_arguments(&b).as_deref(), Some("-enc BASE64"));

        let none = lnk(UNICODE | HAS_NAME, &["이름"]);
        assert_eq!(shortcut_arguments(&none), None);
    }

    #[test]
    fn a_shortcut_whose_arguments_changed_since_the_plan_is_refused() {
        // 수집과 실행 사이에 사용자가 정당한 인자를 붙였을 수 있다. 지금 있는
        // 것을 그냥 떼면 그것이 계획에 없는 파괴다.
        let dir = std::env::temp_dir().join(format!("remedy-lnk-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("작업 폴더");
        let p = dir.join("s.lnk");
        std::fs::write(
            &p,
            lnk(UNICODE | HAS_NAME | HAS_ARGS, &["이름", "-enc NOW"]),
        )
        .expect("픽스처");
        let path = p.to_string_lossy().to_string();

        let err = FsRestore
            .shortcut_strip_args(&path, "-enc THEN")
            .expect_err("계획과 다른데 통과했다");
        assert!(
            format!("{err}").contains(remedy_sdk::i18n::t(
                "계획과 다릅니다",
                "differ from the plan"
            )),
            "{err}"
        );
        // **아무것도 쓰지 않았다.** 절반만 고친 바로가기를 남기면 안 된다.
        assert_eq!(
            shortcut_arguments(&std::fs::read(&path).expect("읽기")).as_deref(),
            Some("-enc NOW")
        );

        FsRestore
            .shortcut_strip_args(&path, "-enc NOW")
            .expect("계획과 같으면 뗀다");
        assert_eq!(
            shortcut_arguments(&std::fs::read(&path).expect("읽기")),
            None
        );
        // 이미 뗀 것을 다시 부르면 목표 상태가 이루어진 것이라 성공이다.
        FsRestore
            .shortcut_strip_args(&path, "-enc NOW")
            .expect("재기동에서 흔하다");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_exec_line_splits_the_same_way_the_collector_reads_it() {
        // 필드 코드는 인자가 아니다. 이 규칙이 갈라지면 계획이 담은 값과
        // 실행기가 떼는 것이 어긋나 정상 치료가 거절된다.
        assert_eq!(
            desktop_exec_args("[Desktop Entry]\nExec=/usr/bin/e --module /x/y.so %F\n").as_deref(),
            Some("--module /x/y.so")
        );
        // `[Desktop Action …]` 의 `Exec=` 는 그 동작의 것이지 항목의 것이 아니다.
        assert_eq!(
            desktop_exec_args("[Desktop Entry]\nName=A\n[Desktop Action X]\nExec=/bin/z --evil\n"),
            None
        );
        assert_eq!(
            desktop_exec_args("[Desktop Entry]\nExec=/usr/bin/e %U\n").as_deref(),
            Some("")
        );
    }

    #[test]
    fn a_shortcut_without_arguments_is_left_alone() {
        // 할 일이 없는데 파일을 다시 쓰면 수정 시각이 바뀌고, G3 가 그것을
        // 계획에 없는 변경으로 본다.
        let b = lnk(UNICODE | HAS_NAME | HAS_ICON, &["이름", "C:\\i.ico"]);
        assert!(strip_shortcut_arguments(&b).is_none());
    }

    #[test]
    fn a_truncated_shortcut_is_refused_not_half_written() {
        // 잘린 파일에서 구간을 들어내면 **깨진 바로가기를 만들어 낸다.**
        let flags = UNICODE | HAS_ARGS;
        let mut b = lnk(flags, &["-enc BASE64"]);
        b.truncate(b.len() - 6);
        assert!(strip_shortcut_arguments(&b).is_none());
    }

    #[test]
    fn something_that_is_not_a_shortcut_is_refused() {
        assert!(strip_shortcut_arguments(&[0u8; 8]).is_none());
        assert!(strip_shortcut_arguments(b"MZ\x90\x00").is_none());
    }

    #[test]
    fn a_multi_sz_round_trips() {
        // 재부팅 큐가 이 타입이다. **빈 문자열이 항목**이라 걸러 내면 짝이 깨지고,
        // 그러면 그 뒤 항목이 통째로 어긋나 엉뚱한 파일이 옮겨진다.
        let items = vec![
            "\\??\\C:\\a.exe".to_string(),
            String::new(),
            "\\??\\C:\\b.dll".to_string(),
            String::new(),
        ];
        let v = RegistryValueBackup::from_multi(&items);
        assert_eq!(v.vtype, 7);
        assert_eq!(v.as_multi().as_deref(), Some(&items[..]));

        // 빈 목록과 "빈 항목 하나" 는 다르다. 둘을 뭉개면 큐가 어긋난다.
        assert_eq!(
            RegistryValueBackup::from_multi(&[]).as_multi(),
            Some(Vec::new())
        );
        assert_eq!(
            RegistryValueBackup::from_multi(&[String::new()]).as_multi(),
            Some(vec![String::new()])
        );
    }

    #[test]
    fn a_dword_is_not_written_as_text() {
        // **이 시험이 지키는 것은 숫자 하나가 아니라 스위치의 뜻이다.**
        //
        // 문자열로 우회하면 `"0"` 이 UTF-16 로 `30 00` 이 되고 종단 NUL 까지
        // 정확히 4바이트라 레지스트리가 받아들인다. 그 넷을 수로 읽으면
        // **48** 이고, `LoadAppInit_DLLs` 에서 0 이 아닌 값은 "AppInit 적재를
        // 켠다" 는 뜻이다 — 치료가 스위치를 켠 채로 두고 껐다고 보고한다.
        let wrong = RegistryValueBackup::from_string(4, "0");
        assert_eq!(wrong.bytes, vec![0x30, 0, 0, 0], "우회의 모양을 고정한다");
        assert_eq!(
            u32::from_le_bytes([
                wrong.bytes[0],
                wrong.bytes[1],
                wrong.bytes[2],
                wrong.bytes[3]
            ]),
            48,
            "문자열로 쓴 '0' 은 0 이 아니다"
        );

        let right = RegistryValueBackup::from_dword(0);
        assert_eq!(right.vtype, 4);
        assert_eq!(right.bytes, vec![0, 0, 0, 0]);
        assert_eq!(RegistryValueBackup::from_dword(1).bytes, vec![1, 0, 0, 0]);
    }

    #[test]
    fn a_non_multi_value_is_not_read_as_a_list() {
        let v = RegistryValueBackup::from_string(1, "그냥 문자열");
        assert!(v.as_multi().is_none());
    }

    /// u16 열을 손으로 짓는다. `from_multi` 는 **늘 올바른 값**만 만들어서
    /// 손상된 것을 지날 수 없다 — 검체가 쓰는 것이 그쪽이다.
    fn u16s(s: &str) -> Vec<u16> {
        s.chars()
            .map(|c| if c == '·' { 0 } else { c as u16 })
            .collect()
    }

    #[test]
    fn a_multi_sz_without_a_terminator_keeps_its_items() {
        // **레지스트리는 임의 바이트를 담는다.** 종단을 뺀 값을 써 두면
        // "떼고 마지막 조각을 버린다" 를 곧이곧대로 하는 파서는 항목을 통째로
        // 잃는다. 잃는 것이 빈 항목 하나가 아니라 값 전체다.
        assert_eq!(split_multi_sz(&u16s("A·")), vec!["A".to_string()]);
        assert_eq!(split_multi_sz(&u16s("A")), vec!["A".to_string()]);
        assert_eq!(
            split_multi_sz(&u16s("A·B")),
            vec!["A".to_string(), "B".to_string()]
        );
    }

    #[test]
    fn a_multi_sz_keeps_empty_items_in_the_middle() {
        // 실기기의 `BootExecute` 모양이다. 가운데 빈 항목을 버리면 **스냅샷이
        // 5항목을 3항목이라고 적는다** (2026-09-05 실측).
        assert_eq!(
            split_multi_sz(&u16s("autocheck autochk *··bootalyac.exe··")),
            vec![
                "autocheck autochk *".to_string(),
                String::new(),
                "bootalyac.exe".to_string(),
            ]
        );
    }

    #[test]
    fn a_multi_sz_tells_no_items_from_one_empty_item() {
        // 재부팅 큐에서 이 둘은 다른 뜻이다 — 빈 목적지는 "지워라" 다.
        assert_eq!(split_multi_sz(&u16s("·")), Vec::<String>::new());
        assert_eq!(split_multi_sz(&[]), Vec::<String>::new());
        assert_eq!(split_multi_sz(&u16s("··")), vec![String::new()]);
    }

    // ── 설정 계열 (P7) ────────────────────────────────────────

    #[test]
    fn removing_a_line_keeps_every_other_byte() {
        // **줄 끝을 바꾸면 손대지 않은 줄까지 바꾼 것이다.** `lines()` 는
        // `\r\n` 과 `\n` 을 똑같이 버려서, 지우고 다시 이으면 파일 전체의
        // 줄 끝이 통일된다.
        let text = "a=1\r\nevil=1\r\nb=2\r\n";
        let out = remove_text_line(text, 2, "evil=1").expect("지워야 한다");
        assert_eq!(out, "a=1\r\nb=2\r\n");
    }

    #[test]
    fn a_file_without_a_trailing_newline_stays_that_way() {
        let text = "a=1\nevil=1";
        assert_eq!(
            remove_text_line(text, 2, "evil=1").as_deref(),
            Some("a=1\n")
        );
        let text2 = "evil=1\na=1";
        assert_eq!(remove_text_line(text2, 1, "evil=1").as_deref(), Some("a=1"));
    }

    #[test]
    fn a_line_whose_content_changed_is_refused() {
        // **번호만 보면 엉뚱한 줄을 지운다.** 수집과 실행 사이에 누가 위에
        // 줄을 넣으면 2번 줄은 다른 내용이 된다.
        let text = "새로 생긴 줄\na=1\nevil=1\n";
        assert!(remove_text_line(text, 2, "evil=1").is_none());
        // 그리고 아무것도 지우지 않았다 — 반환이 `None` 이므로 쓸 것이 없다.
    }

    #[test]
    fn a_line_number_past_the_end_is_refused() {
        assert!(remove_text_line("a=1\n", 9, "a=1").is_none());
        assert!(remove_text_line("a=1\n", 0, "a=1").is_none());
    }

    #[test]
    fn trailing_whitespace_does_not_break_the_match() {
        // 편집기가 줄 끝 공백을 건드리는 일은 흔하다. 그것 때문에 치료가
        // 실패하면 사용자는 이유를 알 수 없다.
        let text = "a=1\nevil=1   \n";
        assert_eq!(
            remove_text_line(text, 2, "evil=1").as_deref(),
            Some("a=1\n")
        );
    }

    #[test]
    fn a_removed_line_goes_back_where_it_was() {
        let before = "a=1\r\nevil=1\r\nb=2\r\n";
        let after = remove_text_line(before, 2, "evil=1").expect("지우기");
        assert_eq!(insert_text_line(&after, 2, "evil=1"), before);
    }

    #[test]
    fn restoring_into_a_shorter_file_appends_instead_of_losing_the_line() {
        // 복원 시점의 파일이 백업 시점과 다를 수 있다. **줄이 사라지는 것보다는
        // 자리가 다른 편이 낫다.**
        let out = insert_text_line("a=1\n", 9, "evil=1");
        assert!(out.ends_with("evil=1\n"), "{out:?}");
        assert!(out.starts_with("a=1\n"));
    }

    #[test]
    fn restoring_after_a_last_line_without_a_newline_does_not_glue_them() {
        let out = insert_text_line("a=1", 2, "evil=1");
        assert_eq!(out, "a=1\nevil=1\n");
    }

    #[test]
    fn removing_a_json_key_leaves_the_others() {
        let text = r#"{"keep":1,"evil":{"cmd":"x"},"also":"y"}"#;
        let out = json_remove_key(text, "evil").expect("지워야 한다");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("evil").is_none(), "{out}");
        assert_eq!(v["keep"], 1);
        assert_eq!(v["also"], "y");
    }

    #[test]
    fn removing_a_nested_json_key_walks_the_path() {
        let text = r#"{"a":{"b":{"evil":1,"ok":2}}}"#;
        let out = json_remove_key(text, "a.b.evil").expect("지워야 한다");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v["a"]["b"].get("evil").is_none());
        assert_eq!(v["a"]["b"]["ok"], 2);
    }

    #[test]
    fn removing_an_array_element_is_refused() {
        // **뒤 원소의 색인이 전부 밀린다.** 같은 파일의 다른 Action 이 그
        // 색인을 가리키고 있으면 엉뚱한 것을 지운다.
        let text = r#"{"list":["a","evil","c"]}"#;
        assert!(json_remove_key(text, "list.1").is_none());
    }

    #[test]
    fn removing_a_key_that_is_not_there_is_refused() {
        // 없는 것을 지웠다고 보고하면 "치료했다" 가 거짓이 된다.
        assert!(json_remove_key(r#"{"a":1}"#, "b").is_none());
        assert!(json_remove_key(r#"{"a":1}"#, "a.b.c").is_none());
    }

    #[test]
    fn broken_json_is_refused_not_rewritten() {
        // 깨진 JSON 을 심어 두는 것도 수법이다. 파싱 실패를 **다시 써서**
        // 고쳐 주면 그 파일이 우리 손으로 정상화된다.
        assert!(json_remove_key("{이건 JSON 이 아니다", "a").is_none());
        assert!(json_set_key("{이건 JSON 이 아니다", "a", "x").is_none());
    }

    #[test]
    fn an_xml_config_is_refused_not_rewritten() {
        // 구조적 설정은 XML 도 편다(2026-11-11) — 그 잎을 겨눈 치료 계획이 와도 **고치는 Op 은
        // JSON 만**이다. XML 을 JSON 으로 읽다 실패하므로 아무것도 쓰지 않는다.
        let xml = r#"<configuration><system.webServer><fastCgi><application fullPath="C:\php83\php-cgi.exe" /></fastCgi></system.webServer></configuration>"#;
        let key = "configuration[0]/system.webServer[0]/fastCgi[0]/application[0]/@fullPath";
        assert!(json_remove_key(xml, key).is_none());
        assert!(json_set_key(xml, key, "x").is_none());
    }

    #[test]
    fn setting_a_key_does_not_create_it() {
        // **만들지 않는다.** 없는 자리를 만들어 쓰면 그것은 복원이 아니라 생성이다.
        assert!(json_set_key(r#"{"a":1}"#, "b", "x").is_none());
        let out = json_set_key(r#"{"a":"evil"}"#, "a", "explorer.exe").expect("써야 한다");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["a"], "explorer.exe");
    }

    #[test]
    fn splitting_a_value_name_handles_the_default_value() {
        // 역슬래시로 끝나면 값 이름이 빈 문자열이고, 그것이 **(기본) 값**이다 —
        // `exefile\shell\open\command` 의 기본값처럼 하이재킹의 표적이 거기 있다.
        assert_eq!(
            split_value_name("HKLM\\SOFTWARE\\X\\Name"),
            Some(("HKLM\\SOFTWARE\\X", "Name"))
        );
        assert_eq!(
            split_value_name("HKLM\\Classes\\exefile\\shell\\open\\command\\"),
            Some(("HKLM\\Classes\\exefile\\shell\\open\\command", ""))
        );
        assert_eq!(split_value_name("하이브없음"), None);
    }
}

// ───────────────────────────────── 디렉터리와 예약 작업 (P7)
mod p7_dir_task_tests {
    use super::super::*;

    struct Tmp(std::path::PathBuf);

    impl Tmp {
        fn new(name: &str) -> Self {
            let p = std::env::temp_dir().join(format!("remedy-dirtest-{name}"));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).expect("작업 디렉터리");
            Self(p)
        }
        fn s(&self) -> String {
            self.0.to_string_lossy().to_string()
        }
        fn join(&self, rel: &str) -> String {
            self.0.join(rel).to_string_lossy().to_string()
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Chromium 확장을 닮은 나무. 빈 디렉터리를 하나 끼운다.
    fn build(root: &std::path::Path) {
        std::fs::create_dir_all(root.join("_locales/ko")).unwrap();
        std::fs::create_dir_all(root.join("비어있음")).unwrap();
        std::fs::write(root.join("manifest.json"), br#"{"name":"x"}"#).unwrap();
        std::fs::write(root.join("_locales/ko/messages.json"), b"{}").unwrap();
        std::fs::write(root.join("bg.js"), b"var a=1;\n").unwrap();
    }

    fn snapshot(root: &std::path::Path) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                let rel = p
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                if p.is_dir() {
                    out.push((format!("d:{rel}"), Vec::new()));
                    stack.push(p);
                } else {
                    out.push((format!("f:{rel}"), std::fs::read(&p).unwrap()));
                }
            }
        }
        out.sort();
        out
    }

    #[test]
    fn a_directory_round_trips_with_its_empty_folders() {
        // **빈 디렉터리는 파일 목록에 흔적을 남기지 않는다.** 목차가 그것을
        // 따로 담지 않으면 복원된 확장이 원래 모습이 아니다.
        let t = Tmp::new("roundtrip");
        let src = t.0.join("확장");
        std::fs::create_dir_all(&src).unwrap();
        build(&src);
        let want = snapshot(&src);

        let (body, index) = FsRestore.dir_read(&src.to_string_lossy()).expect("담기");
        assert!(index.dirs.iter().any(|d| d == "비어있음"), "{index:?}");
        assert_eq!(index.files.len(), 3, "{index:?}");

        FsRestore
            .dir_destroy(&src.to_string_lossy())
            .expect("지우기");
        assert!(!src.exists());

        FsRestore
            .dir_restore(&src.to_string_lossy(), &body, &index)
            .expect("되돌리기");
        assert_eq!(snapshot(&src), want, "되돌린 나무가 원본과 다르다");
    }

    #[test]
    fn the_same_directory_gives_the_same_bytes_twice() {
        // 파일 시스템의 열거 순서는 보장되지 않는다. 순서를 고정하지 않으면
        // 같은 입력이 다른 컨테이너를 내고 결정성 검사가 흔들린다.
        let t = Tmp::new("determinism");
        build(&t.0);
        let a = FsRestore.dir_read(&t.s()).expect("첫 번째");
        let b = FsRestore.dir_read(&t.s()).expect("두 번째");
        assert_eq!(a.0, b.0);
        assert_eq!(a.1, b.1);

        // **두 번 읽어 같은 것만으로는 부족하다.** `read_dir` 이 이 파일
        // 시스템에서 우연히 안정적이면, 정렬을 없애도 이 시험은 통과한다 —
        // 역검증에서 실제로 그렇게 샜다. 고정한 순서가 **무엇인지**를 직접
        // 잰다. 그래야 다른 파일 시스템에서도 같은 컨테이너가 나온다.
        let mut rels: Vec<&str> = a.1.files.iter().map(|f| f.rel.as_str()).collect();
        let got = rels.clone();
        rels.sort();
        assert_eq!(got, rels, "목차의 파일 순서가 고정돼 있지 않다");
        let mut dirs = a.1.dirs.clone();
        let got_dirs = dirs.clone();
        dirs.sort();
        assert_eq!(got_dirs, dirs, "목차의 디렉터리 순서가 고정돼 있지 않다");
    }

    #[test]
    fn a_torn_index_does_not_write_a_partial_tree() {
        // 컨테이너가 변조되면 목차와 본문이 어긋난다. 그때 앞부분만 쓰고
        // 멈추면 **반쯤 복원된 나무**가 남는다.
        let t = Tmp::new("torn");
        let dest = t.join("나가는곳");
        let index = DirIndex {
            dirs: Vec::new(),
            files: vec![DirEntry {
                rel: "a.txt".into(),
                size: 999,
                meta: FileMeta::default(),
            }],
        };
        let e = FsRestore
            .dir_restore(&dest, b"short", &index)
            .expect_err("거절해야 한다");
        assert!(
            e.to_string()
                .contains(remedy_sdk::i18n::t("본문 길이", "the body length")),
            "{e}"
        );
    }

    #[test]
    fn an_index_that_climbs_out_is_refused() {
        let t = Tmp::new("climb");
        let dest = t.join("나가는곳");
        for rel in ["../밖.txt", "/절대", "C:/절대", "a\\b"] {
            let index = DirIndex {
                dirs: Vec::new(),
                files: vec![DirEntry {
                    rel: rel.into(),
                    size: 0,
                    meta: FileMeta::default(),
                }],
            };
            let e = FsRestore
                .dir_restore(&dest, b"", &index)
                .expect_err("거절해야 한다");
            assert!(
                e.to_string()
                    .contains(remedy_sdk::i18n::t("루트 밖", "outside the root")),
                "{rel}: {e}"
            );
        }
    }

    #[test]
    fn a_contained_relative_path_is_allowed() {
        // 위 시험이 무엇이든 거절하는 것으로 통과하면 안 된다.
        assert!(rel_is_contained("_locales/ko/messages.json"));
        assert!(rel_is_contained("manifest.json"));
        assert!(!rel_is_contained(""));
        assert!(!rel_is_contained("a/./b"));
    }

    /// 재해석점을 만드는 데 Windows 는 특권이 필요하다. 코드는 두 OS 가
    /// 같은 것(`FsRestore`)을 쓰므로 여기서 재면 그 길이 재진다.
    #[cfg(unix)]
    #[test]
    fn a_symlink_inside_stops_the_whole_capture() {
        use std::os::unix::fs::symlink;
        let t = Tmp::new("symlink");
        build(&t.0);
        symlink("/etc", t.0.join("바깥")).unwrap();
        let e = FsRestore.dir_read(&t.s()).expect_err("거절해야 한다");
        // 기대값도 같은 언어로 — 시험은 영어로 돈다(`i18n::current` 기본값).
        assert!(
            e.to_string()
                .contains(remedy_sdk::i18n::t("재해석점", "reparse point")),
            "{e}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_root_is_not_deleted_through() {
        use std::os::unix::fs::symlink;
        let t = Tmp::new("symroot");
        let real = t.0.join("진짜");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("소중함.txt"), b"x").unwrap();
        let link = t.0.join("가리키는것");
        symlink(&real, &link).unwrap();
        let e = FsRestore
            .dir_destroy(&link.to_string_lossy())
            .expect_err("거절해야 한다");
        // 기대값도 같은 언어로 — 시험은 영어로 돈다(`i18n::current` 기본값).
        assert!(
            e.to_string()
                .contains(remedy_sdk::i18n::t("재해석점", "reparse point")),
            "{e}"
        );
        assert!(real.join("소중함.txt").exists(), "너머가 지워졌다");
    }

    // ── 예약 작업 등록 경로 ───────────────────────────────────

    /// 등록 경로의 **거절 사유는 복원 화면에 그대로 실려 나간다** —
    /// `remedy-core` 의 `restore::plan` 이 `"작업 등록 경로: {why} — '…'"` 로
    /// 감싸고 그것이 종료 코드 5 의 사유가 된다. 이름을 가려 아래 열둘이 함께
    /// 이 검사를 받는다 (`guard.rs` 의 `check` 래퍼와 같은 수).
    fn task_id_problem(id: &str) -> Option<&'static str> {
        let why = super::super::task_id_problem(id)?;
        assert!(
            !why.chars().any(|c| ('가'..='힣').contains(&c)),
            "등록 경로 거절 사유가 영어 회차에서 한글로 나온다: {why}"
        );
        Some(why)
    }

    #[test]
    fn a_normal_registration_path_passes() {
        assert_eq!(task_id_problem(r"\Microsoft\Windows\Locust"), None);
        assert_eq!(task_id_problem(r"\OneDrive Reporting Task"), None);
        assert!(is_task_target(r"\Locust"));
    }

    #[test]
    fn a_path_that_climbs_out_of_the_tasks_folder_is_refused() {
        // 등록 경로는 `%SystemRoot%\System32\Tasks\<id>` 로 풀린다. `..` 은
        // 임의 파일 읽기이고, 되돌릴 때는 임의 파일 쓰기다.
        for bad in [
            r"\..\..\..\Windows\System32\config\SAM",
            r"\Microsoft\..\..\밖",
            r"\a\.\b",
            r"\a\\b",
        ] {
            assert!(task_id_problem(bad).is_some(), "통과했다: {bad}");
        }
    }

    #[test]
    fn a_name_that_could_be_read_as_a_switch_is_refused() {
        // `/` 는 schtasks 의 스위치 문자다.
        assert!(task_id_problem(r"\a /Delete /TN \b").is_some());
        assert!(task_id_problem("\\a\"b").is_some());
        assert!(task_id_problem(r"\%SystemRoot%").is_some());
        assert!(task_id_problem("\\a\tb").is_some());
    }

    #[test]
    fn something_that_is_not_a_registration_path_is_refused() {
        // 파일 경로·UNC·레지스트리와 겹치면 안 된다.
        for bad in [
            r"C:\Windows\System32\Tasks\Locust",
            r"\\서버\공유\Locust",
            r"HKLM\SOFTWARE\a\b",
            "Locust",
            "",
        ] {
            assert!(task_id_problem(bad).is_some(), "통과했다: {bad}");
            assert!(!is_task_target(bad) || bad.starts_with('\\'), "{bad}");
        }
        assert!(!is_task_target(r"C:\a"));
        assert!(!is_task_target(r"\\서버\공유"));
    }

    #[test]
    fn a_trailing_space_or_dot_is_refused() {
        // Windows 가 파일 이름에서 말없이 떼어 낸다 — 지목한 것과 열리는 것이
        // 달라진다.
        assert!(task_id_problem(r"\Locust ").is_some());
        assert!(task_id_problem(r"\Locust.").is_some());
        assert!(task_id_problem(r"\ Locust").is_some());
    }
}

mod av_exclusion_target_tests {
    use super::super::*;

    // ── 보안 제품 예외 목록 대상 ─────────────────────────────────

    const EXCL: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions";

    #[test]
    fn an_exclusion_value_name_may_contain_backslashes() {
        // **여기가 조용히 실패하던 자리다.** `split_value_name` 은 마지막
        // 역슬래시에서 자르므로 이 대상을 키 `...\Paths\C:\Users\t` 와 값
        // `x-we9i6` 로 읽는다 — 그런 키는 없다.
        let t = format!("{EXCL}\\Paths\\C:\\Users\\t\\AppData\\Local\\Programs\\x-we9i6");
        assert_eq!(
            split_av_exclusion(&t),
            Some(("path", "C:\\Users\\t\\AppData\\Local\\Programs\\x-we9i6"))
        );
        // 대조군 — 옛 방식이 무엇을 내놓았는지 남겨 둔다.
        assert_eq!(
            split_value_name(&t).map(|(_, n)| n),
            Some("x-we9i6"),
            "옛 갈래는 마지막 조각만 값 이름으로 보았다"
        );
    }

    #[test]
    fn the_three_kinds_are_told_apart() {
        assert_eq!(
            split_av_exclusion(&format!("{EXCL}\\Processes\\dbeaver.exe")),
            Some(("process", "dbeaver.exe"))
        );
        assert_eq!(
            split_av_exclusion(&format!("{EXCL}\\Extensions\\.tmp")),
            Some(("ext", ".tmp"))
        );
    }

    #[test]
    fn registry_case_does_not_decide_this() {
        // 레지스트리 경로는 대소문자를 가리지 않는다. 여기서 가리면 증거가
        // 어느 대소문자로 오느냐에 따라 Action 이 거부된다.
        let t = format!("{}\\paths\\C:\\x", EXCL.to_lowercase());
        assert_eq!(split_av_exclusion(&t), Some(("path", "C:\\x")));
    }

    #[test]
    fn a_target_that_is_not_ascii_does_not_panic() {
        // 접두사 길이가 대상의 **문자 경계가 아닐 수 있다.** 바이트로 자르면
        // 거기서 패닉하고, 그것은 계획에 담긴 임의 문자열이 실행기를 죽이는
        // 길이 된다.
        for n in 1..40 {
            assert_eq!(split_av_exclusion(&"가".repeat(n)), None);
            assert_eq!(split_av_exclusion(&format!("x{}", "한".repeat(n))), None);
        }
    }

    #[test]
    fn what_is_not_an_exclusion_is_none_not_a_guess() {
        // 접두사가 맞아도 **값이 비면** 항목이 아니다 — 키 그 자체다.
        assert_eq!(split_av_exclusion(&format!("{EXCL}\\Paths\\")), None);
        assert_eq!(split_av_exclusion(&format!("{EXCL}\\Paths")), None);
        assert_eq!(
            split_av_exclusion("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\X"),
            None
        );
    }
}

mod walk_dir_tests {
    use super::super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("remedy-walk-dir-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn nested_tree_is_indexed_in_name_order_with_dirs_entered_in_place() {
        let root = tmp("nested");
        std::fs::create_dir_all(root.join("b/inner")).unwrap();
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::write(root.join("a/2.txt"), b"two").unwrap();
        std::fs::write(root.join("a/1.txt"), b"one").unwrap();
        std::fs::write(root.join("b/inner/deep.bin"), b"DEEP").unwrap();
        std::fs::write(root.join("c.txt"), b"c").unwrap();
        let mut index = DirIndex {
            dirs: Vec::new(),
            files: Vec::new(),
        };
        let mut body = Vec::new();
        walk_dir(&root, &root, &mut index, &mut body).expect("걷기");
        // 폴더는 만나는 자리에서 바로 내려간다: a, (a 의 파일들), b, b/inner, …, c.txt
        assert_eq!(index.dirs, vec!["a", "b", "b/inner"]);
        let rels: Vec<&str> = index.files.iter().map(|f| f.rel.as_str()).collect();
        assert_eq!(
            rels,
            vec!["a/1.txt", "a/2.txt", "b/inner/deep.bin", "c.txt"]
        );
        // 본문은 파일 순서대로 이어 붙는다.
        assert_eq!(body, b"onetwoDEEPc".to_vec());
        assert_eq!(
            index.files.iter().map(|f| f.size).sum::<u64>(),
            body.len() as u64
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_tree_deeper_than_the_limit_is_refused_not_overflowed() {
        let root = tmp("deep");
        // 상한(256)보다 깊은 트리. 이름을 한 글자로 두어 경로 길이를 아낀다 —
        // 표준 라이브러리가 긴 경로는 알아서 \\?\ 로 연다.
        let mut p = root.clone();
        for _ in 0..(MAX_DIR_DEPTH + 40) {
            p.push("d");
        }
        std::fs::create_dir_all(&p).expect("깊은 트리");
        std::fs::write(p.join("leaf"), b"x").unwrap();
        let mut index = DirIndex {
            dirs: Vec::new(),
            files: Vec::new(),
        };
        let mut body = Vec::new();
        let err = walk_dir(&root, &root, &mut index, &mut body).expect_err("걸려야 한다");
        let text = err.to_string();
        assert!(
            text.contains(remedy_sdk::i18n::t("너무 깊습니다", "too deep")),
            "{text}"
        );
        // 상한까지는 담았고, 그 너머에서 멈췄다.
        assert!(
            index.dirs.len() >= MAX_DIR_DEPTH - 2,
            "{}",
            index.dirs.len()
        );
        assert!(
            index.files.is_empty(),
            "잎은 상한 너머라 담기지 않아야 한다"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

mod scheduled_verify_default_tests {
    use super::super::*;

    /// `FsRestore` 는 예약을 다루지 않으므로 트레이트의 기본 구현을 그대로 쓴다.
    /// (리눅스 `Live` 도 한동안 같은 자리였다 — P12 에서 스스로 구현한다.)
    #[test]
    fn 예약하지_않는_백엔드는_지울_것이_없으므로_성공이다() {
        assert!(
            PlatformWrite::cancel_scheduled_verify(&FsRestore).is_ok(),
            "지울 것이 없는 것은 실패가 아니다 — 리눅스 verify 가 매번 헛경고를 찍던 자리"
        );
        // 예약과 조회는 여전히 "이 백엔드는 못 한다" 가 답이다.
        assert!(PlatformWrite::scheduled_verify(&FsRestore).is_err());
        // 승인 전 질의도 같은 답이고, 앉을 자리를 지어내지 않는다.
        assert!(PlatformWrite::verify_after_reboot_support(&FsRestore).is_err());
        assert_eq!(PlatformWrite::scheduled_verify_site(&FsRestore), None);
        assert!(PlatformWrite::schedule_verify_after_reboot(
            &FsRestore,
            "run-1",
            std::path::Path::new("remedy"),
            std::path::Path::new("plugin.yaml"),
            None,
            remedy_sdk::i18n::Lang::En,
        )
        .is_err());
    }
}

/// **트레이트 기본값이 영어 회차에서 한글을 내지 않는가.**
///
/// 이 답들은 개발자용이 아니다. 리눅스 백엔드는 Windows 전용 메서드를 구현하지
/// 않으므로, 리눅스에서 그런 Op 을 만나면 **기본값이 그대로 고객 화면으로**
/// 나간다 — 14회차가 `survey_recursive_target` 에서 실제 경로를 확인했다.
///
/// 목록은 손으로 적는다. 새 메서드가 들어오면 여기에 더해야 재어진다.
mod trait_default_tests {
    use super::super::*;

    fn has_hangul(s: &str) -> bool {
        s.chars().any(|c| ('가'..='힣').contains(&c))
    }

    /// 필수 여섯만 구현한다 — **나머지는 전부 트레이트 기본값**이다.
    struct Bare;

    impl PlatformWrite for Bare {
        fn backend_name(&self) -> &'static str {
            "bare"
        }
        fn plan_restore(&self, _dest: &str, _meta: &FileMeta) -> RestoreReport {
            RestoreReport::default()
        }
        fn quarantine_read(&self, _path: &str) -> Result<(Vec<u8>, FileMeta), PlatformError> {
            unreachable!("이 시험은 백업하지 않는다")
        }
        fn restore_file(
            &self,
            _dest: &str,
            _bytes: &[u8],
            _meta: &FileMeta,
        ) -> Result<RestoreReport, PlatformError> {
            unreachable!("이 시험은 복원하지 않는다")
        }
        fn destroy_file(&self, _path: &str) -> Result<(), PlatformError> {
            unreachable!("이 시험은 파괴하지 않는다")
        }
        fn exists(&self, _path: &str) -> bool {
            false
        }
    }

    macro_rules! all_english {
        ($($call:expr),+ $(,)?) => {
            $(
                match $call {
                    Err(PlatformError::Unsupported(why)) => {
                        if has_hangul(why) {
                            panic!("{} 의 기본값에 한글이 있다: {why}", stringify!($call));
                        }
                    }
                    _ => panic!(
                        "{} 의 기본값이 Unsupported 가 아니다",
                        stringify!($call)
                    ),
                }
            )+
        };
    }

    #[test]
    fn every_trait_default_answers_in_english() {
        let b = Bare;
        let reg = RegistryValueBackup {
            vtype: 0,
            bytes: Vec::new(),
        };
        all_english!(
            b.registry_read("x"),
            b.registry_delete("x"),
            b.registry_write("x", &reg),
            b.schedule_verify_after_reboot(
                "r",
                std::path::Path::new("remedy"),
                std::path::Path::new("p.yaml"),
                None,
                remedy_sdk::i18n::Lang::En,
            ),
            b.scheduled_verify(),
            b.verify_after_reboot_support(),
            b.av_exclusions_read(),
            b.av_exclusions_write(&[]),
            b.schedule_delete_on_reboot("x"),
            b.stream_read("x"),
            b.stream_delete("x"),
            b.shortcut_strip_args("x", "y"),
            b.text_line_read("x", 1),
            b.text_line_remove("x", 1, "y"),
            b.text_line_restore("x", 1, "y"),
            b.structured_remove_key("x", "y"),
            b.structured_set_key("x", "y", "z"),
            b.dir_read("x"),
            b.dir_destroy("x"),
            b.dir_restore("x", &[], &DirIndex::default()),
            b.persistence_read("x"),
            b.persistence_disable("x", None),
            b.persistence_delete("x", None),
            b.persistence_restore("x", &[], &PersistenceIndex::default()),
            b.cert_read("x"),
            b.cert_delete("x"),
            b.cert_restore("x", &[]),
            b.registry_key_read("x"),
            b.registry_key_delete("x"),
            b.registry_key_restore("x", &[], &RegKeyIndex::default()),
            b.processes_matching(&KillPredicate::default()),
            b.process_descendants(&[]),
            b.process_kill(&[]),
            b.service_stop("x"),
            b.service_disable("x"),
            b.service_delete("x"),
            b.service_clear_recovery("x"),
            b.survey_recursive_target("x", 1, 1),
            b.create_restore_point("x"),
        );
    }

    /// 지울 표시를 모르는 백엔드는 **'남지 않았다'** 다 — 리눅스와 시험 가짜가 이 기본값으로 지금처럼 돈다.
    /// `Unsupported` 를 내면 복원이 그것을 '확인하지 못함' 으로 읽고 모든 서비스 항목을 막는다.
    #[test]
    fn service_delete_pending_defaults_to_not_pending() {
        assert!(matches!(
            Bare.service_delete_pending(r"HKLM\SYSTEM\CurrentControlSet\Services\x"),
            Ok(false)
        ));
    }
}
