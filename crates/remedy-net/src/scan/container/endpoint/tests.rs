//! 엔진 주소와 엔진 확인의 시험 — 스캐너 `client_test.go` 의 주소 · 소켓 소유 시험과, 2026-11-10 의 접속 조건.
//!
//! `/proc` 은 지은 나무([`super::fake::FakeHost`])다. 유닉스에서는 실제 디렉터리를 `/proc` 의 뿌리로 바꿔 끼운
//! 시험도 돈다.

use super::fake::FakeHost;
use super::linux::verify;
use super::*;
use std::io::ErrorKind;

const SOCKET: &str = "/var/run/docker.sock";
const SYSTEMD: &str = "/usr/lib/systemd/systemd";

fn refused(host: &FakeHost) -> EndpointFailure {
    match verify(SOCKET, host) {
        Err(Failure::Endpoint(e)) => e,
        other => panic!("거절하지 않았다: {other:?}"),
    }
}

/// 원본 `TestRejectRemoteEndpointsBeforeConnection` — 이 OS 의 꼴만 받는다(엔진 확인 전에 거절).
#[test]
fn remote_endpoints_are_refused_before_any_connection() {
    for endpoint in [
        "",
        "tcp://localhost:2375",
        "https://localhost:2376",
        "ssh://user@host",
        r"\\remote\pipe\docker_engine",
    ] {
        assert!(parse(endpoint).is_err(), "{endpoint}");
        assert!(parse_unix(endpoint).is_err(), "{endpoint}");
        assert!(parse_pipe(endpoint).is_err(), "{endpoint}");
    }
}

#[test]
fn local_endpoint_shapes() {
    for good in [
        "unix:///var/run/docker.sock",
        "unix:///run/user/1000/podman/podman.sock",
    ] {
        assert_eq!(
            parse_unix(good),
            Ok(Endpoint::Unix(good["unix://".len()..].to_string()))
        );
    }
    for bad in [
        "unix://var/run/docker.sock",
        "unix:///var/run/../docker.sock",
        "unix:///var//run/docker.sock",
        "unix:///var/run/docker.sock/",
        "unix:///var/run/docker.sock?x=1",
        "unix:///var/run/docker.sock#x",
        "unix:///var/run/doc\nker.sock",
    ] {
        assert!(parse_unix(bad).is_err(), "{bad:?}");
    }
    assert_eq!(
        parse_pipe("npipe:////./pipe/docker_engine"),
        Ok(Endpoint::Pipe)
    );
    assert_eq!(parse_pipe(r"\\.\pipe\docker_engine"), Ok(Endpoint::Pipe));
    for bad in [
        "npipe:////./pipe/podman-machine-default",
        r"\\.\pipe\docker_engine_linux",
        "npipe://./pipe/docker_engine",
    ] {
        assert!(parse_pipe(bad).is_err(), "{bad}");
    }
}

/// 원본 `TestRefuseSocketActivation` 의 자리 — 2026-11-10 결정으로 뒤집혔다. 표준 유닛(`dockerd -H fd://` +
/// docker.socket, podman.socket + `podman system service`)은 systemd 와 엔진이 함께 소켓을 쥔다. 엔진이 쥐고 있으면
/// 이미 떠 있으므로 접속한다 — 인자의 `fd://` · `LISTEN_FDS` 는 더 보지 않는다.
#[test]
fn the_standard_socket_activated_units_are_accepted() {
    let mut docker = FakeHost::docker_socket();
    docker.process(1, SYSTEMD, &["/sbin/init"], &["socket:[123]"]);
    docker.process(
        812,
        "/usr/bin/dockerd",
        &["/usr/bin/dockerd", "-H", "fd://"],
        &["/dev/null", "socket:[123]"],
    );
    docker.process(
        900,
        "/usr/bin/containerd",
        &["containerd"],
        &["socket:[999]"],
    );
    assert_eq!(verify(SOCKET, &docker), Ok(EngineKind::Docker));

    let mut podman = FakeHost::docker_socket();
    podman.process(1, SYSTEMD, &["/sbin/init"], &["socket:[123]"]);
    podman.process(
        1500,
        SYSTEMD,
        &["/usr/lib/systemd/systemd", "--user"],
        &["socket:[123]"],
    );
    podman.process(
        1600,
        "/usr/bin/podman",
        &["/usr/bin/podman", "--log-level=info", "system", "service"],
        &["socket:[123]"],
    );
    assert_eq!(verify(SOCKET, &podman), Ok(EngineKind::Podman));

    // systemd 없이 엔진만 쥔 것도 그대로 된다.
    let mut plain = FakeHost::docker_socket();
    plain.process(
        812,
        "/usr/bin/dockerd",
        &["dockerd", "-H", "unix:///run/docker.sock"],
        &["socket:[123]"],
    );
    assert_eq!(verify(SOCKET, &plain), Ok(EngineKind::Docker));
}

/// 엔진이 쥐지 않은 소켓 — 접속하면 systemd 가 엔진을 띄운다. 접속하지 않는다.
#[test]
fn an_engine_that_is_not_running_is_never_contacted() {
    let mut activation_only = FakeHost::docker_socket();
    activation_only.process(1, SYSTEMD, &["/sbin/init"], &["socket:[123]"]);
    assert_eq!(refused(&activation_only), EndpointFailure::EngineNotRunning);
    let mut nobody = FakeHost::docker_socket();
    nobody.process(1, SYSTEMD, &["/sbin/init"], &["/dev/null"]);
    assert_eq!(refused(&nobody), EndpointFailure::EngineNotRunning);
    let message =
        Failure::from(EndpointFailure::EngineNotRunning).message(remedy_sdk::i18n::Lang::Ko);
    assert!(
        message.contains("시작될 수 있어 접속하지 않았습니다"),
        "{message}"
    );
}

/// 원본 `TestListenerOwnerMustBeExclusiveAndObservable` — 엔진과 systemd 밖의 프로세스가 쥐었거나, 확인하지 못한
/// 프로세스가 있으면 접속하지 않는다. 사라진 프로세스는 건너뛴다.
#[test]
fn the_listener_must_be_held_only_by_the_engine_and_systemd() {
    let base = || {
        let mut h = FakeHost::docker_socket();
        h.process(1, SYSTEMD, &["/sbin/init"], &["socket:[123]"]);
        h.process(2, "/usr/bin/dockerd", &["dockerd"], &["socket:[123]"]);
        h
    };
    let mut other_file = base();
    other_file.process(3, "/usr/bin/socat", &["socat"], &["/dev/null"]);
    assert_eq!(verify(SOCKET, &other_file), Ok(EngineKind::Docker));

    let mut shared = base();
    shared.process(3, "/usr/bin/socat", &["socat"], &["socket:[123]"]);
    assert_eq!(refused(&shared), EndpointFailure::SharedListener);

    let mut two = base();
    two.process(3, "/usr/local/bin/dockerd", &["dockerd"], &["socket:[123]"]);
    assert_eq!(refused(&two), EndpointFailure::SharedListener);

    let mut client = base();
    client.process(3, "/usr/bin/podman", &["podman", "ps"], &["socket:[123]"]);
    assert_eq!(refused(&client), EndpointFailure::SharedListener);

    let mut deleted = base();
    deleted
        .links
        .insert("2/exe".into(), Ok("/usr/bin/dockerd (deleted)".into()));
    assert_eq!(refused(&deleted), EndpointFailure::SharedListener);

    let mut denied = base();
    denied.process(3, "/usr/bin/socat", &["socat"], &[]);
    denied
        .dirs
        .insert("3/fd".into(), Err(ErrorKind::PermissionDenied));
    assert_eq!(refused(&denied), EndpointFailure::FdPermission);

    let mut gone = base();
    gone.process(3, "/usr/bin/socat", &["socat"], &[]);
    gone.dirs.insert("3/fd".into(), Err(ErrorKind::NotFound));
    gone.dirs
        .insert("1/fd".into(), Ok(vec!["3".into(), "9".into()]));
    gone.links.insert("1/fd/9".into(), Err(ErrorKind::NotFound));
    assert_eq!(verify(SOCKET, &gone), Ok(EngineKind::Docker));

    let mut unreadable_fd = base();
    unreadable_fd
        .links
        .insert("1/fd/3".into(), Err(ErrorKind::PermissionDenied));
    assert_eq!(refused(&unreadable_fd), EndpointFailure::FdUnreadable);

    let mut unreadable_exe = base();
    unreadable_exe
        .links
        .insert("1/exe".into(), Err(ErrorKind::PermissionDenied));
    assert_eq!(refused(&unreadable_exe), EndpointFailure::FdUnreadable);

    let mut exited = base();
    exited
        .links
        .insert("1/exe".into(), Err(ErrorKind::NotFound));
    assert_eq!(verify(SOCKET, &exited), Ok(EngineKind::Docker));
}

#[test]
fn hidden_or_unreadable_proc_state_refuses() {
    let running = || {
        let mut h = FakeHost::docker_socket();
        h.process(2, "/usr/bin/dockerd", &["dockerd"], &["socket:[123]"]);
        h
    };
    for (option, refuse) in [
        ("hidepid=2", true),
        ("hidepid=invisible", true),
        ("hidepid=0", false),
    ] {
        let mut h = running();
        let line = format!(
            "proc /proc proc rw,nosuid,{option},relatime 0 0\nproc /other proc rw,hidepid=2 0 0\n"
        );
        h.files.insert("mounts".into(), line.into_bytes());
        assert_eq!(verify(SOCKET, &h).is_err(), refuse, "{option}");
        if refuse {
            assert_eq!(refused(&h), EndpointFailure::HidePid);
        }
    }
    let mut no_table = running();
    no_table.files.remove("net/unix");
    assert_eq!(refused(&no_table), EndpointFailure::SocketTable);
    let mut no_listing = running();
    no_listing
        .dirs
        .insert(String::new(), Err(ErrorKind::PermissionDenied));
    assert_eq!(refused(&no_listing), EndpointFailure::ProcList);
    let mut no_mounts = running();
    no_mounts.files.remove("mounts");
    assert_eq!(refused(&no_mounts), EndpointFailure::ProcMounts);
    let mut not_socket = running();
    not_socket.sockets.clear();
    assert_eq!(refused(&not_socket), EndpointFailure::NotSocket);
    let mut missing = running();
    missing.resolved.clear();
    assert_eq!(refused(&missing), EndpointFailure::SocketMissing);
    let mut not_listening = running();
    not_listening.files.insert(
        "net/unix".into(),
        b"Num RefCount Protocol Flags Type St Inode Path\n0: 00000002 00000000 00000000 0001 03 123 /run/docker.sock\n".to_vec(),
    );
    assert_eq!(refused(&not_listening), EndpointFailure::NotListening);
}

#[test]
fn the_descriptor_cap_refuses_past_100000() {
    let mut h = FakeHost::docker_socket();
    h.process(2, "/usr/bin/dockerd", &["dockerd"], &["socket:[123]"]);
    let names: Vec<String> = (0..100_000).map(|i| i.to_string()).collect();
    for name in &names {
        h.links
            .insert(format!("3/fd/{name}"), Ok("/dev/null".into()));
    }
    h.links.insert("3/exe".into(), Ok("/usr/bin/many".into()));
    if let Some(Ok(list)) = h.dirs.get_mut("") {
        list.push("3".into());
    }
    h.dirs.insert("3/fd".into(), Ok(names));
    assert_eq!(refused(&h), EndpointFailure::FdLimit);
}

#[test]
fn windows_needs_the_docker_pipe_in_the_pipe_list() {
    let mut h = FakeHost {
        pipe_names: Some(vec![
            "dockerDesktopLinuxEngine".into(),
            "Docker_Engine".into(),
        ]),
        ..FakeHost::default()
    };
    assert_eq!(engine_kind(&Endpoint::Pipe, &h), Ok(EngineKind::Docker));
    h.pipe_names = Some(vec!["dockerDesktopLinuxEngine".into()]);
    assert_eq!(
        engine_kind(&Endpoint::Pipe, &h),
        Err(Failure::Endpoint(EndpointFailure::PipeMissing))
    );
    h.pipe_names = None;
    assert_eq!(
        engine_kind(&Endpoint::Pipe, &h),
        Err(Failure::Endpoint(EndpointFailure::PipeList))
    );
}

/// 실제 디렉터리를 `/proc` 의 뿌리로 — 링크는 진짜 심볼릭 링크, 소켓은 진짜 Unix 소켓 파일이다.
#[cfg(unix)]
#[test]
fn a_real_tree_with_a_real_socket_is_read_through_the_proc_root() {
    use std::os::unix::fs::symlink;
    let root = std::env::temp_dir().join(format!("remedy-net-proc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let proc = root.join("proc");
    std::fs::create_dir_all(proc.join("net")).unwrap();
    let socket = root.join("docker.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let socket = std::fs::canonicalize(&socket).unwrap();
    let socket = socket.to_str().unwrap();
    let table = format!("Num RefCount Protocol Flags Type St Inode Path\n0: 00000002 00000000 00010000 0001 01 777 {socket}\n");
    std::fs::write(proc.join("net/unix"), table).unwrap();
    std::fs::write(proc.join("mounts"), "proc /proc proc rw 0 0\n").unwrap();
    for (pid, exe, target) in [
        ("1", SYSTEMD, "socket:[777]"),
        ("2", "/usr/bin/dockerd", "socket:[777]"),
    ] {
        std::fs::create_dir_all(proc.join(pid).join("fd")).unwrap();
        symlink(exe, proc.join(pid).join("exe")).unwrap();
        symlink(target, proc.join(pid).join("fd").join("3")).unwrap();
        std::fs::write(proc.join(pid).join("cmdline"), b"x\0").unwrap();
    }
    let host = RealHost::with_proc(proc.clone());
    assert_eq!(verify(socket, &host), Ok(EngineKind::Docker));
    std::fs::remove_file(proc.join("2").join("fd").join("3")).unwrap();
    assert_eq!(
        verify(socket, &host),
        Err(Failure::Endpoint(EndpointFailure::EngineNotRunning))
    );
    let _ = std::fs::remove_dir_all(&root);
}
