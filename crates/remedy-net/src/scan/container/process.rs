//! 주 프로세스 — 엔진이 알린 PID 의 실행 파일(스캐너 `process_unix.go` · `process_windows.go` · `runtimePaths`).
//!
//! 리눅스 엔진이 이 기계에서 돌 때만 본다: 그 PID 의 cgroup 에 컨테이너 ID 가 있고, 실행 파일 이름이 고른 제품의
//! 꼴일 때 그 경로를 후보에 넣는다. 그때도 하위 프로세스와 로드된 라이브러리는 보지 못했다고 적는다. Windows 엔진과
//! 이 프로그램이 Windows 에서 돌 때는 보지 못한다(Docker Desktop 의 리눅스 컨테이너는 이 기계의 `/proc` 에 없다).

use super::client::Client;
use super::endpoint::{linux, Host};
use super::paths;
use super::php::php_executable_name;
use crate::scan::binary::is_node_runtime;
use crate::scan::model::Product;
use remedy_sdk::i18n::Lang;

/// 주 프로세스의 실행 파일과 그 한계(또는 보지 못한 까닭) — 둘 다 그 제품의 *보지 못한 것* 이 된다.
pub(crate) fn runtime_paths(
    c: &Client<'_>,
    id: &str,
    pid: i64,
    products: &[Product],
) -> (Vec<String>, Option<String>) {
    let lang = c.lang;
    if c.windows() {
        let (ko, en) = (
            "Windows 컨테이너에서 실행 중인 프로세스와 수집한 파일의 연결은 확인하지 못했습니다.",
            "In a Windows container the link between the running processes and the collected files was not confirmed.",
        );
        return (Vec::new(), Some(lang.t(ko, en).to_string()));
    }
    local_runtime_paths(c.host, id, pid, products, lang)
}

fn local_runtime_paths(
    host: Option<&dyn Host>,
    id: &str,
    pid: i64,
    products: &[Product],
    lang: Lang,
) -> (Vec<String>, Option<String>) {
    let exe = host
        .filter(|_| cfg!(target_os = "linux") && pid > 0)
        .and_then(|h| linux::main_process_exe(h, id, pid))
        .filter(|exe| paths::valid_file_path(exe) && runtime_selected(&paths::base(exe), products));
    let Some(exe) = exe else {
        let why = lang.pick(
            format!("호스트의 /proc 에서 컨테이너 PID {pid} 의 실행 파일을 확인하지 못했습니다."),
            format!("The executable of container PID {pid} was not confirmed in the host's /proc."),
        );
        return (Vec::new(), Some(why));
    };
    let (ko, en) = (
        "컨테이너의 주 프로세스와 실행 파일만 대조했습니다. 하위 프로세스와 로드된 라이브러리는 확인하지 못했습니다.",
        "Only the container's main process and its executable were compared. Child processes and loaded libraries were not confirmed.",
    );
    (vec![exe], Some(lang.t(ko, en).to_string()))
}

/// 실행 파일 이름이 고른 제품의 것인가.
pub(crate) fn runtime_selected(name: &str, products: &[Product]) -> bool {
    if products.is_empty() {
        return php_executable_name(name);
    }
    products.iter().any(|p| match p {
        Product::Php => php_executable_name(name),
        Product::Node => is_node_runtime(name),
        Product::Brotli => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::container::endpoint::fake::FakeHost;

    #[test]
    fn the_main_process_counts_only_inside_the_container_cgroup() {
        let id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let mut host = FakeHost::default();
        host.files.insert(
            "77/cgroup".into(),
            format!("0::/system.slice/docker-{id}.scope\n").into_bytes(),
        );
        host.links
            .insert("77/exe".into(), Ok("/usr/local/bin/php".into()));
        let (found, note) = local_runtime_paths(Some(&host), id, 77, &[Product::Php], Lang::Ko);
        if cfg!(target_os = "linux") {
            assert_eq!(found, vec!["/usr/local/bin/php".to_string()]);
            assert!(note.unwrap().contains("주 프로세스"));
        } else {
            assert!(found.is_empty());
        }
        for (pid, products) in [
            (77, &[Product::Node][..]),
            (78, &[Product::Php][..]),
            (0, &[Product::Php][..]),
        ] {
            let (found, note) = local_runtime_paths(Some(&host), id, pid, products, Lang::Ko);
            assert!(found.is_empty());
            assert!(note.unwrap().contains(&format!("PID {pid}")));
        }
        assert!(local_runtime_paths(None, id, 77, &[Product::Php], Lang::Ko)
            .0
            .is_empty());
    }
}
