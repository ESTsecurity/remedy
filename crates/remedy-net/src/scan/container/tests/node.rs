//! Node.js — 스캐너 `node_test.go` 와 `linux_legacy_test.go` 의 연결 시험.

use super::support::*;
use crate::scan::binary::fixtures::{minimal_elf32, minimal_elf64};
use crate::scan::binary::inspect_node_binary;
use crate::scan::container::client::BinaryFile;
use crate::scan::container::files::Subject;
use crate::scan::container::inspect::Inspect;
use crate::scan::container::node::{
    node_container_dependencies, scan_node_container, Owners, Walk,
};
use crate::scan::container::packages::package_product;
use crate::scan::model::{Product, Status, Target, TargetKind};
use crate::scan::rules::{Component, DependencyMode};
use remedy_sdk::i18n::Lang;
use std::collections::HashSet;

fn target(products: &[Product]) -> Target {
    Target::new(
        format!("container:{TEST_ID}"),
        TargetKind::Container,
        TEST_ID,
        products,
    )
}

fn binary(data: &[u8], sha: &str) -> BinaryFile {
    BinaryFile {
        prefix: Vec::new(),
        sha256: sha.to_string(),
        md5: String::new(),
        size: data.len() as u64,
        info: inspect_node_binary(data, data.len() as u64),
    }
}

/// 원본 `TestContainerNodeEnvironmentAloneDoesNotEstablishRuntime`.
#[test]
fn the_node_environment_alone_does_not_establish_a_runtime() {
    let (b, _, _) = budget();
    let engine = Engine::unreachable();
    let mut c = client(&b, &engine, "linux");
    let mut t = target(&[Product::Node]);
    let inspected = Inspect {
        env: vec!["NODE_VERSION=22.99.0".into()],
        ..Inspect::default()
    };
    let rules = blank_rules();
    let s = Subject {
        id: TEST_ID,
        inspected: &inspected,
        rules: &rules,
        packages: &[],
        package_data: &[],
        distro: "",
        rpm: None,
    };
    scan_node_container(&mut c, &mut t, &s);
    t.finalize(Lang::Ko);
    assert_eq!(t.products[&Product::Node].status, Status::ReviewRequired);
    assert!(runtime_findings(&t).is_empty());
    assert_eq!(t.metadata["node_version_hint"], "22.99.0");
}

/// 원본 `TestKnownNodeHashRemovesOnlyMissingStaticDependencyGap` — 동적 의존을 앞부분 8 MiB 안에서 읽지 못한 공식
/// 빌드도, 해시가 Brotli 를 담아 지은 공식 빌드의 것이면 연결의 한계만 지운다. 로더를 바꾸는 환경 변수가 있으면 그
/// 한계가 남는다. 다른 한계(전체 설치 · 주 프로세스)는 둘 다 남는다.
#[test]
fn a_known_node_hash_removes_only_the_missing_static_dependency_gap() {
    let mut body = vec![0u8; (8 << 20) + 128];
    body[..128].copy_from_slice(&minimal_elf64());
    body[32..40].copy_from_slice(&(8u64 << 20).to_le_bytes());
    let header: Vec<u8> = body[64..120].to_vec();
    body[(8 << 20)..(8 << 20) + 56].copy_from_slice(&header);
    let len = body.len() as u64;
    body[(8 << 20) + 32..(8 << 20) + 40].copy_from_slice(&len.to_le_bytes());
    let rules = hash_rules(Vec::new(), vec![hash_row(&body, "22.99.0", true)]);
    for loader in [false, true] {
        let (b, _, _) = budget();
        let engine = files_engine(vec![("/usr/local/bin/node", body.clone())]);
        let mut c = client(&b, &engine, "linux");
        let mut t = target(&[Product::Node]);
        let mut inspected = Inspect {
            path: "/usr/local/bin/node".into(),
            ..Inspect::default()
        };
        if loader {
            inspected.env = vec!["LD_PRELOAD=/custom.so".into()];
        }
        let s = Subject {
            id: TEST_ID,
            inspected: &inspected,
            rules: &rules,
            packages: &[],
            package_data: &[],
            distro: "",
            rpm: None,
        };
        scan_node_container(&mut c, &mut t, &s);
        t.finalize(Lang::Ko);
        let gaps = &t.products[&Product::Node].gaps;
        let connection = gaps
            .iter()
            .any(|g| g.contains("Node.js 와 Brotli 의 연결 관계"));
        assert_eq!(connection, loader, "{gaps:?}");
        assert_eq!(t.status, Status::ReviewRequired);
        assert!(gaps.len() >= 2, "{gaps:?}");
        assert_eq!(runtime_findings(&t).len(), 1);
    }
}

/// 원본 `TestContainerSharedDependencyFiltersELFABI` — 같은 이름의 Brotli 가운데 실행 파일과 ABI 가 같은 것 하나만
/// 잇는다. 같은 ABI 가 둘이면 정하지 않는다.
#[test]
fn a_shared_dependency_is_filtered_by_elf_abi() {
    let mut node = binary(&minimal_elf32(), "");
    node.info.needed = vec!["libbrotlidec.so.1".into()];
    let owner = |arch: &str, version: &str| {
        let mut c = Component::new(Product::Brotli);
        c.package = "libbrotli1".into();
        c.architecture = arch.into();
        c.version = version.into();
        c.trusted = true;
        c
    };
    let mut owners = Owners::new();
    owners.insert(
        "/usr/lib32/libbrotlidec.so.1".into(),
        owner("i386", "1.2.0-1"),
    );
    owners.insert(
        "/usr/lib64/libbrotlidec.so.1".into(),
        owner("amd64", "1.1.0-1"),
    );
    let (elf32, elf64) = (minimal_elf32(), minimal_elf64());
    let mut read = |name: &str| {
        Ok(if name.contains("lib32") {
            binary(&elf32, &"a".repeat(64))
        } else {
            binary(&elf64, &"b".repeat(64))
        })
    };
    let walk = Walk {
        owners: &owners,
        checks: None,
        lang: Lang::Ko,
    };
    let (mode, deps, complete) = node_container_dependencies(
        "/usr/bin/node",
        &node,
        &walk,
        &mut read,
        &mut HashSet::new(),
        0,
    );
    assert_eq!(mode, DependencyMode::Shared);
    assert!(complete);
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].architecture, "i386");
    assert_eq!(deps[0].path, "/usr/lib32/libbrotlidec.so.1");
    assert_eq!(deps[0].product, Product::Brotli);
    assert_eq!(deps[0].sha256, "a".repeat(64));

    owners.insert(
        "/usr/lib/libbrotlidec.so.1".into(),
        owner("i386", "1.2.0-1"),
    );
    let mut same_abi = |_: &str| Ok(binary(&elf32, ""));
    let walk = Walk {
        owners: &owners,
        checks: None,
        lang: Lang::Ko,
    };
    let (_, _, complete) = node_container_dependencies(
        "/usr/bin/node",
        &node,
        &walk,
        &mut same_abi,
        &mut HashSet::new(),
        0,
    );
    assert!(!complete, "같은 ABI 의 후보 둘을 하나로 정했다");
    for name in ["php", "php-cli", "php-fpm"] {
        assert_eq!(
            package_product(name, &[Product::Php]),
            Some(Product::Php),
            "{name}"
        );
    }
}

/// 의존을 따라가다 같은 파일로 돌아오거나 깊이 8을 넘으면 끝까지 보았다고 하지 않는다. `libnode` 를 거친 공유
/// Brotli 는 실행 파일의 연결로 올라온다.
#[test]
fn dependency_walks_through_libnode_and_stops_on_cycles() {
    let elf = |needed: &[&str]| {
        let data = crate::scan::binary::fixtures::elf(needed);
        binary(&data, "c")
    };
    let mut owners = Owners::new();
    let mut lib = Component::new(Product::Node);
    lib.package = "libnode115".into();
    owners.insert("/usr/lib/libnode.so.115".into(), lib);
    let mut brotli = Component::new(Product::Brotli);
    brotli.package = "libbrotli1".into();
    brotli.source = "dpkg".into();
    owners.insert("/usr/lib/libbrotlidec.so.1".into(), brotli);
    let mut read = |name: &str| {
        Ok(if name.ends_with("libnode.so.115") {
            elf(&["libbrotlidec.so.1"])
        } else {
            elf(&[])
        })
    };
    let walk = Walk {
        owners: &owners,
        checks: None,
        lang: Lang::Ko,
    };
    let root = elf(&["libnode.so.115"]);
    let (mode, deps, complete) = node_container_dependencies(
        "/usr/bin/node",
        &root,
        &walk,
        &mut read,
        &mut HashSet::new(),
        0,
    );
    assert_eq!(
        (mode, deps.len(), complete),
        (DependencyMode::Shared, 1, true)
    );
    assert!(
        deps[0].source.contains(
            "/usr/lib/libnode.so.115 의 ELF DT_NEEDED → /usr/lib/libbrotlidec.so.1; dpkg"
        ),
        "{}",
        deps[0].source
    );

    let mut cycle = |_: &str| Ok(elf(&["libnode.so.115"]));
    let (mode, _, complete) = node_container_dependencies(
        "/usr/bin/node",
        &root,
        &walk,
        &mut cycle,
        &mut HashSet::new(),
        0,
    );
    assert_eq!((mode, complete), (DependencyMode::Unknown, false));
    let (mode, _, complete) = node_container_dependencies(
        "/usr/bin/node",
        &root,
        &walk,
        &mut read,
        &mut HashSet::new(),
        9,
    );
    assert_eq!((mode, complete), (DependencyMode::Unknown, false));
}
