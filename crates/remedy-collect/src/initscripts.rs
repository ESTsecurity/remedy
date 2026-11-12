//! SysV · OpenRC · Upstart 의 시작 스크립트 (2026-11-12 · 목표 결정 28).
//!
//! # 실행하지 않고 읽는다
//!
//! 스크립트를 셸로 돌리면 무엇을 띄우는지 정확히 알 수 있지만 그것은 **그 스크립트를 실행하는 것**이다 —
//! 점검 도구가 남의 기계에서 할 일이 아니다. 그래서 정적으로 풀 수 있는 것만 푼다. 규칙은 사내
//! runtime-scanner 의 시작 스크립트 해석과 같다.
//!
//! - **변수**: 대입(`NAME=값` · 앞머리 `export ` · `env `)을 위에서 아래로 모은다. 값의 `$NAME` · `${NAME}`
//!   은 **이미 아는 변수로만** 편다. 명령 치환(`$(…)` · 백틱) · `;|&<>` 가 든 값, 홑따옴표 안의 `$`, 모르는
//!   변수가 든 값은 풀지 않고 그 변수를 잊는다.
//! - **실행 파일 자리**: ① 그런 이름의 변수(`DAEMON` · `EXEC` · OpenRC 의 `command` · 끝이 `_BIN` 인 것 —
//!   PHP 가 내는 php-fpm 스크립트가 `php_fpm_BIN` 을 쓴다), ② `exec <경로>` 줄(Upstart), ③ `start-stop-daemon
//!   … --exec <경로>`(Debian) · `daemon [선택] <경로>`(RHEL) 줄. **절대 경로**로 풀린 것만 센다.
//! - **덮어쓰는 설정**은 부르는 쪽([`crate::Collector`])이 스크립트 뒤에 붙여 준다 — 같은 변수를 뒤가 덮는다.
//!
//! 줄 단위로 푼다. 스캐너는 `;|&<>` 가 든 줄을 통째로 버리지만 여기서는 **실행 파일 자리의 낱말만** 푼다 —
//! Upstart 의 `exec /usr/bin/node app.js >> /var/log/app.log 2>&1` 처럼 리디렉션이 붙은 줄이 흔하다.
//!
//! **풀지 못한 것은 보지 않는다** — 셸 함수 · 명령 치환으로 정한 경로 · 경로 없이 이름만 적은 실행 파일
//! (`PATH` 에서 찾는다). 스캐너는 그런 줄이 PHP · Node 를 언급하면 '확인하지 못했다' 로 적는데, 이
//! 수집기는 무엇이 위협인지 모르므로(룰이 안다) 풀린 경로만 낸다.

use std::collections::BTreeMap;

/// SysV · OpenRC 스크립트가 사는 자리.
pub(crate) const INIT_D: &str = "/etc/init.d";
/// Upstart 작업 정의가 사는 자리. `*.conf` 만 작업이다.
pub(crate) const UPSTART: &str = "/etc/init";

/// 실행 파일 자리로 읽는 변수 이름. 끝이 `_BIN` 인 이름도 센다([`is_program_var`]).
const PROGRAM_VARS: [&str; 3] = ["DAEMON", "EXEC", "command"];

/// 값 하나의 상한 — 스캐너와 같다. 그보다 긴 값은 풀지 않는다.
const MAX_VALUE: usize = 8192;

/// 변수를 몇 겹까지 따라가 펴는가 — 스캐너와 같다.
const MAX_DEPTH: usize = 8;

/// `daemon` 의 선택 중 **값을 다음 낱말로 받는** 것(RHEL `/etc/init.d/functions`).
const DAEMON_OPTS_WITH_VALUE: [&str; 3] = ["--check", "--user", "--pidfile"];

/// 스크립트(와 뒤에 붙인 덮어쓰는 설정)가 띄우는 실행 파일의 절대 경로. 처음 나온 차례 · 중복 없음.
pub fn programs(script: &str, overrides: &[String]) -> Vec<String> {
    let lines = logical_lines(script, overrides);
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    let mut out: Vec<String> = Vec::new();
    for line in &lines {
        let a = line.strip_prefix("export ").unwrap_or(line);
        let a = a.strip_prefix("env ").unwrap_or(a);
        let Some((key, value)) = a.split_once('=') else {
            continue;
        };
        if !is_name(key) {
            continue;
        }
        match static_value(value, &vars) {
            Some(v) => {
                // ① 실행 파일 자리의 변수 — 값의 첫 낱말이 실행 파일이다.
                if is_program_var(key) {
                    add(config_fields(&v).into_iter().next(), &mut out);
                }
                vars.insert(key.to_string(), v);
            }
            None => {
                vars.remove(key);
            }
        }
    }
    // ② · ③ 은 **모든 대입을 읽은 뒤의** 변수로 푼다(스캐너와 같다 — 덮어쓰는 설정이 뒤에 온다).
    for line in &lines {
        let words = raw_fields(line);
        let Some(first) = words.first() else {
            continue;
        };
        let program = match first.as_str() {
            "exec" => words.get(1),
            "start-stop-daemon" => exec_of(&words),
            "daemon" => daemon_program(&words),
            _ => None,
        };
        if let Some(w) = program {
            add(resolve_word(w, &vars), &mut out);
        }
    }
    out
}

/// 절대 경로면 (처음 나온 것만) 더한다.
fn add(p: Option<String>, out: &mut Vec<String>) {
    if let Some(p) = p.filter(|p| p.starts_with('/')) {
        if !out.contains(&p) {
            out.push(p);
        }
    }
}

/// `start-stop-daemon` 의 `--exec <경로>` · `-x <경로>` · `--exec=<경로>`.
fn exec_of(words: &[String]) -> Option<&String> {
    let mut it = words.iter().skip(1);
    while let Some(w) = it.next() {
        if w == "--exec" || w == "-x" {
            return it.next();
        }
        if w.starts_with("--exec=") {
            return Some(w);
        }
    }
    None
}

/// `daemon [--check <이름>] [--user <사용자>] [--pidfile <파일>] [--force] [+/-<nice>] <실행 파일> [인자]` 의
/// 실행 파일 낱말. `--x=y` 꼴의 선택은 그 낱말 하나다.
fn daemon_program(words: &[String]) -> Option<&String> {
    let mut it = words.iter().skip(1);
    while let Some(w) = it.next() {
        if DAEMON_OPTS_WITH_VALUE.contains(&w.as_str()) {
            it.next();
            continue;
        }
        let nice = (w.starts_with('+') || w.starts_with('-'))
            && w.len() > 1
            && w[1..].chars().all(|c| c.is_ascii_digit());
        if w.starts_with("--") || nice {
            continue;
        }
        return Some(w);
    }
    None
}

/// 낱말 하나(따옴표 그대로)를 펴서 첫 낱말을 돌려준다. `--exec=` 앞머리는 뗀다.
fn resolve_word(word: &str, vars: &BTreeMap<String, String>) -> Option<String> {
    let w = word.strip_prefix("--exec=").unwrap_or(word);
    let v = static_value(w, vars)?;
    config_fields(&v).into_iter().next()
}

fn is_program_var(key: &str) -> bool {
    PROGRAM_VARS.contains(&key) || key.ends_with("_BIN")
}

fn is_name(s: &str) -> bool {
    let mut c = s.chars();
    c.next()
        .is_some_and(|f| f.is_ascii_alphabetic() || f == '_')
        && c.all(|x| x.is_ascii_alphanumeric() || x == '_')
}

/// 스크립트와 덮어쓰는 설정을 이어 **논리 줄**로 — `\` 로 이은 줄은 한 줄, 빈 줄 · `#` 줄은 뺀다.
fn logical_lines(script: &str, overrides: &[String]) -> Vec<String> {
    std::iter::once(script)
        .chain(overrides.iter().map(String::as_str))
        .flat_map(|t| {
            t.replace("\r\n", "\n")
                .replace("\\\n", " ")
                .split('\n')
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// 값 하나를 **정적으로** 편다. 못 펴면 `None` — 그 값은 모르는 것이다.
fn static_value(value: &str, vars: &BTreeMap<String, String>) -> Option<String> {
    const SHELL: [char; 7] = ['`', '\0', ';', '|', '&', '<', '>'];
    let v = value.trim();
    if v.len() > MAX_VALUE || v.contains(SHELL) || v.contains("$(") {
        return None;
    }
    // 홑따옴표는 펴지 않는다 — 그 안의 `$` 를 아는 변수로 읽어 절대 경로로 만들면 안 된다.
    let mut single = false;
    for c in v.chars() {
        if c == '\'' {
            single = !single;
        }
        if single && c == '$' {
            return None;
        }
    }
    let mut s = v;
    if let Some(q) = s.chars().next().filter(|c| *c == '"' || *c == '\'') {
        if s.len() > 1 {
            if !s.ends_with(q) {
                return None;
            }
            s = &s[1..s.len() - 1];
        }
    }
    let mut s = s.to_string();
    for _ in 0..MAX_DEPTH {
        if !s.contains('$') {
            break;
        }
        s = substitute(&s, vars)?;
        if s.len() > MAX_VALUE {
            return None;
        }
    }
    (!s.contains('$') && !s.contains(SHELL)).then_some(s)
}

/// `${NAME}` · `$NAME` 을 아는 값으로 한 번 바꾼다. 모르는 이름이 있으면 `None`. 다른 꼴의 `$`
/// (`${X:-y}` · `$1`)는 그대로 둔다 — 부르는 쪽이 남은 `$` 로 '못 폈다' 를 안다.
fn substitute(s: &str, vars: &BTreeMap<String, String>) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('$') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let (name, used) = if let Some(b) = after.strip_prefix('{') {
            match b.find('}') {
                Some(end) if is_name(&b[..end]) => (&b[..end], end + 2),
                _ => ("", 0),
            }
        } else {
            let end = after
                .char_indices()
                .find(|(k, c)| {
                    !(c.is_ascii_alphanumeric() || *c == '_') || (*k == 0 && c.is_ascii_digit())
                })
                .map_or(after.len(), |(k, _)| k);
            (&after[..end], end)
        };
        if name.is_empty() {
            out.push('$');
            rest = after;
            continue;
        }
        out.push_str(vars.get(name)?);
        rest = &after[used..];
    }
    out.push_str(rest);
    Some(out)
}

/// 따옴표를 떼고 낱말로 가른다. 변수 · 치환 · 파이프는 해석하지 않는다(스캐너의 `configFields`).
fn config_fields(line: &str) -> Vec<String> {
    split_words(line, false)
}

/// 따옴표를 **남긴 채** 낱말로 가른다 — 낱말 하나를 [`static_value`] 로 펼 때 홑따옴표를 알아보려고.
fn raw_fields(line: &str) -> Vec<String> {
    split_words(line, true)
}

fn split_words(line: &str, keep_quotes: bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut tok = String::new();
    let mut quote: Option<char> = None;
    for c in line.trim().chars() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
                if keep_quotes {
                    tok.push(c);
                }
            } else {
                tok.push(c);
            }
            continue;
        }
        match c {
            '"' | '\'' => {
                quote = Some(c);
                if keep_quotes {
                    tok.push(c);
                }
            }
            ' ' | '\t' => {
                if !tok.is_empty() {
                    out.push(std::mem::take(&mut tok));
                }
            }
            '#' if tok.is_empty() => return out,
            _ => tok.push(c),
        }
    }
    if !tok.is_empty() {
        out.push(tok);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Debian 의 `php8.2-fpm` 스크립트 꼴 — 실행 파일은 `DAEMON` 이고 `start-stop-daemon` 줄은 리디렉션이 붙는다.
    #[test]
    fn a_debian_daemon_variable_is_the_program() {
        let s = "#!/bin/sh\nNAME=php-fpm8.2\nDAEMON=/usr/sbin/$NAME\nDAEMON_ARGS=\"--daemonize\"\n\
                 CONF_PIDFILE=$(sed -n 's/^pid[ =]*//p' /etc/x)\n\
                 start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON -- \\\n\
                 \t$DAEMON_ARGS 2>/dev/null || return 2\n";
        assert_eq!(programs(s, &[]), vec!["/usr/sbin/php-fpm8.2"]);
    }

    /// PHP 가 내는 php-fpm 스크립트 — 실행 파일이 `php_fpm_BIN` 이고 시작 줄은 그 변수로 바로 부른다.
    #[test]
    fn the_php_shipped_script_names_the_program_in_a_bin_variable() {
        let s =
            "prefix=/opt/php83\nexec_prefix=${prefix}\nphp_fpm_BIN=${exec_prefix}/sbin/php-fpm\n\
                 php_opts=\"--fpm-config $php_fpm_CONF\"\n\t\t$php_fpm_BIN --daemonize $php_opts\n";
        assert_eq!(programs(s, &[]), vec!["/opt/php83/sbin/php-fpm"]);
    }

    /// Upstart 의 `exec` · OpenRC 의 `command` · RHEL 의 `daemon` — 리디렉션 · 선택이 붙어도 실행 파일 낱말만 푼다.
    #[test]
    fn exec_command_and_daemon_lines_give_their_program() {
        let up = "description \"app\"\nstart on runlevel [2345]\n\
                  exec /srv/node/bin/node /srv/app.js >> /var/log/app.log 2>&1\n";
        assert_eq!(programs(up, &[]), vec!["/srv/node/bin/node"]);

        let rc = "#!/sbin/openrc-run\ncommand=\"/opt/node/bin/node\"\ncommand_args=\"/srv/a.js\"\n";
        assert_eq!(programs(rc, &[]), vec!["/opt/node/bin/node"]);

        let rh = "phpbin=/usr/local/php/bin/php-cgi\n\
                  daemon --user=apache --pidfile /run/x.pid +5 \"$phpbin\" -b 127.0.0.1:9000 &\n";
        assert_eq!(programs(rh, &[]), vec!["/usr/local/php/bin/php-cgi"]);
    }

    /// 덮어쓰는 설정이 뒤에 온다 — 둘 다 실행 파일 자리이므로 둘 다 낸다(스캐너와 같다).
    #[test]
    fn an_override_adds_its_program_after_the_script() {
        let s = "DAEMON=/usr/sbin/php-fpm8.2\n[ -r /etc/default/x ] && . /etc/default/x\n\
                 start-stop-daemon --start --exec \"$DAEMON\"\n";
        let over = vec!["DAEMON=/opt/php/sbin/php-fpm\n".to_string()];
        assert_eq!(
            programs(s, &over),
            vec!["/usr/sbin/php-fpm8.2", "/opt/php/sbin/php-fpm"]
        );
    }

    /// 풀지 못하는 것은 내지 않는다 — 명령 치환 · 홑따옴표 안의 `$` · 모르는 변수 · 이름만 적은 실행 파일.
    #[test]
    fn what_cannot_be_resolved_statically_is_not_reported() {
        for s in [
            "DAEMON=$(command -v php-fpm)\nstart-stop-daemon --start --exec $DAEMON\n",
            "DAEMON='/opt/$X/php'\n",
            "exec $NODE_HOME/bin/node app.js\n",
            "daemon --pidfile ${pidfile} php-fpm --daemonize\n",
            "DAEMON=`which node`\n",
            "iscsiadm -m node --loginall=automatic\n",
        ] {
            assert!(programs(s, &[]).is_empty(), "{s}");
        }
    }

    /// 펴진 값에 `$` 가 남으면(`${X:-기본}`) 못 편 것이다 — 기본값을 지어내 경로로 쓰지 않는다.
    #[test]
    fn a_default_value_expansion_is_not_guessed() {
        assert_eq!(
            static_value("${PIDFILE:-/run/x.pid}", &BTreeMap::new()),
            None
        );
        let vars = BTreeMap::from([("A".to_string(), "/opt".to_string())]);
        assert_eq!(static_value("\"$A/b\"", &vars).as_deref(), Some("/opt/b"));
        assert_eq!(static_value("'$A/b'", &vars), None);
    }
}
