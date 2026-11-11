//! 엔진에 닿지 못하거나 받은 것을 믿지 못한 까닭 — 결과 파일의 *보지 못한 것* 에 들어가는 문장.
//!
//! 스캐너는 Go 의 오류 문장(라이브러리 · OS 의 글 포함)을 그대로 이어 붙였다. 여기서는 갈래마다 정한 문장만 내고,
//! 덧붙이는 것은 꼴을 확인한 짧은 값(HTTP 상태 · API 판 · 경로 갈래)뿐이다 — 엔진이나 OS 가 보낸 글은 옮기지 않는다.

use crate::scan::budget::Halt;
use remedy_sdk::i18n::Lang;
use std::fmt;
use std::io;

/// 까닭 하나. 크기를 작게 둔다 — 함수마다 `Result` 로 오간다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Failure {
    /// 한도 · 취소 · 실행 시한 — 예산이 낸 까닭 그대로.
    Halt(Halt),
    Endpoint(EndpointFailure),
    Wire(Wire),
    Policy(Policy),
    Version(Version),
    File(FileFailure),
}

/// 엔진 주소와 엔진 확인.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndpointFailure {
    UnixOnly,
    UnixPath,
    PipeOnly,
    NoProc,
    SocketMissing,
    NotSocket,
    SocketTable,
    NotListening,
    ProcList,
    ProcMounts,
    HidePid,
    FdPermission,
    FdLimit,
    FdUnreadable,
    SharedListener,
    EngineNotRunning,
    PipeList,
    PipeMissing,
    EngineChanged,
}

/// 연결 · HTTP 틀.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wire {
    Timeout,
    Refused,
    Missing,
    Denied,
    Closed,
    Malformed,
    HeaderTooLarge,
    Framing,
    Other,
}

/// 허용 목록 · 경로 경계 · 응답 상태.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Policy {
    NotAllowed,
    OutsideScope,
    /// Windows 엔진의 파일 조회가 5xx 를 냈다 — 그 컨테이너의 파일 조회를 더 하지 않는다.
    WindowsArchive(u16),
    NotNegotiated,
    Status {
        status: u16,
        method: &'static str,
        route: String,
    },
    Compressed,
    Json,
}

/// API 판 맞추기.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Version {
    Unsupported,
    Range,
    Kind,
    /// 엔진의 범위(꼴을 확인한 `1.N` 둘)와 이쪽의 최고 판.
    Incompatible {
        min: String,
        max: String,
        supported: u32,
    },
}

/// 파일 하나 읽기.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileFailure {
    StatTooLarge,
    StatBase64,
    StatMissing,
    StatJson,
    NotRegular,
    FileTooLarge,
    BadRequest,
    PurposeLimit,
    StatChanged,
    ArchiveTooLarge,
    ArchiveLimit,
    ArchiveFormat,
    ArchiveMember,
    ArchiveSize,
    ArchiveTrailing,
    ArchiveAfterEnd,
    NotPe,
    Read,
}

impl Failure {
    /// 엔진이 그 파일이 없다고 답했다(HTTP 404).
    pub(crate) fn is_missing(&self) -> bool {
        matches!(self, Failure::Policy(Policy::Status { status: 404, .. }))
    }

    /// 점검 제한에 닿았다 — 예산의 상한 또는 파일 하나의 아카이브 상한(스캐너 `control.ErrLimit`).
    #[cfg(test)]
    pub(crate) fn is_limit(&self) -> bool {
        matches!(
            self,
            Failure::Halt(Halt::Limit(_)) | Failure::File(FileFailure::ArchiveLimit)
        )
    }

    /// 읽기 오류에 실려 온 까닭 — 예산의 것이면 그 까닭, 이 모듈의 것이면 그것, 그 밖의 입출력 오류는 읽기 실패다.
    pub(crate) fn from_io(e: &io::Error) -> Failure {
        if let Some(halt) = Halt::from_io(e) {
            return Failure::Halt(halt);
        }
        match e
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<Carried>())
        {
            Some(Carried(f)) => f.clone(),
            None => Failure::File(FileFailure::Read),
        }
    }

    /// `io::Error` 에 싣는다 — 읽기 고리를 지나도 까닭을 잃지 않는다.
    pub(crate) fn into_io(self) -> io::Error {
        io::Error::other(Carried(self))
    }

    pub(crate) fn message(&self, lang: Lang) -> String {
        match self {
            Failure::Halt(h) => h.message(lang),
            Failure::Endpoint(e) => e.message(lang).to_string(),
            Failure::Wire(w) => w.message(lang).to_string(),
            Failure::Policy(p) => p.message(lang),
            Failure::Version(v) => v.message(lang),
            Failure::File(f) => f.message(lang).to_string(),
        }
    }
}

impl From<Halt> for Failure {
    fn from(h: Halt) -> Self {
        Failure::Halt(h)
    }
}

impl From<EndpointFailure> for Failure {
    fn from(e: EndpointFailure) -> Self {
        Failure::Endpoint(e)
    }
}

impl From<Wire> for Failure {
    fn from(w: Wire) -> Self {
        Failure::Wire(w)
    }
}

impl From<FileFailure> for Failure {
    fn from(f: FileFailure) -> Self {
        Failure::File(f)
    }
}

impl From<Policy> for Failure {
    fn from(p: Policy) -> Self {
        Failure::Policy(p)
    }
}

/// `io::Error` 에 싣는 꼴.
#[derive(Debug)]
struct Carried(Failure);

impl fmt::Display for Carried {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.message(Lang::En))
    }
}

impl std::error::Error for Carried {}

impl EndpointFailure {
    fn message(self, lang: Lang) -> &'static str {
        use EndpointFailure::*;
        match self {
            UnixOnly => lang.t(
                "직접 지정한 로컬 Unix 소켓(unix:///…)만 쓸 수 있습니다. TCP 나 원격 접속은 지원하지 않습니다.",
                "Only a local Unix socket given directly (unix:///…) can be used. TCP and remote connections are not supported.",
            ),
            UnixPath => lang.t(
                "Unix 소켓의 절대 경로가 잘못되었습니다.",
                "The absolute path of the Unix socket is invalid.",
            ),
            PipeOnly => lang.t(
                "Windows 에서는 로컬 Docker 의 기본 네임드 파이프(npipe:////./pipe/docker_engine)만 쓸 수 있습니다. 실행 중인 Podman 서비스는 확인할 수 없습니다.",
                "On Windows only the default named pipe of the local Docker (npipe:////./pipe/docker_engine) can be used. A running Podman service cannot be confirmed.",
            ),
            NoProc => lang.t(
                "이 운영체제에서는 실행 중인 엔진을 /proc 로 확인할 수 없어 소켓에 접속하지 않았습니다.",
                "On this operating system the running engine cannot be confirmed through /proc, so the socket was not contacted.",
            ),
            SocketMissing => lang.t(
                "엔진의 로컬 소켓을 찾지 못해 접속하지 않았습니다.",
                "The engine's local socket was not found, so it was not contacted.",
            ),
            NotSocket => lang.t(
                "지정한 경로가 로컬 Unix 소켓 파일이 아닙니다.",
                "The given path is not a local Unix socket file.",
            ),
            SocketTable => lang.t(
                "사용 중인 소켓 정보(/proc/net/unix)를 읽지 못해 접속하지 않았습니다.",
                "The socket table (/proc/net/unix) could not be read, so the engine was not contacted.",
            ),
            NotListening => lang.t(
                "연결을 받고 있는 소켓을 확인하지 못해 접속하지 않았습니다.",
                "No socket listening for connections was confirmed, so the engine was not contacted.",
            ),
            ProcList => lang.t(
                "실행 중인 프로세스 목록(/proc)을 읽지 못해 접속하지 않았습니다.",
                "The process list (/proc) could not be read, so the engine was not contacted.",
            ),
            ProcMounts => lang.t(
                "/proc 설정을 읽지 못해 소켓을 가진 프로세스를 모두 확인할 수 없어 접속하지 않았습니다.",
                "The /proc settings could not be read, so not every process holding the socket could be confirmed and the engine was not contacted.",
            ),
            HidePid => lang.t(
                "/proc 의 hidepid 설정 때문에 수신 소켓을 가진 프로세스를 모두 확인할 수 없어 접속하지 않았습니다.",
                "The hidepid setting of /proc hides processes, so not every process holding the listening socket could be confirmed and the engine was not contacted.",
            ),
            FdPermission => lang.t(
                "소켓 소유 프로세스 확인에 필요한 /proc 파일 디스크립터 접근 권한이 없어 접속하지 않았습니다. root 로 실행하십시오.",
                "There is no permission to read the /proc file descriptors needed to confirm which processes own the socket, so the engine was not contacted. Run this as root.",
            ),
            FdLimit => lang.t(
                "소켓 소유 프로세스 확인 한도(파일 디스크립터 100,000개)를 넘어 접속하지 않았습니다.",
                "Confirming the socket owners went past the limit of 100,000 file descriptors, so the engine was not contacted.",
            ),
            FdUnreadable => lang.t(
                "소켓 소유 프로세스를 모두 확인하지 못해 접속하지 않았습니다.",
                "Not every socket owner could be confirmed, so the engine was not contacted.",
            ),
            SharedListener => lang.t(
                "엔진과 systemd 밖의 프로세스도 수신 소켓을 가지고 있어 접속하지 않았습니다. 접속하면 다른 서비스가 시작될 수 있습니다.",
                "A process other than the engine and systemd also holds the listening socket, so it was not contacted. Connecting could start another service.",
            ),
            EngineNotRunning => lang.t(
                "컨테이너 엔진이 실행 중이 아닙니다. 접속하면 엔진이 시작될 수 있어 접속하지 않았습니다.",
                "The container engine is not running. It was not contacted, because connecting could start it.",
            ),
            PipeList => lang.t(
                "네임드 파이프 목록을 읽지 못해 Docker 엔진이 실행 중인지 확인하지 못했습니다. 접속하지 않았습니다.",
                "The named pipe list could not be read, so whether Docker is running was not confirmed. The engine was not contacted.",
            ),
            PipeMissing => lang.t(
                "Docker 엔진의 네임드 파이프가 없습니다 — 엔진이 실행 중이 아니어서 접속하지 않았습니다. 엔진을 시작하지 않습니다.",
                "The Docker engine's named pipe does not exist — the engine is not running, so it was not contacted. The engine is not started.",
            ),
            EngineChanged => lang.t(
                "점검 중에 로컬 엔진의 종류가 바뀌어 접속하지 않았습니다.",
                "The kind of the local engine changed during the check, so it was not contacted.",
            ),
        }
    }
}

impl Wire {
    fn message(self, lang: Lang) -> &'static str {
        match self {
            Wire::Timeout => lang.t(
                "엔진 요청의 제한 시간을 넘었습니다.",
                "The engine request timed out.",
            ),
            Wire::Refused => lang.t(
                "엔진이 연결을 받지 않았습니다.",
                "The engine refused the connection.",
            ),
            Wire::Missing => lang.t(
                "엔진의 접속 자리가 없습니다.",
                "The engine's endpoint does not exist.",
            ),
            Wire::Denied => lang.t(
                "엔진에 접속할 권한이 없습니다.",
                "There is no permission to connect to the engine.",
            ),
            Wire::Closed => lang.t(
                "엔진이 응답을 끝까지 보내기 전에 연결을 끊었습니다.",
                "The engine closed the connection before the response was complete.",
            ),
            Wire::Malformed => lang.t(
                "엔진의 HTTP 응답 형식이 올바르지 않습니다.",
                "The engine's HTTP response is malformed.",
            ),
            Wire::HeaderTooLarge => lang.t(
                "엔진의 HTTP 응답 헤더가 크기 제한(32 KiB)을 넘었습니다.",
                "The engine's HTTP response headers exceeded the 32 KiB limit.",
            ),
            Wire::Framing => lang.t(
                "엔진 응답 본문의 길이 · 전송 방식이 올바르지 않습니다.",
                "The length or transfer coding of the engine's response body is invalid.",
            ),
            Wire::Other => lang.t(
                "엔진과 통신하지 못했습니다.",
                "Could not communicate with the engine.",
            ),
        }
    }
}

impl Policy {
    fn message(&self, lang: Lang) -> String {
        match self {
            Policy::NotAllowed => lang
                .t(
                    "허용 목록에 없는 컨테이너 API 요청입니다.",
                    "The container API request is not on the allow list.",
                )
                .to_string(),
            Policy::OutsideScope => lang
                .t(
                    "엔진 OS 의 파일 경로가 아니거나 컨테이너 마운트 경계를 벗어났습니다.",
                    "The path is not a file path of the engine's OS, or it crosses a container mount boundary.",
                )
                .to_string(),
            Policy::WindowsArchive(status) => lang.pick(
                format!("Windows 컨테이너 파일 조회 API 가 HTTP {status} 오류를 돌려줘 이 컨테이너의 파일 수집을 멈췄습니다. 격리 방식과 엔진의 파일 조회 지원 여부를 확인하십시오."),
                format!("The Windows container file API returned HTTP {status}, so file collection from this container stopped. Check the isolation mode and whether the engine supports file reads."),
            ),
            Policy::NotNegotiated => lang
                .t(
                    "엔진 API 판의 호환성을 확인하기 전에는 조회할 수 없습니다.",
                    "Nothing can be queried before the engine API version is confirmed compatible.",
                )
                .to_string(),
            Policy::Status {
                status,
                method,
                route,
            } => {
                let route = crate::text::plain(route, 200);
                lang.pick(
                    format!("컨테이너 API {method} {route}: HTTP {status}"),
                    format!("container API {method} {route}: HTTP {status}"),
                )
            }
            Policy::Compressed => lang
                .t(
                    "압축된 API 응답은 받지 않습니다.",
                    "Compressed API responses are not accepted.",
                )
                .to_string(),
            Policy::Json => lang
                .t(
                    "컨테이너 API 의 JSON 응답 형식이 잘못되었습니다.",
                    "The container API's JSON response is malformed.",
                )
                .to_string(),
        }
    }
}

impl Version {
    fn message(&self, lang: Lang) -> String {
        match self {
            Version::Unsupported => lang
                .t(
                    "OS 와 버전 정보가 있는 Linux Docker · Podman 또는 Windows Docker 엔진만 지원합니다.",
                    "Only a Linux Docker or Podman engine, or a Windows Docker engine, that reports its OS and version is supported.",
                )
                .to_string(),
            Version::Range => lang
                .t(
                    "엔진의 API 판 범위를 확인하지 못해 조회를 멈췄습니다.",
                    "The engine's API version range could not be confirmed, so querying stopped.",
                )
                .to_string(),
            Version::Kind => lang
                .t(
                    "로컬 엔진의 종류를 확인하지 못했습니다.",
                    "The kind of the local engine could not be confirmed.",
                )
                .to_string(),
            Version::Incompatible {
                min,
                max,
                supported,
            } => lang.pick(
                format!("엔진 API {min}~{max} 와 지원 범위 1.40~1.{supported} 가 맞지 않습니다."),
                format!("The engine API {min} to {max} does not overlap the supported range 1.40 to 1.{supported}."),
            ),
        }
    }
}

impl FileFailure {
    fn message(self, lang: Lang) -> &'static str {
        use FileFailure::*;
        match self {
            StatTooLarge => lang.t(
                "파일 정보 헤더가 너무 큽니다.",
                "The file information header is too large.",
            ),
            StatBase64 => lang.t(
                "파일 정보 헤더의 base64 형식이 잘못되었습니다.",
                "The file information header is not valid base64.",
            ),
            StatMissing => lang.t(
                "파일 정보 헤더에 필수 항목이 없습니다.",
                "The file information header lacks a required field.",
            ),
            StatJson => lang.t(
                "파일 정보 헤더의 JSON 형식이 잘못되었습니다.",
                "The file information header is not valid JSON.",
            ),
            NotRegular => lang.t(
                "요청한 일반 파일이 아니거나 심볼릭 링크입니다.",
                "It is not the requested regular file, or it is a symbolic link.",
            ),
            FileTooLarge => lang.t(
                "개별 컨테이너 파일의 크기 제한(256 MiB)을 넘었습니다.",
                "The file exceeds the 256 MiB limit for a single container file.",
            ),
            BadRequest => lang.t(
                "개별 파일 경로 또는 컨테이너 ID 가 잘못되었습니다.",
                "The file path or the container ID is invalid.",
            ),
            PurposeLimit => lang.t(
                "이 용도의 개별 컨테이너 파일 크기 제한을 넘었습니다.",
                "The file exceeds the size limit for this kind of container file.",
            ),
            StatChanged => lang.t(
                "HEAD 뒤에 파일 정보가 바뀌어 읽기를 멈췄습니다.",
                "The file information changed after HEAD, so reading stopped.",
            ),
            ArchiveTooLarge => lang.t(
                "개별 파일 아카이브의 크기 제한을 넘었습니다.",
                "The single-file archive exceeds its size limit.",
            ),
            ArchiveLimit => lang.t(
                "점검 제한에 도달했습니다: 개별 파일 아카이브 크기 제한",
                "check limit reached: the single-file archive size limit",
            ),
            ArchiveFormat => lang.t(
                "파일 아카이브 형식이 잘못되었습니다.",
                "The file archive is malformed.",
            ),
            ArchiveMember => lang.t(
                "아카이브에 요청한 일반 파일 밖의 항목이나 확장 헤더가 있습니다.",
                "The archive holds an entry or extended header other than the requested regular file.",
            ),
            ArchiveSize => lang.t(
                "아카이브의 파일 크기가 맞지 않습니다.",
                "The file size in the archive does not match.",
            ),
            ArchiveTrailing => lang.t(
                "아카이브에 다른 파일이나 잘못된 데이터가 더 있습니다.",
                "The archive holds another file or invalid data.",
            ),
            ArchiveAfterEnd => lang.t(
                "아카이브의 끝 뒤에 데이터가 더 있습니다.",
                "There is more data after the end of the archive.",
            ),
            NotPe => lang.t(
                "Windows PE 실행 파일의 머리를 확인하지 못했습니다.",
                "The Windows PE executable header could not be confirmed.",
            ),
            Read => lang.t(
                "엔진의 응답을 끝까지 읽지 못했습니다.",
                "The engine's response could not be read to the end.",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::budget::Limit;

    #[test]
    fn a_failure_survives_an_io_error_and_says_its_words_in_both_languages() {
        let f = Failure::Policy(Policy::Status {
            status: 404,
            method: "HEAD",
            route: "/containers/x/archive".into(),
        });
        let back = Failure::from_io(&f.clone().into_io());
        assert_eq!(back, f);
        assert!(back.is_missing());
        assert_eq!(
            f.message(Lang::Ko),
            "컨테이너 API HEAD /containers/x/archive: HTTP 404"
        );
        assert!(Failure::from_io(&io::Error::other("raw os text"))
            .message(Lang::Ko)
            .contains("끝까지"));
        assert!(Failure::Halt(Halt::Limit(Limit::Requests)).is_limit());
        assert!(Failure::File(FileFailure::ArchiveLimit).is_limit());
        assert!(!Failure::Wire(Wire::Timeout).is_limit());
        for lang in [Lang::Ko, Lang::En] {
            for e in [
                EndpointFailure::EngineNotRunning,
                EndpointFailure::FdPermission,
                EndpointFailure::SharedListener,
            ] {
                assert!(!Failure::from(e).message(lang).is_empty());
            }
        }
        assert!(Failure::from(EndpointFailure::EngineNotRunning)
            .message(Lang::Ko)
            .ends_with("접속하지 않았습니다."));
    }
}
