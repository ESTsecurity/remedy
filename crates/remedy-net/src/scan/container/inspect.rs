//! 엔진의 JSON 응답을 스캐너가 읽던 그대로 — Go `encoding/json` 이 구조체에 담던 규칙.
//!
//! 칸 이름은 대소문자를 가리지 않고 맞추고, 모르는 칸은 버린다. `null` 은 빈 값이다. 담는 칸의 형이 틀리면(글자
//! 자리에 숫자 · 정수 자리에 소수) 응답 전체를 받지 않는다. Go 는 대소문자만 다른 칸이 둘 있으면 문서의 뒤의 것을
//! 쓰는데, 여기서는 그 차례를 알 수 없어 그런 응답을 받지 않는다 — 실제 엔진은 그렇게 쓰지 않는다.

use super::failure::{Failure, Policy};
use super::gostr::fold_eq;
use serde_json::{Map, Value};

type Object = Map<String, Value>;

/// `GET /version` 에서 쓰는 칸.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct EngineVersion {
    pub(crate) version: String,
    pub(crate) api_version: String,
    pub(crate) min_api_version: String,
    pub(crate) os: String,
}

/// `GET /containers/{id}/json` 에서 쓰는 칸.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Inspect {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) image: String,
    pub(crate) path: String,
    pub(crate) args: Vec<String>,
    pub(crate) mounts: Vec<Mount>,
    pub(crate) isolation: String,
    pub(crate) running: bool,
    pub(crate) pid: i64,
    pub(crate) env: Vec<String>,
    pub(crate) entrypoint: Vec<String>,
    pub(crate) cmd: Vec<String>,
}

/// 마운트 하나 — 종류(`bind` · `volume` · `npipe` …)와 컨테이너 안의 자리.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Mount {
    pub(crate) kind: String,
    pub(crate) destination: String,
}

/// `GET /containers/json` 의 한 줄.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Summary {
    pub(crate) id: String,
    pub(crate) names: Vec<String>,
    pub(crate) state: String,
}

/// 형이 틀렸다.
struct Bad;

type Got<T> = Result<T, Bad>;

fn malformed(_: Bad) -> Failure {
    Failure::Policy(Policy::Json)
}

pub(crate) fn version(v: &Value) -> Result<EngineVersion, Failure> {
    let read = |o: &Object| -> Got<EngineVersion> {
        Ok(EngineVersion {
            version: string(o, "Version")?,
            api_version: string(o, "ApiVersion")?,
            min_api_version: string(o, "MinAPIVersion")?,
            os: string(o, "Os")?,
        })
    };
    top(v).and_then(|o| read(&o)).map_err(malformed)
}

pub(crate) fn inspect(v: &Value) -> Result<Inspect, Failure> {
    top(v).and_then(|o| read_inspect(&o)).map_err(malformed)
}

fn read_inspect(o: &Object) -> Got<Inspect> {
    let empty = Object::new();
    let host = object(o, "HostConfig")?.unwrap_or(&empty);
    let state = object(o, "State")?.unwrap_or(&empty);
    let config = object(o, "Config")?.unwrap_or(&empty);
    Ok(Inspect {
        id: string(o, "Id")?,
        name: string(o, "Name")?,
        image: string(o, "Image")?,
        path: string(o, "Path")?,
        args: strings(o, "Args")?,
        mounts: mounts(o)?,
        isolation: string(host, "Isolation")?,
        running: boolean(state, "Running")?,
        pid: int(state, "Pid")?,
        env: strings(config, "Env")?,
        entrypoint: strings(config, "Entrypoint")?,
        cmd: strings(config, "Cmd")?,
    })
}

fn mounts(o: &Object) -> Got<Vec<Mount>> {
    let Some(items) = array(o, "Mounts")? else {
        return Ok(Vec::new());
    };
    let empty = Object::new();
    items
        .iter()
        .map(|item| {
            let m = match item {
                Value::Null => &empty,
                Value::Object(m) => m,
                _ => return Err(Bad),
            };
            Ok(Mount {
                kind: string(m, "Type")?,
                destination: string(m, "Destination")?,
            })
        })
        .collect()
}

/// `GET /containers/json` — 배열(또는 `null`).
pub(crate) fn summaries(v: &Value) -> Result<Vec<Summary>, Failure> {
    let items = match v {
        Value::Null => return Ok(Vec::new()),
        Value::Array(items) => items,
        _ => return Err(malformed(Bad)),
    };
    let empty = Object::new();
    items
        .iter()
        .map(|item| {
            let o = match item {
                Value::Null => &empty,
                Value::Object(o) => o,
                _ => return Err(Bad),
            };
            Ok(Summary {
                id: string(o, "Id")?,
                names: strings(o, "Names")?,
                state: string(o, "State")?,
            })
        })
        .collect::<Got<Vec<Summary>>>()
        .map_err(malformed)
}

/// `GET /images/{id}/json` 의 `Id`.
pub(crate) fn image_id(v: &Value) -> Result<String, Failure> {
    top(v).and_then(|o| string(&o, "Id")).map_err(malformed)
}

/// 응답 전체 — 객체거나 `null`(빈 객체).
fn top(v: &Value) -> Got<Object> {
    match v {
        Value::Null => Ok(Object::new()),
        Value::Object(o) => Ok(o.clone()),
        _ => Err(Bad),
    }
}

/// 이름이 맞는 칸 — 대소문자를 접어 견준다. 둘 이상이면 형이 틀린 것으로 친다.
fn field<'v>(o: &'v Object, name: &str) -> Got<Option<&'v Value>> {
    let mut hits = o.iter().filter(|(k, _)| fold_eq(k, name));
    let first = hits.next();
    if hits.next().is_some() {
        return Err(Bad);
    }
    Ok(first.map(|(_, v)| v).filter(|v| !v.is_null()))
}

fn string(o: &Object, name: &str) -> Got<String> {
    match field(o, name)? {
        None => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(Bad),
    }
}

fn boolean(o: &Object, name: &str) -> Got<bool> {
    match field(o, name)? {
        None => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(Bad),
    }
}

fn int(o: &Object, name: &str) -> Got<i64> {
    match field(o, name)? {
        None => Ok(0),
        Some(Value::Number(n)) if !n.is_f64() => n.as_i64().ok_or(Bad),
        Some(_) => Err(Bad),
    }
}

fn array<'v>(o: &'v Object, name: &str) -> Got<Option<&'v Vec<Value>>> {
    match field(o, name)? {
        None => Ok(None),
        Some(Value::Array(items)) => Ok(Some(items)),
        Some(_) => Err(Bad),
    }
}

fn strings(o: &Object, name: &str) -> Got<Vec<String>> {
    let Some(items) = array(o, name)? else {
        return Ok(Vec::new());
    };
    items
        .iter()
        .map(|item| match item {
            Value::Null => Ok(String::new()),
            Value::String(s) => Ok(s.clone()),
            _ => Err(Bad),
        })
        .collect()
}

fn object<'v>(o: &'v Object, name: &str) -> Got<Option<&'v Object>> {
    match field(o, name)? {
        None => Ok(None),
        Some(Value::Object(m)) => Ok(Some(m)),
        Some(_) => Err(Bad),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fields_match_without_case_and_wrong_types_refuse_the_response() {
        let v = json!({
            "id": "abc", "Name": "/web", "Image": "sha256:x", "Path": "php", "Args": ["-a", null],
            "Mounts": [{"Type": "bind", "Destination": "/data"}, null],
            "HostConfig": {"Isolation": "process"}, "State": {"Running": true, "Pid": 42},
            "Config": {"Env": ["PATH=/usr/bin"], "Entrypoint": null, "Cmd": ["php"]},
            "Unknown": {"anything": [1, 2]}
        });
        let i = inspect(&v).unwrap();
        assert_eq!(i.id, "abc");
        assert_eq!(i.args, vec!["-a".to_string(), String::new()]);
        assert_eq!(i.mounts.len(), 2);
        assert_eq!(i.mounts[0].destination, "/data");
        assert!(i.running);
        assert_eq!(i.pid, 42);
        assert!(i.entrypoint.is_empty());
        assert_eq!(inspect(&Value::Null).unwrap(), Inspect::default());
        for bad in [
            json!({"Id": 5}),
            json!({"State": {"Pid": 1.5}}),
            json!({"State": {"Running": "yes"}}),
            json!({"Config": {"Cmd": "php"}}),
            json!({"Config": {"Env": ["A=1", 2]}}),
            json!({"Mounts": {}}),
            json!({"Id": "a", "ID": "b"}),
            json!([1]),
        ] {
            assert!(inspect(&bad).is_err(), "{bad}");
        }
        let ver = version(
            &json!({"Version": "29", "ApiVersion": "1.52", "MinAPIVersion": "1.24", "Os": "linux"}),
        )
        .unwrap();
        assert_eq!(
            (ver.api_version.as_str(), ver.os.as_str()),
            ("1.52", "linux")
        );
        assert!(summaries(&json!({"Id": "x"})).is_err());
        assert!(summaries(&Value::Null).unwrap().is_empty());
        assert_eq!(image_id(&json!({"Id": "sha256:1"})).unwrap(), "sha256:1");
    }
}
