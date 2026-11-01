//! `verdict.require` 파서 — 감염 판정 게이트 (설계-02 §5).
//!
//! **점수 임계값을 게이트로 쓰지 않는다.** 서로 독립적인 근거의 논리곱을 명시하게
//! 하면, 룰 하나의 오탐이 곧바로 삭제로 이어지지 않는다.
//!
//! 문법은 닫혀 있다 — `and` `or` `not` `(...)` 과 `<rule-id>`,
//! `count(<rule-id>) >= N` 만이다. 넓히면 그만큼 판정이 불투명해진다.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Rule(String),
    /// `count(<rule-id>) >= N`
    Count {
        rule: String,
        at_least: usize,
    },
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "verdict.require 문법 오류: {}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Num(usize),
    LParen,
    RParen,
    Ge,
    And,
    Or,
    Not,
}

fn lex(s: &str) -> Result<Vec<Tok>, ParseError> {
    let mut out = Vec::new();
    let cs: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < cs.len() {
        let c = cs[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            '>' => {
                if cs.get(i + 1) == Some(&'=') {
                    out.push(Tok::Ge);
                    i += 2;
                } else {
                    // '>' 단독은 지원하지 않는다. count 비교는 '>=' 뿐이다.
                    return Err(ParseError(
                        "'>' 는 지원하지 않습니다. '>=' 만 씁니다".into(),
                    ));
                }
            }
            _ if c.is_ascii_digit() => {
                let start = i;
                while i < cs.len() && cs[i].is_ascii_digit() {
                    i += 1;
                }
                let n: String = cs[start..i].iter().collect();
                out.push(Tok::Num(
                    n.parse()
                        .map_err(|_| ParseError(format!("숫자가 너무 큽니다: {n}")))?,
                ));
            }
            // 룰 id 에 '-' 가 들어가므로(예: malicious-task) '-' 를 연산자로 쓰지 않는다.
            _ if c.is_alphanumeric() || c == '-' || c == '_' => {
                let start = i;
                while i < cs.len() && (cs[i].is_alphanumeric() || cs[i] == '-' || cs[i] == '_') {
                    i += 1;
                }
                let w: String = cs[start..i].iter().collect();
                out.push(match w.as_str() {
                    "and" => Tok::And,
                    "or" => Tok::Or,
                    "not" => Tok::Not,
                    _ => Tok::Ident(w),
                });
            }
            _ => return Err(ParseError(format!("알 수 없는 문자: '{c}'"))),
        }
    }
    Ok(out)
}

struct P {
    t: Vec<Tok>,
    i: usize,
}

impl P {
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.i)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.t.get(self.i).cloned();
        self.i += 1;
        t
    }
    fn expect(&mut self, want: Tok) -> Result<(), ParseError> {
        match self.next() {
            Some(t) if t == want => Ok(()),
            other => Err(ParseError(format!("{want:?} 를 기대했으나 {other:?}"))),
        }
    }

    fn or_expr(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.and_expr()?;
        while matches!(self.peek(), Some(Tok::Or)) {
            self.i += 1;
            let right = self.and_expr()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and_expr(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.unary()?;
        while matches!(self.peek(), Some(Tok::And)) {
            self.i += 1;
            let right = self.unary()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr, ParseError> {
        if matches!(self.peek(), Some(Tok::Not)) {
            self.i += 1;
            return Ok(Expr::Not(Box::new(self.unary()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, ParseError> {
        match self.next() {
            Some(Tok::LParen) => {
                let e = self.or_expr()?;
                self.expect(Tok::RParen)?;
                Ok(e)
            }
            Some(Tok::Ident(name)) => {
                if name == "count" && matches!(self.peek(), Some(Tok::LParen)) {
                    self.i += 1;
                    let rule = match self.next() {
                        Some(Tok::Ident(r)) => r,
                        other => {
                            return Err(ParseError(format!("count( 안에 룰 id 가 아닌 {other:?}")))
                        }
                    };
                    self.expect(Tok::RParen)?;
                    self.expect(Tok::Ge)?;
                    let n = match self.next() {
                        Some(Tok::Num(n)) => n,
                        other => return Err(ParseError(format!("숫자를 기대했으나 {other:?}"))),
                    };
                    Ok(Expr::Count { rule, at_least: n })
                } else {
                    Ok(Expr::Rule(name))
                }
            }
            other => Err(ParseError(format!("예상치 못한 토큰: {other:?}"))),
        }
    }
}

pub fn parse(s: &str) -> Result<Expr, ParseError> {
    let toks = lex(s)?;
    if toks.is_empty() {
        return Err(ParseError("비어 있습니다".into()));
    }
    let mut p = P { t: toks, i: 0 };
    let e = p.or_expr()?;
    if p.i != p.t.len() {
        return Err(ParseError(format!(
            "끝까지 읽지 못했습니다 ({}번째 토큰에서 멈춤)",
            p.i
        )));
    }
    Ok(e)
}

/// 이 식이 참조하는 룰 id 전부. 존재하지 않는 룰을 참조하는지 검사할 때 쓴다.
pub fn referenced_rules(e: &Expr, out: &mut Vec<String>) {
    match e {
        Expr::Rule(r) => out.push(r.clone()),
        Expr::Count { rule, .. } => out.push(rule.clone()),
        Expr::Not(a) => referenced_rules(a, out),
        Expr::And(a, b) | Expr::Or(a, b) => {
            referenced_rules(a, out);
            referenced_rules(b, out);
        }
    }
}

/// 한 그룹 안에서 판정한다.
///
/// `counts` 는 그 그룹이 가진 룰별 증거 수다. **그룹 간 증거가 섞여 판정을
/// 성립시키는 일은 없다** — 서로 무관한 두 정상 소프트웨어의 조각이 합쳐져
/// 감염 판정을 만드는 사고를 막는다 (설계-02 §4).
pub fn eval(e: &Expr, counts: &BTreeMap<String, usize>) -> bool {
    match e {
        Expr::Rule(r) => counts.get(r).copied().unwrap_or(0) > 0,
        Expr::Count { rule, at_least } => counts.get(rule).copied().unwrap_or(0) >= *at_least,
        Expr::Not(a) => !eval(a, counts),
        Expr::And(a, b) => eval(a, counts) && eval(b, counts),
        Expr::Or(a, b) => eval(a, counts) || eval(b, counts),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(pairs: &[(&str, usize)]) -> BTreeMap<String, usize> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn parses_the_first_plugin_expression() {
        let e = parse("task and payload").unwrap();
        assert!(eval(&e, &counts(&[("task", 1), ("payload", 1)])));
        assert!(!eval(&e, &counts(&[("task", 1)])), "논리곱이어야 한다");
    }

    #[test]
    fn hyphenated_rule_ids_work() {
        // 'malicious-task' 의 '-' 를 연산자로 읽으면 룰 이름이 쪼개진다.
        let e = parse("malicious-task and dropped-payload").unwrap();
        assert_eq!(
            e,
            Expr::And(
                Box::new(Expr::Rule("malicious-task".into())),
                Box::new(Expr::Rule("dropped-payload".into()))
            )
        );
    }

    #[test]
    fn and_binds_tighter_than_or() {
        let e = parse("a or b and c").unwrap();
        // a or (b and c)
        assert!(eval(&e, &counts(&[("a", 1)])));
        assert!(!eval(&e, &counts(&[("b", 1)])));
        assert!(eval(&e, &counts(&[("b", 1), ("c", 1)])));
    }

    #[test]
    fn parentheses_override_precedence() {
        let e = parse("(a or b) and c").unwrap();
        assert!(!eval(&e, &counts(&[("a", 1)])));
        assert!(eval(&e, &counts(&[("a", 1), ("c", 1)])));
    }

    #[test]
    fn not_works() {
        let e = parse("a and not b").unwrap();
        assert!(eval(&e, &counts(&[("a", 1)])));
        assert!(!eval(&e, &counts(&[("a", 1), ("b", 1)])));
    }

    #[test]
    fn count_requires_at_least() {
        let e = parse("count(a) >= 2").unwrap();
        assert!(!eval(&e, &counts(&[("a", 1)])));
        assert!(eval(&e, &counts(&[("a", 2)])));
        assert!(eval(&e, &counts(&[("a", 5)])));
    }

    #[test]
    fn closed_grammar_rejects_extras() {
        // 문법을 넓히면 판정이 불투명해진다. 지원하지 않는 것은 거부한다.
        assert!(parse("a && b").is_err(), "'&&' 는 문법에 없다");
        assert!(
            parse("score >= 80").is_err(),
            "점수 임계값은 게이트가 아니다"
        );
        assert!(parse("count(a) > 1").is_err(), "'>' 는 지원하지 않는다");
        assert!(parse("").is_err());
        assert!(parse("a and").is_err());
        assert!(parse("(a and b").is_err());
        assert!(parse("a b").is_err(), "연산자 없이 이어 붙일 수 없다");
    }

    #[test]
    fn collects_referenced_rules() {
        let e = parse("a and (count(b) >= 2 or not c)").unwrap();
        let mut v = Vec::new();
        referenced_rules(&e, &mut v);
        v.sort();
        assert_eq!(v, vec!["a", "b", "c"]);
    }
}
