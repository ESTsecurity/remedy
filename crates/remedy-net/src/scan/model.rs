//! 결과 모델 — 발견 하나에서 대상 하나, 대상들에서 실행 전체로 판정이 올라가는 길.
//!
//! 사내 runtime-scanner 의 `internal/model` 을 옮겼다. 규칙은 셋이다.
//!
//! - **취약이 이긴다.** 확인하지 못한 것(`gaps`)이 있어도 확인된 취약은 남는다.
//! - **확인하지 못한 것을 양호로 내지 않는다.** 제품에 `gaps` 가 하나라도 있으면 그 제품은 많아야 *확인 필요* 다.
//! - **제품마다 따로 센다.** 한 제품에만 붙은 `gaps` 가 다른 제품을 *확인 필요* 로 만들지 않는다. 대상에 붙은
//!   `gaps` 는 모든 제품에 복사된다.
//!
//! 사람이 읽는 칸(`reason` · `action` · `gaps` · `scope` · 발견의 `name`)은 실행 언어로 적힌다.

use remedy_sdk::i18n::Lang;
use schemars::JsonSchema;
use serde::Serialize;
use std::collections::BTreeMap;

/// 판정. 뒤에 선 것이 더 나쁘다 — 올림은 가장 나쁜 값을 고른다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// 양호 — 본 범위에서 고친 버전임을 확인했거나 그 제품이 없다.
    Clear,
    /// 확인 필요 — 근거가 모자라거나 다 보지 못했다.
    ReviewRequired,
    /// 취약 — 고치기 전 버전임을 확인했다.
    Vulnerable,
}

impl Status {
    pub fn label(self, lang: Lang) -> &'static str {
        match self {
            Status::Clear => lang.t("양호", "clear"),
            Status::ReviewRequired => lang.t("확인 필요", "needs review"),
            Status::Vulnerable => lang.t("취약", "vulnerable"),
        }
    }
}

/// 판정하는 제품. Brotli 는 따로 고르는 제품이 아니라 Node.js 가 연결한 디코더로만 나온다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Product {
    Php,
    Node,
    Brotli,
}

impl Product {
    /// 결과 파일과 명령줄(`--runtime`)의 이름.
    pub fn id(self) -> &'static str {
        match self {
            Product::Php => "php",
            Product::Node => "node",
            Product::Brotli => "brotli",
        }
    }

    /// 화면에 적는 이름.
    pub fn name(self) -> &'static str {
        match self {
            Product::Php => "PHP",
            Product::Node => "Node.js",
            Product::Brotli => "Brotli",
        }
    }
}

/// 근거 한 줄 — 어디서(`source`) 무엇을(`detail`) 보았나.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Evidence {
    pub source: String,
    pub detail: String,
}

impl Evidence {
    pub fn new(source: impl Into<String>, detail: impl Into<String>) -> Self {
        Evidence {
            source: source.into(),
            detail: detail.into(),
        }
    }
}

/// 발견 하나 — 파일 · 패키지 · 설정 가운데 판정이 붙은 것.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Finding {
    pub product: Product,
    pub id: String,
    pub name: String,
    pub path: Option<String>,
    pub version: Option<String>,
    pub package: Option<String>,
    /// 배포판 식별자 또는 `upstream`.
    pub vendor: Option<String>,
    /// `cli` · `fpm` · `cgi` · `apache-module` · `node` 처럼 어떤 실행 꼴인가.
    pub runtime: Option<String>,
    pub cves: Vec<String>,
    pub status: Status,
    pub reason: String,
    pub action: String,
    pub evidence: Vec<Evidence>,
}

/// 한 제품을 어디까지 보았나.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Coverage {
    pub status: Status,
    /// `gaps` 가 없을 때만 참.
    pub complete: bool,
    /// 읽은 자리.
    pub scope: Vec<String>,
    /// 보지 못한 것과 그 까닭.
    pub gaps: Vec<String>,
    pub reason: String,
    pub action: String,
}

impl Coverage {
    fn fresh() -> Self {
        Coverage {
            status: Status::Clear,
            complete: true,
            scope: Vec::new(),
            gaps: Vec::new(),
            reason: String::new(),
            action: String::new(),
        }
    }
}

/// 대상의 종류.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    /// 이미지 파일 안의 실행 이미지 하나(플랫폼마다 하나).
    Image,
    /// 실행 중인 컨테이너 하나.
    Container,
}

/// 대상 하나 — 이미지의 플랫폼 하나 또는 컨테이너 하나.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct Target {
    pub id: String,
    pub kind: TargetKind,
    pub name: String,
    pub status: Status,
    pub reason: String,
    pub action: String,
    pub findings: Vec<Finding>,
    /// 대상 전체에 걸린 *보지 못한 것* — 올릴 때 모든 제품에 복사된다.
    pub gaps: Vec<String>,
    /// 모든 제품이 `complete` 일 때만 참.
    pub complete: bool,
    pub scope: Vec<String>,
    pub products: BTreeMap<Product, Coverage>,
    /// 플랫폼 · 배포판 · 다이제스트처럼 대상을 알아보는 값.
    pub metadata: BTreeMap<String, String>,
}

fn push_unique(list: &mut Vec<String>, value: String) {
    if !list.contains(&value) {
        list.push(value);
    }
}

impl Target {
    /// 고른 제품으로 시작하는 빈 대상. 제품은 *양호 · 다 보았음* 에서 출발하고, 발견과 `gaps` 가 그것을 내린다.
    pub fn new(
        id: impl Into<String>,
        kind: TargetKind,
        name: impl Into<String>,
        products: &[Product],
    ) -> Self {
        let mut t = Target {
            id: id.into(),
            kind,
            name: name.into(),
            status: Status::Clear,
            reason: String::new(),
            action: String::new(),
            findings: Vec::new(),
            gaps: Vec::new(),
            complete: true,
            scope: Vec::new(),
            products: BTreeMap::new(),
            metadata: BTreeMap::new(),
        };
        t.init_products(products);
        t
    }

    pub fn init_products(&mut self, products: &[Product]) {
        for p in products {
            self.products.entry(*p).or_insert_with(Coverage::fresh);
        }
    }

    /// 대상 전체에 걸린 *보지 못한 것*. 같은 문장은 한 번만 남는다.
    pub fn add_gap(&mut self, message: impl Into<String>) {
        push_unique(&mut self.gaps, message.into());
    }

    /// 한 제품에만 걸린 *보지 못한 것*.
    pub fn add_product_gap(&mut self, product: Product, message: impl Into<String>) {
        let c = self.products.entry(product).or_insert_with(Coverage::fresh);
        push_unique(&mut c.gaps, message.into());
        c.complete = false;
    }

    pub fn add_scope(&mut self, what: impl Into<String>) {
        push_unique(&mut self.scope, what.into());
    }

    pub fn add_product_scope(&mut self, product: Product, path: impl Into<String>) {
        let c = self.products.entry(product).or_insert_with(Coverage::fresh);
        push_unique(&mut c.scope, path.into());
    }

    /// 발견과 `gaps` 에서 제품의 판정을, 제품에서 대상의 판정을 낸다. 여러 번 불러도 된다 — 중간 결과를 남길 때도
    /// 이것을 부른다. `reason` · `action` 이 이미 적힌 대상은 그 문장을 지킨다.
    pub fn finalize(&mut self, lang: Lang) {
        let mut worst = Status::Clear;
        let mut complete = true;
        for (product, c) in self.products.iter_mut() {
            for gap in &self.gaps {
                push_unique(&mut c.gaps, gap.clone());
            }
            if !c.gaps.is_empty() {
                c.complete = false;
            }
            let mut status = if c.complete {
                Status::Clear
            } else {
                Status::ReviewRequired
            };
            let mut found = 0usize;
            for f in self.findings.iter().filter(|f| f.product == *product) {
                found += 1;
                status = status.max(f.status);
            }
            c.status = status;
            let (reason, action) = product_words(*product, status, found, lang);
            c.reason = reason;
            c.action = action;
            worst = worst.max(status);
            complete = complete && c.complete;
        }
        if self.products.is_empty() {
            // 제품을 고르기 전에 실패한 대상 — 발견과 대상의 `gaps` 만으로 낸다.
            complete = self.gaps.is_empty();
            if !complete {
                worst = Status::ReviewRequired;
            }
            for f in &self.findings {
                worst = worst.max(f.status);
            }
        }
        self.status = worst;
        self.complete = complete;
        if self.reason.is_empty() {
            self.reason = match worst {
                Status::Vulnerable => lang.t(
                    "보안 패치가 적용되지 않은 런타임이 발견됐습니다.",
                    "A runtime without the security patch was found.",
                ),
                Status::Clear => lang.t(
                    "지정한 범위의 런타임 점검을 마쳤습니다.",
                    "The runtime check of the given scope is complete.",
                ),
                Status::ReviewRequired => lang.t(
                    "일부 항목의 보안 패치 적용 여부를 확인하지 못했습니다.",
                    "The security patch could not be confirmed for some items.",
                ),
            }
            .to_string();
        }
        if self.action.is_empty() {
            self.action = lang
                .t(
                    "제품별 결과와 확인하지 못한 항목을 살펴보십시오.",
                    "See the per-product results and the unconfirmed items.",
                )
                .to_string();
        }
    }
}

fn product_words(product: Product, status: Status, found: usize, lang: Lang) -> (String, String) {
    let name = product.name();
    match status {
        Status::Vulnerable => (
            match lang {
                Lang::Ko => format!("보안 패치가 적용되지 않은 {name} 구성요소가 발견됐습니다."),
                Lang::En => format!("A {name} component without the security patch was found."),
            },
            lang.t(
                "서비스 담당자가 공급사 안내에 따라 보안 패치를 적용한 뒤 다시 점검하십시오.",
                "Have the service owner apply the vendor's security patch, then check again.",
            )
            .to_string(),
        ),
        Status::Clear => (
            match (lang, found) {
                (Lang::Ko, 0) => format!("지정한 범위에서 {name} 을(를) 찾지 못했습니다."),
                (Lang::En, 0) => format!("No {name} was found in the given scope."),
                (Lang::Ko, _) => format!("발견된 {name} 의 보안 패치 적용을 확인했습니다."),
                (Lang::En, _) => format!("The security patch was confirmed for the {name} found."),
            },
            lang.t(
                "점검 범위와 기준일을 확인하고 서비스 기능도 따로 시험하십시오.",
                "Check the scope and the criteria date, and test the service separately.",
            )
            .to_string(),
        ),
        Status::ReviewRequired => (
            match lang {
                Lang::Ko => format!(
                    "{name} 의 보안 패치 적용 여부를 확인할 근거가 모자라거나 점검이 끝나지 않았습니다."
                ),
                Lang::En => format!(
                    "There was not enough evidence to confirm the {name} security patch, or the check did not finish."
                ),
            },
            lang.t(
                "확인하지 못한 항목을 살펴보고 해당 서버에서 다시 점검하십시오.",
                "Review the unconfirmed items and check again on that server.",
            )
            .to_string(),
        ),
    }
}

/// 실행 전체의 판정. 대상이 하나도 없으면 *확인 필요* 다 — 아무것도 보지 못한 것을 양호로 내지 않는다.
pub fn aggregate(targets: &[Target]) -> Status {
    if targets.is_empty() {
        return Status::ReviewRequired;
    }
    let mut status = Status::Clear;
    for t in targets {
        if t.status == Status::Vulnerable {
            return Status::Vulnerable;
        }
        if t.status != Status::Clear || !t.complete || !t.gaps.is_empty() {
            status = Status::ReviewRequired;
        }
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(product: Product, status: Status) -> Finding {
        Finding {
            product,
            id: format!("{}:{status:?}", product.id()),
            name: "시험".to_string(),
            path: None,
            version: None,
            package: None,
            vendor: None,
            runtime: None,
            cves: Vec::new(),
            status,
            reason: String::new(),
            action: String::new(),
            evidence: Vec::new(),
        }
    }

    fn target(products: &[Product]) -> Target {
        Target::new("t", TargetKind::Image, "시험 이미지", products)
    }

    #[test]
    fn nothing_found_and_nothing_missed_is_clear() {
        let mut t = target(&[Product::Php, Product::Node]);
        t.finalize(Lang::Ko);
        assert_eq!(t.status, Status::Clear);
        assert!(t.complete);
        assert!(t.products[&Product::Php].reason.contains("찾지 못했습니다"));
        assert_eq!(aggregate(&[t]), Status::Clear);
    }

    #[test]
    fn a_gap_is_never_clear() {
        let mut t = target(&[Product::Php]);
        t.add_gap("패키지 DB 를 읽지 못했습니다.");
        t.finalize(Lang::Ko);
        assert_eq!(t.status, Status::ReviewRequired);
        assert!(!t.complete);
        assert_eq!(t.products[&Product::Php].gaps.len(), 1);
    }

    #[test]
    fn a_confirmed_vulnerability_survives_gaps() {
        let mut t = target(&[Product::Php]);
        t.findings.push(finding(Product::Php, Status::Vulnerable));
        t.add_gap("레이어 한도에 닿았습니다.");
        t.finalize(Lang::Ko);
        assert_eq!(t.status, Status::Vulnerable);
        assert!(!t.complete);
        assert_eq!(aggregate(&[t]), Status::Vulnerable);
    }

    #[test]
    fn a_product_gap_stays_with_its_product() {
        let mut t = target(&[Product::Php, Product::Node]);
        t.add_product_gap(Product::Node, "연결된 Brotli 를 확인하지 못했습니다.");
        t.findings.push(finding(Product::Php, Status::Clear));
        t.finalize(Lang::Ko);
        assert_eq!(t.products[&Product::Php].status, Status::Clear);
        assert!(t.products[&Product::Php].complete);
        assert_eq!(t.products[&Product::Node].status, Status::ReviewRequired);
        assert_eq!(t.status, Status::ReviewRequired);
        assert!(!t.complete);
    }

    #[test]
    fn a_target_gap_reaches_every_product_once() {
        let mut t = target(&[Product::Php, Product::Node]);
        t.add_gap("같은 문장");
        t.add_gap("같은 문장");
        t.finalize(Lang::Ko);
        t.finalize(Lang::Ko);
        assert_eq!(t.gaps.len(), 1);
        assert_eq!(
            t.products[&Product::Php].gaps,
            vec!["같은 문장".to_string()]
        );
        assert_eq!(
            t.products[&Product::Node].gaps,
            vec!["같은 문장".to_string()]
        );
    }

    #[test]
    fn a_review_finding_lowers_only_its_product() {
        let mut t = target(&[Product::Php, Product::Node]);
        t.findings
            .push(finding(Product::Php, Status::ReviewRequired));
        t.findings.push(finding(Product::Node, Status::Clear));
        t.finalize(Lang::En);
        assert_eq!(t.products[&Product::Php].status, Status::ReviewRequired);
        assert_eq!(t.products[&Product::Node].status, Status::Clear);
        assert!(t.products[&Product::Node].reason.contains("confirmed"));
        assert_eq!(t.status, Status::ReviewRequired);
        // 발견이 확인 필요일 뿐 못 본 것은 없다 — 다 보았다는 표시는 남는다.
        assert!(t.complete);
    }

    #[test]
    fn an_earlier_reason_is_kept() {
        let mut t = target(&[Product::Php]);
        t.reason = "이미지를 열지 못했습니다.".to_string();
        t.add_gap("이미지를 열지 못했습니다.");
        t.finalize(Lang::Ko);
        assert_eq!(t.reason, "이미지를 열지 못했습니다.");
        assert!(!t.action.is_empty());
    }

    #[test]
    fn a_target_without_products_still_rolls_up() {
        let mut t = target(&[]);
        t.add_gap("입력을 읽지 못했습니다.");
        t.finalize(Lang::Ko);
        assert_eq!(t.status, Status::ReviewRequired);
        assert!(!t.complete);
    }

    #[test]
    fn no_target_at_all_needs_review() {
        assert_eq!(aggregate(&[]), Status::ReviewRequired);
    }

    #[test]
    fn a_clear_target_with_a_leftover_gap_needs_review() {
        let mut clear = target(&[Product::Node]);
        clear.finalize(Lang::Ko);
        let mut odd = target(&[]);
        odd.status = Status::Clear;
        odd.gaps.push("남은 것".to_string());
        assert_eq!(aggregate(&[clear, odd]), Status::ReviewRequired);
    }

    #[test]
    fn status_serialises_as_the_scanner_words() {
        let json =
            serde_json::to_string(&[Status::Clear, Status::ReviewRequired, Status::Vulnerable])
                .unwrap();
        assert_eq!(json, r#"["clear","review_required","vulnerable"]"#);
    }
}
