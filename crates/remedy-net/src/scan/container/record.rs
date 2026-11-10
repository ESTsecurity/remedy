//! 대상을 올리고 남긴다 — 스캐너 `finalizeContainerTarget` · `recordPartial`.

use super::client::Client;
use super::phpconf::set_php_config_finding;
use crate::scan::model::Target;
use remedy_sdk::i18n::Lang;

/// 대상을 올린다. PHP 를 찾았는데 세션 설정 판정이 아직 없으면 *설정을 모으지 못했다* 는 판정을 먼저 싣는다.
pub(crate) fn finalize_container_target(t: &mut Target, lang: Lang) {
    let issue = lang.t(
        "설정 파일을 수집하지 못해 PHP 세션 설정을 확인하지 못했습니다.",
        "The configuration files were not collected, so the PHP session settings were not confirmed.",
    );
    set_php_config_finding(t, &[], &[issue.to_string()], lang);
    t.finalize(lang);
}

/// 끝내지 못한 대상의 지금 모양을 예산에 남긴다 — 올리는 것은 사본뿐이라 쓰던 대상의 까닭 · 할 일은 빈 채로 남는다.
pub(crate) fn record_partial(c: &Client<'_>, t: &Target) {
    let mut copy = t.clone();
    finalize_container_target(&mut copy, c.lang);
    c.budget.record_target(&copy);
}
