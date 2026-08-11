<?php
/**
 * Synthetic fixture — LinkFlow namespace flag plus the staff-suppression cookie.
 * Identity strings only. No cloaking logic, no network code.
 *
 * Targets PHP_WP_LinkFlow_Cloaked_Spam_Payload_CUST, branch 2:
 * $lf and any of ($cookie, $guard, $badurls).
 *
 * Carries no C2 host, so it covers the case where the actor rotates away from
 * sys-pys.com but keeps the lf_ namespace. That is precisely how the previous
 * rule (custom_php_seo_spam_linkflow.yar) went stale on this family.
 */

$lf_enable = 0;

$fixture_suppression_cookie = 'http2_session_id';

$fixture_guard = "class_exists('WP_Defence')";
