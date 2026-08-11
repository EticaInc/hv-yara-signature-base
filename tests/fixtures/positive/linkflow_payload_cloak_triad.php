<?php
/**
 * Synthetic fixture — behavioural triad with no LinkFlow namespace at all.
 * Identity strings only. No cloaking logic, no redirects, no network code.
 *
 * Targets PHP_WP_LinkFlow_Cloaked_Spam_Payload_CUST, branch 3:
 * $cookie and $cloak and $badurls.
 *
 * The family-agnostic branch: no `lf_` prefix and no C2 host, matching purely
 * on the shape of "suppress for staff browsers, exclude admin and asset paths,
 * serve only to everyone else." Should survive a full renaming of the family.
 */

$bad_urls = array();

$fixture_cookie = 'http2_session_id';

// referenced as a string, not invoked
$fixture_cloak_call = 'is_user_logged_in()';
