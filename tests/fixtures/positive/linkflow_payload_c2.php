<?php
/**
 * Synthetic fixture — cloaked SEO-spam payload, C2 indicator.
 * Identity strings only. No network code, no cloaking logic, no payload.
 *
 * Targets PHP_WP_LinkFlow_Cloaked_Spam_Payload_CUST, branch 1: $c2 alone.
 * Stands in for xml_domit_rss.php and its near-identical twin validation.php
 * (20,205 B and 20,202 B, same mtime to the second).
 */

// string only — never dereferenced, never contacted
$fixture_c2_indicator = 'sys-pys.com';
