<?php
/**
 * Synthetic fixture — LinkFlow "WP Defence" coordinator.
 * Identity strings only. No working payload, no replication, no network code.
 *
 * Targets PHP_WP_Defence_LinkFlow_Coordinator_CUST, branch 1: $sync alone.
 * `lf_sync_mu_plugin_copy` is present in every real copy of the coordinator and
 * is the single string the Tier 2 grep sweep keys on.
 */

// name only — the body is deliberately inert
function lf_sync_mu_plugin_copy() {
    return false;
}
