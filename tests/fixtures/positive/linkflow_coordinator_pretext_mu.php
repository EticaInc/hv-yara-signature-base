<?php
/**
 * Description: Fetches plugin updates from a remote server.
 *
 * Synthetic fixture — cover-story string plus both replication constants.
 * Identity strings only. No working payload, no file writes.
 *
 * Targets PHP_WP_Defence_LinkFlow_Coordinator_CUST, branch 3:
 * $pretext and all of ($mu1, $mu2).
 *
 * Carries neither the vendor URL nor either class name, so it is the branch
 * that would survive a rename of both the fake vendor and the class. The two
 * constants together are what the real coordinator uses to push itself from
 * plugins/ into mu-plugins/.
 */

$fixture_targets = array(
    'source' => 'WP_PLUGIN_DIR',
    'dest'   => 'WPMU_PLUGIN_DIR',
);
