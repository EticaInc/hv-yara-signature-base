<?php
/**
 * Legitimate plugin that references both WP_PLUGIN_DIR and WPMU_PLUGIN_DIR.
 *
 * Precision test for PHP_WP_Defence_LinkFlow_Coordinator_CUST branch 3, which
 * requires the cover-story string AND both constants. Plenty of real plugins
 * enumerate both directories; the constants alone must not be enough to match.
 * This file omits the cover string, so it must stay silent.
 *
 * Do not quote the cover string in this file, even in a comment. YARA matches
 * bytes, not code — an earlier draft of this fixture spelled it out here and
 * matched for that reason alone. Same applies to the case notes and sweep
 * documents: they quote every identity string, so keep them out of scan scope.
 */

function fixture_plugin_search_paths() {
    $paths = array();
    if ( defined( 'WP_PLUGIN_DIR' ) ) {
        $paths[] = WP_PLUGIN_DIR;
    }
    if ( defined( 'WPMU_PLUGIN_DIR' ) ) {
        $paths[] = WPMU_PLUGIN_DIR;
    }
    return $paths;
}
