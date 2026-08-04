rule PHP_WP_StealthAdmin_Plugin_CUST {
    meta:
        description = "Detects a malicious WordPress plugin campaign that creates a hidden administrator account, hides itself from the plugin list, manipulates user counts, and persists by re-activating itself on shutdown. Known variants: 'Core Handler' (wordpresslicensed) and 'Seo Core' (alice.tulaeva)."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-06-29"
        hash = "f3b56f3760555cd4359d3fd9d264f4b626e6c7d8586d299e21000edffb89c741"
        hash2 = "bed9b6e8a20ce6388da32e2473f2dd3523782828326f3ea46856cc6c099076ad"

    strings:
        $php = "<?php" ascii

        // --- Rogue admin creation pattern ---
        $create_fn     = "function create_admin()" ascii
        $set_role      = "set_role('administrator')" ascii
        $wp_create     = "wp_create_user(" ascii

        // --- User hiding from WP queries and REST API ---
        $hide_fn       = "function hide_admin_user(" ascii
        $hide_rest_fn  = "function hide_from_rest(" ascii
        $rest_hook     = "add_filter('rest_user_query'" ascii

        // --- User count manipulation to mask rogue account ---
        $count_fn      = "function correct_user_count(" ascii
        $count_decr    = "$list['total_users']--" ascii

        // --- Plugin self-hiding from admin UI ---
        $hide_plugin   = "function hide_plugin(" ascii
        $filter_all    = "add_filter('all_plugins', 'hide_plugin')" ascii

        // --- Persistence: re-activation on shutdown ---
        $persist_fn    = "function ensure_plugin_active()" ascii
        $persist_hook  = "add_action('shutdown', 'ensure_plugin_active')" ascii

        // --- XML-RPC user enumeration lockdown ---
        $xmlrpc_hide   = "unset($methods['wp.getUsers'])" ascii

    condition:
        filesize < 100KB and
        $php at 0 and
        (
            // Core campaign fingerprint: rogue admin creation + hiding + persistence
            (
                $create_fn and
                $wp_create and
                $set_role and
                $hide_fn and
                $persist_fn
            )
            or
            // Broader behavioral match: 4+ of the technique indicators
            (
                4 of ($count_fn, $count_decr, $hide_plugin, $filter_all,
                       $persist_fn, $persist_hook, $hide_rest_fn, $rest_hook,
                       $xmlrpc_hide)
            )
        )
}
