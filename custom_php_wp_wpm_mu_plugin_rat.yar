rule PHP_WP_WPM_MuPlugin_RAT_CUST {
    meta:
        description = "Detects the 'WPM' mu-plugin remote administration backdoor, camouflaged as a 'Heartbeat Optimizer' / mail transport drop-in and restored by PHP_WP_Scatter_Stub_CUST. Registers a private REST namespace exposing shell execution, theme functions.php rewriting, plugin activation and deletion, and cron manipulation. Captures credentials through the authenticate filter and after_password_reset, and conceals its operator account and itself via pre_user_query, views_users, pre_current_active_plugins and the site health debug_information filter. Anti-forensics restores each edited file's pre-edit mtime, falling back to the median mtime of neighbouring files and then to WordPress core files. Self-heals from a base64 blob held in both a wp_options row and a meta table row. Every string is built at runtime by per-string XOR closures. This rule covers the large mu-plugin payload only; the small scattered loader stubs are PHP_WP_Scatter_Stub_CUST."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-09-25"
        hash = "3c81e88856ff9c82a43ddf2c554b571c7dc0d3fbce56ff1dc05d92184ff03056"
    strings:
        $php = "<?php" ascii

        // --- Identity: markers unique to this payload. The campaign secret and the
        //     _core_integrity_hash option are deliberately NOT used here: they are shared
        //     with the scatter stub, and keying on them would double-count one infection.
        $id_ns    = "cron-api/v1" ascii
        $id_build = "245e8fa609e18d8c" ascii
        $id_pkg   = "Heartbeat Optimizer" ascii
        $id_log   = "_site_login_attempt_log" ascii
        $id_wph   = "_wph_b9dd" ascii
        $id_tc    = "transient_cleanup_run_dfb4" ascii

        // --- Behavioral: WordPress core hook names, which the operator cannot rename
        //     without losing the capability, plus the structural fingerprint of the
        //     per-string XOR decoder closure this build wraps every literal in.
        $h_userquery  = "pre_user_query" ascii
        $h_viewsusers = "views_users" ascii
        $h_pluginlist = "pre_current_active_plugins" ascii
        $h_pwreset    = "after_password_reset" ascii
        $h_auth       = "'authenticate'" ascii
        $h_updplugins = "site_transient_update_plugins" ascii

        // Counted, not merely present: one closure could appear incidentally; this build
        // wraps every literal, carrying 139 occurrences.
        $o_xorclosure = /\(function\(\)\{\$[A-Za-z0-9_]+=array\([0-9]+(,[0-9]+){4,}\);/ ascii
    condition:
        filesize < 5MB and $php and
        (
            (2 of ($id_*))
            or
            // Account/plugin concealment plus credential capture, in a file whose literals
            // are all assembled by XOR decoder closures.
            (#o_xorclosure > 10 and 4 of ($h_*))
        )
}
