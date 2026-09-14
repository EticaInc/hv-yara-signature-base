rule PHP_WP_SecurityHelper_UserConcealer_CUST {
    meta:
        description = "Detects the 'WP Security Helper' fake WordPress plugin: a stealth user-concealment component that hides tracked administrator accounts from the users list (pre_user_query -> ID NOT IN / ID !=), fakes the subsubsub tab and user counts (pre_count_users / views_users), blocks the user-edit and user-delete screens for the concealed IDs (returning a stock 'Invalid user ID.' wp_die), and hides itself from the plugin list behind a secret ?sp query-parameter bypass. Unlike the rogue-admin *creator* families in this base it does not create the account itself; it conceals whichever admin IDs are promoted while active or supplied through its wsh_* filters, its WSH_HIDDEN_USERS constant, or the legacy _pre_user_id concealment artifact it shares with the rogue-admin ecosystem."
        author = "Security Team"
        family = "WP Security Helper"
        severity = "CRITICAL"
        date = "2026-09-14"
        hash = "5758166e02bc573e6bd8f0e9c65a50734b2063dcd8a2927167c65d9f21b44e74"

    strings:
        $php = "<?php" ascii

        // --- Family identity (this build) ---
        $class      = /class\s+WP_Security_Helper\b/ ascii
        $opt_track  = "wsh_tracked_admin_ids" ascii
        $const_hide = "WSH_HIDDEN_USERS" ascii
        $wsh_track  = "wsh_auto_track_new_admins" ascii
        $wsh_ids    = "wsh_hidden_user_ids" ascii
        $wsh_align  = "wsh_align_unknown_tab_if_matches_total_users" ascii

        // --- Concealment behavior (WP hook names are fixed API, not renameable) ---
        // self-hide from the plugin list behind a secret ?sp bypass
        $sp_bypass   = /isset\s*\(\s*\$_GET\s*\[\s*['"]sp['"]\s*\]\s*\)/ ascii
        $all_plugins = /['"]all_plugins['"]/ ascii
        $hide_fn     = "hide_plugin_from_list" ascii
        // hide specific user IDs from the users query
        $pre_user    = /['"]pre_user_query['"]/ ascii
        $sql_notin   = ".ID NOT IN (" ascii
        $sql_neq     = ".ID != " ascii
        // fake the tab / user counts
        $pre_count   = /['"]pre_count_users['"]/ ascii
        $views_u     = /['"]views_users['"]/ ascii
        // block edit / delete of the concealed users
        $guard_edit  = "guard_user_edit" ascii
        $guard_del   = "guard_user_delete" ascii
        // legacy concealment artifact shared with the rogue-admin ecosystem
        $legacy      = "_pre_user_id" ascii

    condition:
        filesize < 200KB and
        $php at 0 and
        (
            // (a) High-confidence family fingerprint on the build's unique names.
            (
                $class and $opt_track and
                2 of ($const_hide, $wsh_track, $wsh_ids, $wsh_align)
            )
            or
            // (b) Rename-resistant behavioral fingerprint: four independent
            //     concealment techniques co-occurring -- secret-?sp self-hide from
            //     the plugin list, hiding user IDs from the users query, faking the
            //     user counts, and one corroborating concealment marker. Keyed on
            //     fixed WordPress hook names the attacker cannot rename away.
            (
                $sp_bypass and $all_plugins and
                $pre_user and 1 of ($sql_notin, $sql_neq) and
                1 of ($pre_count, $views_u) and
                1 of ($guard_edit, $guard_del, $legacy, $hide_fn)
            )
        )
}
