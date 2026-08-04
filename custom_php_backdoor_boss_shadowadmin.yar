rule PHP_Boss_ShadowAdmin_CUST {
    meta:
        description = "Detects 'Boss' persistent backdoor that creates hidden admin user and installs as mu-plugin"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-01-13"
        hash = "2c5a6c8e9f2a4b8d7c6e5f4a3b2d1e0f"
    strings:
        // Unique function names defined in the malware
        $func_sync = "function boss_sync()"
        $func_ensure = "function boss_ensure_user_exists"

        // Variable naming conventions used for configuration
        $var_boss_user = "$boss_username ="
        $var_dyn_key = "$dyn_key ="

        // The stealth logic: Decrementing the user count in the admin view
        $stealth_count = "preg_replace_callback('/\\((\\d+)\\)/', function($m)"

        // The persistence logic: Writing itself to mu-plugins
        $persist_mu = "$mu_dir . '/' . $mu_plugin_filename"

        // The hiding logic: Querying DB to exclude specific user
        $hide_db_query = "SELECT ID FROM $wpdb->users WHERE user_login = %s"

    condition:
        filesize < 100KB and
        (
            // Match highly specific function names
            1 of ($func_*) or
            // Or match a combination of the stealth/persistence logic
            (
                // FIXED: Now checking for either the boss user variable OR the dynamic key variable
                ($var_boss_user or $var_dyn_key) and
                ( $stealth_count or $persist_mu or $hide_db_query )
            )
        )
}
