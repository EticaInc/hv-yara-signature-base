rule PHP_WP_Session_Manager_CUST {
    meta:
        description = "Detects advanced WP session stealer, webshell, and redirect cleaner acting as a mu-plugin."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-03-25"
    strings:
        $php = "<?php" ascii

        // Structural Indicators
        $s1 = "_wp_session_paused" ascii
        $s2 = "_sm_rg_whitelist" ascii
        $s3 = "wp_debug_session" ascii

        // Behaviors
        $b1 = "array('Wordfence', 'Sucuri', 'WPScan', 'Nessus'" ascii
        $b2 = "add_filter('authenticate', function ($user, $username, $password)" ascii
        $b3 = "function_exists('shell_exec')" ascii
        $b4 = "$_al_hmac" ascii
    condition:
        filesize < 3MB and $php and ($s1 or $s2 or $s3) and 2 of ($b*)
}
rule PHP_WP_Session_Manager_Dropper_CUST {
    meta:
        description = "Detects the advanced-cache.php dropper that retrieves session-manager.php from wp_session_tokens_config in the database."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-04-12"
        hash = "advanced-cache.php"
    strings:
        // Unique comment tag used by this malware variant
        $s1 = "/* _sm_ac_v5 */" ascii

        // Target DB extraction string
        $s2 = "option_name='wp_session_tokens_config'" ascii nocase

        // Target drop file
        $s3 = "session-manager.php" ascii nocase

        // Cache bypass headers
        $cache1 = "DONOTCACHEPAGE" ascii
        $cache2 = "LSCACHE_NO_CACHE" ascii

    condition:
        filesize < 50KB and
        (
            $s1 or
            ($s2 and $s3) or
            ($s2 and $cache1 and $cache2)
        )
}
