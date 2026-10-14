rule PHP_WP_Backdoor_Campaign_CUST
{
    meta:
        description = "Detects a campaign of malicious WordPress backdoor plugins featuring administrative authentication bypass via master key, plugin list hiding, and timestomping."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-10-14"
        hash = "a3b0764dd7509ff8b8c669e528660dec"
        hash = "b256d3a82dc9e78df10467399832322f"
        hash = "902061f6ebf843cfa0b3d9e0a7e7bcee"

    strings:
        $php = "<?php" ascii

        // Unique Campaign Master Backdoor Key
        $master_key = "2MMatYMDsDr4yMlFmKx3pB5G9iBVTsU0NwOwTE78ShvqQ4Ui" ascii

        // Unique Campaign License Write Key
        $license_key = "e2075474294983e013ee4dd2201c7a73" ascii

        // Backdoor bypass execution sequence
        $auth_bypass_flow = /wp_set_auth_cookie\s*\(\s*\$[a-zA-Z0-9_]+\s*\)\s*;\s*wp_(safe_)?redirect\s*\(\s*[^)]+\s*\)\s*;\s*(exit|die)\s*;?/ ascii

        // Plugin list hiding registration
        $all_plugins = "all_plugins" ascii

        // Campaign self-hiding callback: a hardcoded "dir/file.php" slug assignment
        // immediately followed by an isset() guard and unset() of that entry from
        // $plugins. Requiring the contiguous sequence (instead of an unset() and a
        // slug assignment anywhere in the file) avoids generic plugin-list filters
        // that loop over $plugins and unset entries by computed slug.
        $plugin_hiding_guarded = /\$[a-zA-Z0-9_]+\s*=\s*['"][a-zA-Z0-9_-]+\/[a-zA-Z0-9_-]+\.php['"]\s*;\s*if\s*\(\s*isset\s*\(\s*\$plugins\s*\[\s*\$[a-zA-Z0-9_]+\s*\]\s*\)\s*\)\s*\{?\s*unset\s*\(\s*\$plugins\s*\[\s*\$[a-zA-Z0-9_]+\s*\]\s*\)\s*;/ ascii

        // Timestomping indicators
        $touch_real_path = /touch\(\s*\$[a-zA-Z0-9_]+->getRealPath\(\s*\)/ ascii
        $dir_iter = "DirectoryIterator" ascii
        $rec_dir_iter = "RecursiveDirectoryIterator" ascii
        $rec_iter_iter = "RecursiveIteratorIterator" ascii

    condition:
        $php and filesize < 3MB and (
            $master_key or
            $license_key or
            ($auth_bypass_flow and $all_plugins) or
            $plugin_hiding_guarded or
            ($touch_real_path and any of ($dir_iter, $rec_dir_iter, $rec_iter_iter))
        )
}
