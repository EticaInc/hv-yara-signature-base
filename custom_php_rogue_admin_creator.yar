rule PHP_RogueAdmin_Creator_CUST {
    meta:
        description = "Detects a fake WordPress plugin (WP Compatibility Patch) that creates a hidden rogue administrator account."
        author = "Security Team"
        severity = "HIGH"
        date = "2026-06-07"
        hash = "233a4b148f2df4e21515a6752bb2803a10eab33821e107ad7eb101b33d05872e"
    strings:
        $php = "<?php" ascii
        // Core elements of this specific backdoor
        $func_name = "wpc_patch_bootstrap" ascii
        $user_login = "'user_login' => 'adminbackup'" ascii
        // WP option used to hide the user ID
        $hidden_id = "get_option('_pre_user_id')" ascii
        // Hook used to hide the user from list
        $hook_hide = "add_action('pre_user_query'," ascii
    condition:
        filesize < 100KB and all of them
}
