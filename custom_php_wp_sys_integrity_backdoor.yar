rule PHP_WP_SysIntegrity_Backdoor_CUST {
    meta:
        description = "Detects the 'Security Sentinel' fake WordPress security plugin, which creates a hidden administrator account with hex-obfuscated credentials, hides that account from user lists/REST/counts, hides itself from the plugin list, and -- unlike earlier rogue-admin campaigns in this base -- actively blocks its own deactivation and deletion via wp_die() with a distinctive 'required by other plugins' cover message."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-08-17"
        hash = "61984b84344a6c94d80909740812431a5dc582f9fa0afb6e6a4020f49a753784"

    strings:
        $php = "<?php" ascii

        // Anti-removal cover message. On its own this is just English text a
        // legitimate plugin-dependency guard could plausibly also show, so the
        // condition below never accepts it alone -- it must co-occur with the
        // actual blocking mechanism or a malicious-account indicator.
        $deactivate_block = "Cannot Deactivate Plugin" ascii
        $delete_block = "Cannot Delete Plugin" ascii
        $shared_block_text = "cannot be deactivated or deleted until the plugins that require it are deactivated or deleted" ascii

        // The actual anti-removal mechanism: functions that wp_die()-block
        // deactivation/deletion, as opposed to the cover message alone
        $func_deactivation_msg = "function sys_integrity_deactivation_message()" ascii
        $func_deletion_msg = "function sys_integrity_deletion_message()" ascii
        $func_delete_plugin_msg = "function sys_integrity_delete_plugin()" ascii

        // Rogue admin creation with hex-obfuscated credential constants
        $create_user_call = "wp_create_user(SYS_INT_USER, SYS_INT_PASS, SYS_INT_EMAIL)" ascii
        $define_user = "define('SYS_INT_USER'" ascii
        $define_pass = "define('SYS_INT_PASS'" ascii

        // Function-name prefix shared by this family's hiding/persistence routines
        $func_ensure_user = "function sys_integrity_ensure_user()" ascii
        $func_hide_user = "function sys_integrity_hide_user(" ascii
        $func_hide_plugin_all = "function sys_integrity_hide_plugin_from_all(" ascii
        $func_check_integrity = "function sys_integrity_check_integrity()" ascii

        // CSS :has()-selector self-hiding from the plugin list (slug varies per
        // drop, so this is structural rather than a literal slug match)
        $css_hide_selector = /\.plugin-title:has\(a\[href\*="[^"]+"\]\)\s*\{/ ascii

    condition:
        filesize < 500KB and $php and
        (
            (
                (2 of ($deactivate_block, $delete_block, $shared_block_text))
                and
                (
                    1 of ($func_deactivation_msg, $func_deletion_msg, $func_delete_plugin_msg)
                    or
                    1 of ($create_user_call, $define_user, $define_pass, $func_ensure_user, $func_hide_user, $func_hide_plugin_all, $func_check_integrity)
                )
            )
            or
            ($create_user_call and 2 of ($func_ensure_user, $func_hide_user, $func_hide_plugin_all, $func_check_integrity))
            or
            ($css_hide_selector and ($define_user or $define_pass))
        )
}
