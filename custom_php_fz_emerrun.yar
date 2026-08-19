/*
 * Detection rules for the FZ_EmerRun WordPress attack toolkit.
 *
 * The toolkit creates a hidden administrator, installs an obfuscated user
 * hider and magic-login backdoor as MU plugins, and persists its state in
 * WordPress options. The decoded rules cover an unpacked copy of either
 * generated MU-plugin payload.
 */

rule PHP_FZ_EmerRun_Dropper_CUST
{
    meta:
        description = "Detects the FZ_EmerRun WordPress hidden-admin and magic-login MU-plugin dropper"
        author = "Security Team"
        family = "FZ_EmerRun"
        severity = "CRITICAL"
        date = "2026-08-19"
        hash = "ed00234ad2b67dbbc9073e8c711b18b7d39e0a5255b6159189f75cf2ed99cfb9"

    strings:
        $php = "<?php" ascii

        // Family and persistence identifiers.
        $class = /class\s+FZ_EmerRun\b/ ascii
        $option_tokens = "fz_emer_login_tokens" ascii
        $option_done = "fz_emer_done_v1" ascii
        $login_parameter = "_wplogin" ascii
        $mu_magic = "class-wp-token-validate.php" ascii
        $mu_hider = "class-wp-query-" ascii

        // Dropper workflow identifiers.
        $fn_create_admin = "createHiddenAdmin" ascii
        $fn_create_magic = "createMagicUrl" ascii
        $fn_inject_hider = "injectHiddenMu" ascii
        $fn_inject_magic = "injectMagicMu" ascii
        $fn_rollback = "rollbackHiddenUser" ascii
        $fn_cached_state = "getValidCachedDone" ascii
        $create_user = "wp_create_user(" ascii
        $set_admin_role = /set_role\s*\(\s*['"]administrator['"]\s*\)/ ascii

    condition:
        filesize < 200KB and
        $php and
        (
            ($class and 2 of ($fn_*)) or
            ($option_tokens and $option_done and $login_parameter and 1 of ($mu_*)) or
            ($create_user and $set_admin_role and 3 of ($fn_*) and 1 of ($mu_*))
        )
}

rule PHP_FZ_EmerRun_Obfuscated_MU_Loader_CUST
{
    meta:
        description = "Detects the FZ_EmerRun XOR and raw-DEFLATE loader used by its generated MU plugins"
        author = "Security Team"
        family = "FZ_EmerRun"
        severity = "CRITICAL"
        date = "2026-08-19"
        hash = "191441486d0d627e09455a224f29c6ed4e66fd463dec51a4fd3387c0a8f26c60"
        hash2 = "f4229b3a03b3774755228afebf7e53d9274a8ab1ffaa21848e580a653378e20d"

    strings:
        $php = "<?php" ascii
        $guard = /if\s*\(\s*!\s*defined\s*\(\s*['"]ABSPATH['"]\s*\)\s*\)\s*return\s*;/ ascii
        $split_gzinflate = /call_user_func\s*\(\s*['"]gz['"]\s*\.\s*['"]inflate['"]/ ascii
        $xor_function = /function\s*\(\s*\$[a-zA-Z_]\w*\s*,\s*\$[a-zA-Z_]\w*\s*\)\s*\{\s*\$[a-zA-Z_]\w*\s*=\s*['"]{2}\s*;/ ascii
        $xor_bytes = /chr\s*\(\s*ord\s*\(\s*\$[a-zA-Z_]\w*\[\$[a-zA-Z_]\w*\]\s*\)\s*\^\s*ord/ ascii
        $key_chain = /(chr\s*\(\s*\d{1,3}\s*\)\s*\.\s*){4,}chr\s*\(\s*\d{1,3}\s*\)/ ascii
        $packed_payload = /pack\s*\(\s*['"]C\*['"]\s*,/ ascii
        $eval_decoded = /eval\s*\(\s*\$[a-zA-Z_]\w*\s*\)\s*;/ ascii

    condition:
        filesize < 20KB and
        $php and
        $guard and
        $split_gzinflate and
        $packed_payload and
        $eval_decoded and
        ($xor_function or ($xor_bytes and $key_chain))
}

rule PHP_FZ_EmerRun_User_Hider_Decoded_CUST
{
    meta:
        description = "Detects the decoded FZ_EmerRun MU-plugin payload that hides a rogue WordPress user from administrator listings"
        author = "Security Team"
        family = "FZ_EmerRun"
        severity = "CRITICAL"
        date = "2026-08-19"
        hash = "0a356faba51d5b26ad45ec9047fcb18b7b696b545d3e8cb9a977d646584209bf"
        hash_scope = "SHA-256 of decoded payload before a PHP opening tag is added"
        source_hash = "191441486d0d627e09455a224f29c6ed4e66fd463dec51a4fd3387c0a8f26c60"

    strings:
        $php = "<?php" ascii
        $hook_pre_user = /add_action\s*\(\s*['"]pre_user_query['"]/ ascii
        $hook_query_args = /add_filter\s*\(\s*['"]users_list_table_query_args['"]/ ascii
        $hook_views = /add_filter\s*\(\s*['"]views_users['"]/ ascii
        $sql_exclusion = /query_where\s*\.\=\s*['"][^\r\n]{0,160}user_login\s*!=\s*['"]/ ascii
        $not_in_key = "login__not_in" ascii
        $not_in_append = /login__not_in['"]\s*\]\s*\[\s*\]\s*=\s*['"]/ ascii

    condition:
        filesize < 10KB and
        $php and
        $hook_pre_user and
        $hook_query_args and
        $hook_views and
        $sql_exclusion and
        $not_in_key and
        $not_in_append
}

rule PHP_FZ_EmerRun_Magic_Login_Decoded_CUST
{
    meta:
        description = "Detects the decoded FZ_EmerRun MU-plugin payload that exchanges a URL token for a WordPress administrator session"
        author = "Security Team"
        family = "FZ_EmerRun"
        severity = "CRITICAL"
        date = "2026-08-19"
        hash = "aa57c1b87494ebad1261b9ab331575cf8a4f0988a431a86084bff52c1a03878e"
        hash_scope = "SHA-256 of decoded payload before a PHP opening tag is added"
        source_hash = "f4229b3a03b3774755228afebf7e53d9274a8ab1ffaa21848e580a653378e20d"

    strings:
        $php = "<?php" ascii
        $hook_init = /add_action\s*\(\s*['"]init['"]/ ascii
        $login_parameter = /\$_GET\s*\[\s*['"]_wplogin['"]\s*\]/ ascii
        $token_option = "fz_emer_login_tokens" ascii
        $set_current_user = "wp_set_current_user(" ascii
        $set_auth_cookie = "wp_set_auth_cookie(" ascii
        $clear_auth_cookie = "wp_clear_auth_cookie(" ascii

    condition:
        filesize < 10KB and
        $php and
        $hook_init and
        $login_parameter and
        $token_option and
        $set_auth_cookie and
        1 of ($set_current_user, $clear_auth_cookie)
}
