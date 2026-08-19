/*
 * Detection for the malicious WP Smart Thumbnails plugin masquerading as a
 * media utility while providing authentication bypass, command execution,
 * and arbitrary filesystem access.
 */

rule PHP_WP_Smart_Thumbnails_Webshell_CUST
{
    meta:
        description = "Detects the malicious WP Smart Thumbnails plugin webshell with administrator impersonation and filesystem access"
        author = "Security Team"
        family = "WP_Smart_Thumbnails_Webshell"
        severity = "CRITICAL"
        date = "2026-08-19"
        hash = "a6830e3624c83fbe62634503a674387c473a7d29368dc6e7964f2690ef3ade36"

    strings:
        $php = "<?php" ascii
        $class = "WP_Smart_Thumbnails_Health" ascii
        $auth_namespace = "_wpsth_auth" ascii

        // Campaign-specific request parameters.
        $param_key = "_wpsth_key" ascii
        $param_command = "_wpsth_cmd" ascii
        $param_write_path = "_wpsth_wpath" ascii
        $param_read_path = "_wpsth_read" ascii
        $param_list_path = "_wpsth_ls" ascii

        // Authentication bypass and webshell capabilities.
        $set_current_user = "wp_set_current_user(" ascii
        $set_auth_cookie = "wp_set_auth_cookie(" ascii
        $behavior_file_write = "file_put_contents(" ascii
        $behavior_file_read = "file_get_contents(" ascii
        $behavior_directory_list = "scandir(" ascii
        $behavior_shell_exec = "shell_exec" ascii
        $behavior_proc_open = "proc_open" ascii

    condition:
        filesize < 500KB and
        $php and
        (
            ($class and $auth_namespace and 2 of ($param_*)) or
            ($auth_namespace and $param_key and $set_current_user and $set_auth_cookie) or
            (3 of ($param_*) and $set_auth_cookie and 2 of ($behavior_*))
        )
}
