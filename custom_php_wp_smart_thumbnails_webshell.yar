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

// Advisory-based coverage: the published hash identifies the packed stage.
rule PHP_WP_Smart_Thumbnails_Packed_Dropper_CUST
{
    meta:
        description = "Detects the packed WP Smart Thumbnails dropper using an inverted WordPress guard and custom stream-wrapper execution"
        author = "Security Team"
        family = "WP_Smart_Thumbnails_Webshell"
        severity = "CRITICAL"
        date = "2026-10-25"
        hash = "ccc95113334357c2a3671aae12043bff00020858cec115f7e724fe43e9f1fc24"
        reference = "https://patchstack.com/articles/four-ways-back-in-the-wordpress-xss-campaign-that-hides-its-own-admin-account/"

    strings:
        $php = "<?php" ascii
        $guard = /\bif\s*\(\s*defined\s*\(\s*['"]ABSPATH['"]\s*\)\s*\)\s*\{\s*return\s*;\s*\}/ ascii
        $comment = "WP plugin load: do not run shell" ascii
        $plugin_name = "WP Smart Thumbnails" ascii
        $plugin_author = "MediaPress Labs" ascii
        $stream_uri = "dyiv://" ascii
        $stream_register = "stream_wrapper_register" ascii fullword

        // Transform names inferred from the advisory's decoding description.
        // MD5 is an integrity check, not a decoding operation.
        $decode_base64 = "base64_decode" ascii fullword
        $decode_uncompress = "gzuncompress" ascii fullword
        $decode_rot13 = "str_rot13" ascii fullword
        $decode_reverse = "strrev" ascii fullword

    condition:
        filesize < 100KB and
        $php and
        (
            ($stream_uri and $stream_register and $decode_uncompress) or
            ($guard and $comment) or
            ($guard and $plugin_name and $plugin_author and 2 of ($decode_*)) or
            ($guard and $stream_register and $decode_uncompress and $decode_rot13 and $decode_reverse)
        )
}

// Covers PHP-tagged unpacked copies; the advisory provides no unpacked hash.
rule PHP_WP_Smart_Thumbnails_Moon_FileManager_CUST
{
    meta:
        description = "Detects the unpacked WP Smart Thumbnails unauthenticated Moon file manager with JSON file-operation actions"
        author = "Security Team"
        family = "WP_Smart_Thumbnails_Webshell"
        severity = "CRITICAL"
        date = "2026-10-25"
        source_hash = "ccc95113334357c2a3671aae12043bff00020858cec115f7e724fe43e9f1fc24"
        reference = "https://patchstack.com/articles/four-ways-back-in-the-wordpress-xss-campaign-that-hides-its-own-admin-account/"

    strings:
        $php = "<?php" ascii
        $title = "Moon, tell me if I could" ascii
        $action_upload = "upload" ascii fullword
        $action_delete = "delete" ascii fullword
        $action_rename = "rename" ascii fullword
        $action_mkdir = "mkdir" ascii fullword
        $action_save = "save" ascii fullword

    condition:
        filesize < 150KB and
        $php and
        $title and
        3 of ($action_*)
}
