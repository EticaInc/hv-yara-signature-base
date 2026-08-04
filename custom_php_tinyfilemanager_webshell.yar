rule PHP_TinyFileManager_Webshell_CUST {
    meta:
        description = "Detects Tiny File Manager v2.x deployed as a webshell in WordPress plugin directories. Legitimate software repurposed as a backdoor - provides full filesystem access with hardcoded credentials."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-06-20"
        reference = "Observed Tiny File Manager webshell deployment"
        hash = "7adc00cee55965872d3a0e7ddbce32e8"

    strings:
        $php = "<?php" ascii

        // Unique application identifiers
        $tfm_name = "Tiny File Manager" ascii nocase
        $tfm_author = "H3K" ascii
        $tfm_github = "tinyfilemanager.github.io" ascii
        $tfm_session = "FM_SESSION_ID" ascii

        // Hardcoded credential structure
        $auth_users = "$auth_users" ascii
        $password_verify = "password_verify" ascii

        // Filesystem manipulation capabilities
        $fm_root_path = "FM_ROOT_PATH" ascii
        $fm_readonly = "FM_READONLY" ascii

        // Dangerous operations
        $file_delete = "fm_rdelete" ascii
        $file_copy = "fm_rcopy" ascii
        $file_rename = "fm_rename" ascii

    condition:
        filesize < 500KB and $php and (
            // High confidence: TFM identity strings
            ($tfm_name and ($tfm_author or $tfm_github)) or
            // High confidence: TFM session + auth + filesystem ops
            ($tfm_session and $auth_users and $password_verify) or
            // Medium confidence: TFM filesystem constants + dangerous ops
            ($fm_root_path and $fm_readonly and 2 of ($file_delete, $file_copy, $file_rename))
        )
}
