rule PHP_Vim_Patior_Webshell_CUST {
    meta:
        description = "Detects Vim Patior PHP file-manager webshell variants with hex-encoded filesystem APIs"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-09-02"
        hash = "28ac6741c662840e7c97efe52fdd2b2c7b1e89272dbb8811e00aa643d4d16c59"
    strings:
        $php = "<?php" ascii
        $family = "Vim Patior" ascii
        $hex_uname = "7068705f756e616d65" ascii
        $hex_getcwd = "676574637764" ascii
        $hex_file_get = "66696c655f6765745f636f6e74656e7473" ascii
        $hex_file_put = "66696c655f7075745f636f6e74656e7473" ascii
        $hex_rename = "72656e616d65" ascii
    condition:
        filesize < 100KB and $php and $family and 3 of ($hex_*)
}
