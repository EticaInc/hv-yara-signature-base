rule PHP_WP_Persistence_Guard_CUST {
    meta:
        description = "Detects WP plugin guard that hides must-use plugins and restores malware from .dat files."
        author = "Security Team"
        severity = "HIGH"
        date = "2026-03-25"
    strings:
        $php = "<?php" ascii

        $s1 = "plugin_status" ascii
        $s2 = "mustuse" ascii
        $s3 = ".subsubsub .mustuse{display:none!important}" ascii
        $s4 = "gzuncompress(" ascii
        $s5 = "base64_decode(" ascii
        $s6 = "WP_PLUGIN_DIR" ascii
        $s7 = "WPMU_PLUGIN_DIR" ascii
    condition:
        filesize < 3MB and $php and $s1 and $s2 and $s3 and $s4 and $s5 and $s6 and $s7
}
