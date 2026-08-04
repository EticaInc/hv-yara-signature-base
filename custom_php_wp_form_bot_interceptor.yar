rule PHP_WP_Form_Bot_Interceptor_CUST
{
    meta:
        description = "Detects malicious SEO spam / bot interception plugins manipulating search engine crawlers"
        author = "Security Team"
        severity = "HIGH"
        date = "2026-03-30"
        hash = "wp-form-new-v-2026.php"
    strings:
        $php = "<?php" ascii
        $s1 = "IVQ_MASTER_KEY" ascii
        $s2 = "IVQ_API_BASE" ascii
        $s3 = "IVQ_OPTION_TOKEN" ascii
        $s4 = "IVQ_RDNS_DOMAINS" ascii
    condition:
        $php at 0 and filesize < 3MB and (any of ($s*))
}
