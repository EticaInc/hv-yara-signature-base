rule PHP_Woocommerce_TAG_Backdoor_CUST
{
    meta:
        description = "Detects malicious Woocommerce Custom TAG plugin doing data exfiltration and IP tracking"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-03-30"
    strings:
        $php = "<?php" ascii
        $s1 = "Plugin Name: Woocommerce custom TAG" ascii
        $s2 = "public function hide_plugin_from_list" ascii
        $s3 = "public function sendUserData" ascii
        $s4 = "$wpdb->prefix . 'ip_tracking'" ascii
        $s5 = "/wp-plugin/?update-check-th&webID=" ascii
    condition:
        $php at 0 and filesize < 3MB and ($s1 or (3 of ($s2, $s3, $s4, $s5)))
}
