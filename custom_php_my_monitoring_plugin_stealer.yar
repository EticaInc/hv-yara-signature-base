rule PHP_My_Monitoring_Plugin_Stealer_CUST
{
    meta:
        description = "Detects malicious monitoring plugin that exfiltrates passwords and .env files"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-03-30"
    strings:
        $php = "<?php" ascii
        $s1 = "Plugin Name: My Monitoring Plugin" ascii
        $s2 = "add_action('my_monitoring_cron', array($this, 'send_data_to_mongodb'));" ascii
        $s3 = "Отправляет данные сайта в центральную MongoDB" ascii wide
    condition:
        $php at 0 and filesize < 3MB and 2 of ($s1, $s2, $s3)
}
