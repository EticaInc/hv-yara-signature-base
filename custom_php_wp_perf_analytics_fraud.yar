rule PHP_WP_Perf_Analytics_Fraud_CUST {
    meta:
        description = "Detects a fake WP Performance Analytics plugin that injects XOR-obfuscated JavaScript into WP footers"
        author = "Security Team"
        severity = "HIGH"
        date = "2026-03-29"
        hash = "PENDING"

    strings:
        // Magic header for PHP files
        $php = "<?php" ascii

        // File characteristics & weak indicators
        $s1 = "Plugin Name: WP Performance Analytics" ascii nocase
        $s2 = "wp-perf-analytics" ascii

        // Evasion checks
        $ev1 = "/bot|crawl|spider|lighthouse|pagespeed" ascii
        $ev2 = "_cf_verified" ascii
        $ev3 = "_wp_perf_ok" ascii

        // JavaScript Decryption & Obfuscation Routine
        $js1 = "atob(d)" ascii
        $js2 = "charCodeAt(i)^k" ascii
        $js3 = "new Uint8Array(s.length)" ascii
        $js4 = "String.fromCharCode" ascii

    condition:
        filesize < 3MB
        and $php at 0
        and (
            ($s1 and $s2)
            or ($ev2 and $ev3)
            or ($js1 and $js2 and $js3 and $js4)
            or ($ev1 and $js2)
        )
}
