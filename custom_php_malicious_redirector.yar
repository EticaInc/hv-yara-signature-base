rule PHP_FakePlugin_Redirector_CUST {
    meta:
        description = "Detects a fake WordPress plugin that clears caches and injects a heavily obfuscated malicious redirect script (datadock.info)."
        author = "Security Team"
        severity = "HIGH"
        date = "2026-03-12"
        hash = "e80ae1f2dbd27a8db360561f2d4b108c5cf61c01db1c76018bbca464a36c9f99"
    strings:
        $php = "<?php" ascii
        // The hex-encoded payload URL
        $url_hex = "\\x68\\x74\\x74\\x70\\x73:\\x2f\\x2f\\x64\\x61t\\x61\\x64\\x6f\\x63k\\x2e\\x69\\x6e\\x66o\\x2f\\x70\\x6c\\x67" ascii
        // Specific class, cookie, and method names used by this malware
        $cookie = "http2_session_id" ascii
        $class_name = "HTTP2_FORWARDED_FOR" ascii
        $func = "print_partner_script" ascii
    condition:
        filesize < 200KB and $php and ($url_hex or ($cookie and $class_name and $func))
}
