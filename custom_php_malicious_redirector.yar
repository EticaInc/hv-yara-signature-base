rule PHP_FakePlugin_Redirector_CUST {
    meta:
        description = "Detects the HTTP2_FORWARDED_FOR fake WordPress plugin campaign that hides itself and hijacks front-end traffic to a hex-obfuscated partner URL. Known variants use datadock.info or saraviadorablogport.com."
        author = "Security Team"
        severity = "HIGH"
        date = "2026-03-12"
        hash = "e80ae1f2dbd27a8db360561f2d4b108c5cf61c01db1c76018bbca464a36c9f99"
        hash2 = "6f1b7f4b21b806952429e6d53eea9d7119627f6da42279b69a962d58a9fb0914"
    strings:
        $php = "<?php" ascii
        // The hex-encoded payload URL used by the datadock.info variant
        $url_hex = "\\x68\\x74\\x74\\x70\\x73:\\x2f\\x2f\\x64\\x61t\\x61\\x64\\x6f\\x63k\\x2e\\x69\\x6e\\x66o\\x2f\\x70\\x6c\\x67" ascii
        // Specific class, cookie, and method names shared by known variants
        $cookie = "http2_session_id" ascii
        $class_name = "HTTP2_FORWARDED_FOR" ascii
        $func = "print_partner_script" ascii
        $func2 = "has_partner_content" ascii
        // Structural fingerprint for future variants with a rotated, fully
        // hex-obfuscated partner URL. Only trust it with campaign fingerprints.
        $hex_obfuscated_url_generic = /\$\w+\s*=\s*"(\\x[0-9a-fA-F]{2}){15,}"/ ascii
    condition:
        filesize < 200KB and $php and
        (
            $url_hex
            or
            (($cookie or $class_name) and $hex_obfuscated_url_generic)
            or
            ($cookie and $class_name and ($func or $func2))
        )
}
