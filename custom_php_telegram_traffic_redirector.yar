rule PHP_Telegram_Traffic_Redirector_CUST {
    meta:
        description = "Detects a PHP traffic hijacker that fetches redirect URLs from Telegram channels or fallback C2 domains, then injects JavaScript to redirect visitors. Uses chr() array obfuscation and base64-encoded JS fragments."
        author = "Security Team"
        severity = "HIGH"
        date = "2026-06-20"
        reference = "Observed malicious WordPress traffic-redirect campaign"
        hash = "9643e91365e45739fa28d382ef236689"

    strings:
        $php = "<?php" ascii

        // Base64-encoded JavaScript redirect fragments (unique to this family)
        $b64_location_replace = "PHNjcmlwdD4gd2luZG93LmxvY2F0aW9uLnJlcGxhY2U" ascii
        $b64_location_href = "d2luZG93LmxvY2F0aW9uLmhyZWY" ascii
        $b64_script_close = "PC9zY3JpcHQ+" ascii

        // Cookie-based visitor tracking (redirects once per 24h)
        $cookie_partner = "partner_" ascii

        // Telegram channel scraping pattern (fetches C2 URLs from <code> blocks)
        $telegram_scrape = /preg_match_all\s*\(\s*['"]\/<code>/ ascii

        // chr() array-to-string conversion function (obfuscation engine)
        $chr_builder = /\.=\s*chr\s*\(\s*\$/ ascii

        // Disable SSL verification for C2 calls
        $ssl_bypass = "CURLOPT_SSL_VERIFYPEER, 0" ascii

        // Cache file with base64 domain storage
        $cache_b64 = /file_put_contents\s*\(\s*\$[^,]+,\s*base64_encode\s*\(/ ascii

    condition:
        filesize < 50KB and $php and (
            // High confidence: base64 JS redirect fragments
            (2 of ($b64_location_replace, $b64_location_href, $b64_script_close)) or
            // Medium confidence: Telegram scraping + cookie tracking
            ($telegram_scrape and $cookie_partner) or
            // Medium confidence: chr() obfuscation + SSL bypass + cache
            ($chr_builder and $ssl_bypass and $cache_b64)
        )
}
