/*
    Custom YARA Rules: Malicious JavaScript Redirects (AdsHouse)

    Refined to eliminate False Positives on base64 "emoji" strings found in
    legitimate sourcemaps (e.g., Yoast SEO, CSS).
*/

rule JS_AdsHouse_Redirect_Loader_CUST {
    meta:
        description = "Detects malicious JavaScript redirecting to ads-house.com using base64 obfuscation and evasion logic"
        author = "Security Team"
        severity = "HIGH"
        date = "2026-01-19"
        hash = "68c97..." // Representative hash of the logic structure

    strings:
        // High Confidence: The specific malicious domain in base64 ('/ads-house.com/')
        $b64_domain = "L2Fkcy1ob3VzZS5jb20v" ascii

        // Logic Sequence: The specific order of checks found in the malware (!isAdmin && !isLoggedIn && !isUserLanguage)
        $logic_seq = "!isA()&&!isL()&&!isU()" ascii

        // Cache Key Generation: Matches "wp-settings-" + atob('emoji')
        // Uses regex to handle potential quote variations (' or ")
        $cache_key_re = /wp-settings-['"]\+atob\(['"]ZW1vamk['"]\)/

        // Function Definitions: Specific signatures of the helper functions
        $func_isU = "function isU(){const a=navigator.language" ascii
        $func_isA = "function isA(){const a=['/wp-login.php'" ascii
        $func_isL = "function isL(){let a=!1;if(" ascii

    condition:
        filesize < 500KB and
        (
            // 1. Match the specific malicious domain
            $b64_domain

            or

            // 2. OR match the specific code structure (evasion logic AND (cache key OR helper functions))
            // This catches the malware even if they rotate the domain name.
            (
                $logic_seq and
                (
                    $cache_key_re or
                    $func_isU or
                    $func_isA or
                    $func_isL
                )
            )
        )
}
