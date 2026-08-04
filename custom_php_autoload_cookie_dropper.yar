/*
    Custom YARA Rule: PHP Autoload Cookie Dropper
    Detects PHP backdoors that abuse spl_autoload_register/unregister
    to execute payloads delivered via cookies through temp file drop.

    Technique:
    - Registers a function as a PHP autoloader
    - Decodes payload from cookies using str_rot13 + base64_decode
    - Writes decoded PHP payload to a temp file (tempnam)
    - Requires the temp file to execute the payload
    - Immediately deletes the temp file to cover tracks
    - Triggers the autoloader via class_parents() on a fake class
*/
rule PHP_Autoload_Cookie_Dropper_CUST {
    meta:
        description = "Detects PHP backdoors abusing spl_autoload_register to execute cookie-delivered payloads via temp file droppers with rot13+base64 decoding"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-06-24"
        hash = "422771ad7161b76155317080e95319ba156ba03863ed68a26ba68845babc9ead"

    strings:
        // File type constraint - PHP opening tag
        $php = "<?php" ascii

        // 1. Core technique: autoload abuse for code execution
        $autoload_reg = "spl_autoload_register" ascii
        $autoload_unreg = "spl_autoload_unregister" ascii

        // 2. Cookie-based payload source with arithmetic index obfuscation
        // Matches patterns like $_COOKIE[53+-53], $_COOKIE[19-18], etc.
        $cookie_arith = /\$_COOKIE\[\s*-?\d+\s*[\+\-]\s*-?\d+\s*\]/ ascii

        // 3. Double-decode chain: rot13 wrapped in base64_decode from cookie
        $decode_chain = /base64_decode\s*\(\s*str_rot13\s*\(\s*\$/ ascii

        // 4. Temp file dropper infrastructure
        $tempnam = "tempnam(" ascii
        $session_path = "session_save_path()" ascii

        // 5. Hex-escaped PHP tag construction for payload
        // \x3c\x3f\x70\x68p = <?php
        $hex_php_tag = "\\x3c\\x3f\\x70\\x68" ascii

        // 6. Write-execute-delete pattern (cleanup after require_once execution)
        $cleanup = /array_map\s*\(\s*'unlink'/ ascii

        // 7. Trigger mechanism: class_parents on non-existent class
        $trigger = /class_parents\s*\(/ ascii

    condition:
        filesize < 3MB and
        $php and
        $autoload_reg and
        (
            // Strong detection: autoload pair + decode chain + cookie arithmetic
            (
                $autoload_unreg and
                $decode_chain and
                $cookie_arith
            )
            or
            // Alternative: autoload + hex PHP tag + temp dropper + cleanup
            (
                $hex_php_tag and
                $tempnam and
                $cleanup
            )
            or
            // Alternative: autoload + decode chain + trigger mechanism + temp dropper
            (
                $decode_chain and
                $trigger and
                ($tempnam or $session_path)
            )
        )
}
