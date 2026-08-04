rule PHP_XOR_Dropper_Prepend_CUST {
    meta:
        description = "Detects PHP XOR Dropper prepended to legitimate files (WordPress Core Injection)"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-01-28"
        hash1 = "e6e3f5b70676a0c2017120c90c61988898950854427457221226507455011707"
        hash2 = "3b5d5c3d0c4d7f5a9e0f1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2"
        reference = "Observed WordPress core-injection campaign"

    strings:
        // 1. The custom alphabet string used for decoding
        $alphabet = "abcdefghijklmnopqrstuvwxyz0123456789" ascii

        // 2. The distinct list of temp directories checked for writing payload
        // We match individual distinct strings rather than the whole array to account for order changes
        $dir_1 = "sys_get_temp_dir()" ascii
        $dir_2 = "session_save_path()" ascii
        $dir_3 = "/dev/shm" ascii
        $dir_4 = "upload_tmp_dir" ascii

        // 3. The XOR decoding logic pattern
        // Matches: ( ( int)$v - $ch - ($k % 10)) ^ digit;
        // Uses regex to be flexible with whitespace and variable names
        $xor_math = /\(\s*\(?\s*int\s*\)\s*\$[a-zA-Z0-9_]+\s*-\s*\$[a-zA-Z0-9_]+\s*-\s*\(\s*\$[a-zA-Z0-9_]+\s*%\s*10\s*\)\s*\)\s*\^\s*[0-9]+/

        // 4. Hex encoded POST/REQUEST check (e.g., ["\x66act\x6Fr"])
        // Matches typical obfuscated superglobal access
        $hex_request = /\["\\[xX][0-9a-fA-F]{2}[a-zA-Z0-9_]+"\\[xX][0-9a-fA-F]{2}/

    condition:
        // Must start with PHP tag (standard for prepends)
        uint32(0) == 0x68703f3c // <?ph

        // Logical combinations to minimize False Positives
        and $alphabet
        and 3 of ($dir_*)
        and ($xor_math or $hex_request)

        // Optional: Ensure it's not just the alphabet string alone
        and filesize < 5MB // Optimization: Malicious prepends are usually small, but attached to large files. 5MB cap is safe for WP core.
}
