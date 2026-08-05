rule PHP_Hex_Obfuscated_Persistence_Loader_CUST {
    meta:
        description = "Detects a self-healing PHP persistence loader disguised as a plugin asset (e.g. site.css). Deobfuscates its own strings through a hex2bin(self::$_ky[...]) lookup class, then AES-256-CBC decrypts (key/IV shipped in the same file) a further eval()'d payload. Forks/daemonizes via pcntl_fork or proc_open, installs a '* * * * *' cron job, and continuously re-writes/re-chmods its target file if its sha256 hash or permissions change, to survive manual cleanup."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-08-05"

    strings:
        $php = "<?php" ascii

        // Structural fingerprint of the string-deobfuscation engine: a private
        // static hex2bin(self::$array[$key]) accessor, lazily built by a second
        // private static method. Identifier names are randomized per build, so
        // this is written to survive renaming rather than matching literal names.
        $obfuscator_engine_generic = /class\s+_\w+\{private\s+static\$_\w+;public\s+static\s+function\s+_\w+\(\$_\w+\)\{if\(!self::\$_\w+\)self::_\w+\(\);return\s+hex2bin\(self::\$_\w+\[\$_\w+\]\);\}private\s+static\s+function\s+_\w+\(\)\{self::\$_\w+=array\(/ ascii

        // Secondary corroborating signal: the AES-encrypted-eval chain used to
        // unpack the next stage, present regardless of the engine's identifiers.
        $aes_cbc = "aes-256-cbc" ascii nocase
        $openssl_raw = "OPENSSL_RAW_DATA" ascii
        $openssl_decrypt = "openssl_decrypt(" ascii
        $hex2bin_call = "hex2bin(" ascii

        // Self-healing / daemonizing persistence behavior
        $cron_persist = "* * * * *" ascii
        $fork_daemon = "pcntl_fork" ascii
        $setsid = "posix_setsid" ascii

    condition:
        filesize < 3MB and $php and
        (
            $obfuscator_engine_generic
            or
            (
                $openssl_decrypt and $aes_cbc and $openssl_raw and $hex2bin_call and
                (1 of ($cron_persist, $fork_daemon, $setsid))
            )
        )
}
