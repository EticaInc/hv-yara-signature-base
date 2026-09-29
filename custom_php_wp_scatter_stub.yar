rule PHP_WP_Scatter_Stub_CUST {
    meta:
        description = "Detects the scatter stub dropper family that plants identical request-gated stubs across theme, plugin and mu-plugin directories. Covers the original build (session-cache handler injection) and the v2 '_wpv' mode dispatcher: mode 'p' writes attacker POST data to a temp file and includes it, mode 'r' rebuilds the mu-plugins RAT from a base64 blob stored in a WordPress option, mode 'h' inserts or hijacks an administrator directly in wp_users, mode 'a' mints an HMAC-signed one-shot admin login, and mode 'u' overwrites the stub with new code. Both single-quoted and double-quoted PHP array builds, and short ($_root/$_m) and WP-camouflage ($_wp11cb/$__opt_61b9) identifier styles, are in scope. Companion to PHP_WP_WPM_MuPlugin_RAT_CUST, which covers the large mu-plugin payload this stub restores; this rule covers only the small scattered stubs."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-03-25"
        hash = "de8718f85084832dbb9711c018cd43e4e2171de8c1e89870c10c3af328910b86"
        hash = "63018bb2e35626c4beb46fedaea9f7199fe9de6a0ccd64c61706cdd776903ece"
    strings:
        $php = "<?php" ascii

        // --- v1 identity: payload for backdoor injection (base64 of the injected string portion)
        $payload1 = "Ci8vIFdvcmRQcmVzcyBTZXNzaW9uIENhY2hlIEhhbmRsZXIKaW" ascii

        $s1 = "_wph" ascii
        $s2 = "$_POST[\"c\"]" ascii
        $s3 = "tempnam(sys_get_temp_dir()" ascii
        $s5 = "echo json_encode([" ascii

        // Database user insertion backdoor
        $s6 = "update_user_meta(" ascii
        $s7 = "[\"administrator\"=>true]" ascii

        // --- v2 identity: request gate token and the mode 's' self-identifying ping
        $v2_secret  = "a3f8b2c1d4e5f607" ascii
        $v2_gate    = "_wpv" ascii
        $v2_scatter = "'scatter'=>true" ascii

        // --- Behavioral: fixed WordPress/PHP API surface only, so a full rename of the
        //     campaign's own identifiers, option keys and gate token does not evade it.
        $b_cookie = "wp_set_auth_cookie(" ascii
        $b_hmac   = "hash_equals(" ascii
        $b_users  = "$wpdb->users" ascii
        $b_admin  = /['"]administrator['"]\s*=>\s*true/ ascii
    condition:
        filesize < 3MB and $php and
        (
            // v1 build. Bound left at 3MB so already-deployed detections are unchanged.
            (filesize < 3MB and $s1 and $s2 and $s3 and $s5 and ($payload1 or ($s6 and $s7)))
            or
            // v2 build, by identity. The scattered stubs are ~4KB by design; the 64KB bound
            // keeps this branch off the 185KB mu-plugin RAT, which embeds a copy of this
            // stub's source in order to re-scatter it and is attributed by
            // PHP_WP_WPM_MuPlugin_RAT_CUST instead. Without the bound one infected file
            // raises two dashboard events.
            (filesize < 64KB and all of ($v2_*))
            or
            // Rename-resistant: request-driven code include, forged admin session and a
            // direct wp_users write in one unauthenticated stub-sized file.
            (filesize < 64KB and $s3 and $b_cookie and $b_hmac and $b_users and $b_admin)
        )
}
