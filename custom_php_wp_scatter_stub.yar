rule PHP_WP_Scatter_Stub_CUST {
    meta:
        description = "Detects scatter stub droppers that recreate session managers or inject backdoors into WP login."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-03-25"
    strings:
        $php = "<?php" ascii

        // Payload for backdoor injection (base64 of the injected string portion)
        $payload1 = "Ci8vIFdvcmRQcmVzcyBTZXNzaW9uIENhY2hlIEhhbmRsZXIKaW" ascii

        $s1 = "_wph" ascii
        $s2 = "$_POST[\"c\"]" ascii
        $s3 = "tempnam(sys_get_temp_dir()" ascii
        $s5 = "echo json_encode([" ascii

        // Database user insertion backdoor
        $s6 = "update_user_meta(" ascii
        $s7 = "[\"administrator\"=>true]" ascii
    condition:
        filesize < 3MB and $php and $s1 and $s2 and $s3 and $s5 and ($payload1 or ($s6 and $s7))
}
