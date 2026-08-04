rule PHP_WP_Aedoodnemi_Dropper_CUST {
    meta:
        description = "Detects WordPress dropper and webshell component using rot13 C2 domains used by the Aedoodnemi campaign."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-03-04"

    strings:
        $php = "<?php" ascii

        // C2 domains obfuscated with rot13
        $c2_rot13_1 = "ncv.nrqbbqnrmv.sha"
        $c2_rot13_2 = "ncv.xhgbgb.fof"

        // Specific trigger parameters
        $get_param1 = "'cuquoo'"
        $get_param2 = "'web'"

        // Webshell UI element
        $form_html = "<input type=\"hidden\" name=\"path\" value=\"$path/$file\">"

    condition:
        filesize < 3MB and $php and
        (1 of ($c2_rot13_*) or ($get_param1 and $get_param2 and $form_html))
}

rule PHP_WP_Aedoodnemi_Backdoor_CUST {
    meta:
        description = "Detects persistent WordPress backdoors sharing the Aedoodnemi campaign's hardcoded password hash, including header.php and theme functions.php variants."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-03-04"

    strings:
        $php = "<?php" ascii

        // Hardcoded backdoor hash/password
        $hardcoded_pass = "Zgc5c4MXrK42MQ4F8YpQL/+fflvUNPlfnyDNGK/X/wEfeQ=="

        // Base64 decoding obfuscation routine
        $obf_str1 = "$ea = '_shaesx_';"
        $obf_str2 = "str_replace('_sha', 'bas', $ea);"

        // Custom decryption function
        $func_name = "function wp_cd("

        // Infection marker searched for or injected into theme functions.php
        $functions_marker = "$algo = \\'default\\'; $pass ="

    condition:
        filesize < 3MB and $php and
        $hardcoded_pass and (1 of ($obf_str*) or $func_name or $functions_marker)
}
