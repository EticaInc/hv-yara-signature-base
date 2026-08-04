rule custom_php_wp_aedoodnemi_dropper_CUST {
    meta:
        description = "Detects WordPress dropper and webshell component using rot13 C2 domain"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-03-04"

    strings:
        // C2 domain obfuscated with rot13
        $c2_rot13 = "ncv.nrqbbqnrmv.sha"

        // Specific trigger parameters
        $get_param1 = "'cuquoo'"
        $get_param2 = "'web'"

        // Webshell UI element
        $form_html = "<input type=\"hidden\" name=\"path\" value=\"$path/$file\">"

    condition:
        $c2_rot13 or ($get_param1 and $get_param2 and $form_html)
}

rule custom_php_wp_aedoodnemi_backdoor_CUST {
    meta:
        description = "Detects persistent WordPress backdoor modifying header.php"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-03-04"

    strings:
        // Hardcoded backdoor hash/password
        $hardcoded_pass = "Zgc5c4MXrK42MQ4F8YpQL/+fflvUNPlfnyDNGK/X/wEfeQ=="

        // Base64 decoding obfuscation routine
        $obf_str1 = "$ea = '_shaesx_';"
        $obf_str2 = "str_replace('_sha', 'bas', $ea);"

        // Custom decryption function
        $func_name = "function wp_cd("

    condition:
        $hardcoded_pass and (1 of ($obf_str*) or $func_name)
}
