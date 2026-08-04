/*
    Custom YARA Rules: PHP Backdoors & Webshells
*/
rule PHP_Obfuscated_O00_Backdoor_CUST {
    meta:
        description = "Detects obfuscated PHP backdoor using O00O0O variable naming and specific 'act' parameters"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2024-05-22"
        hash = "class-wp-rest-servers.php sample"
    strings:
        // Variable pattern: $O00O0O, $OO0000 etc.
        $var_pattern = /\$[O0]{4,6} =/

        // Specific function definition found in sample
        $func_rand = "function RandAbc($length = \"\")"

        // The alphabet used in the RandAbc function
        $alphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_.:/-"

        // Specific action handlers in the webshell
        $act_recover = "$act == 'recover' && isset($recover_file)"
        $act_redate = "$act == 'redate' && isset($redate_file)"

        // Fake 404 header often used to hide the shell
        $fake_404 = "header(\"HTTP/1.1 404 Not Found\");"
    condition:
        filesize < 200KB and
        (
            $func_rand or
            (2 of ($act_*) and $fake_404) or
            ($var_pattern and $alphabet)
        )
}
