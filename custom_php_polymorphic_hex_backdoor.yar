rule PHP_Polymorphic_Hex_Backdoor_CUST {
    meta:
        description = "Detects polymorphic PHP backdoor utilizing rot13 encoded function names and hex packed strings for execution"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-03-12"
        hash = "bdc3d36aac3b7116f199706598ff089fae3bff4635226c5e17c326e2295e0a33"

    strings:
        // Core obfuscation technique
        $str_rot13_func = "str_rot13"

        // Rot13 encoded common PHP functions seen in this family
        $r_pack = "'cnpx'" ascii // pack
        $r_b64decode = "'onfr64_qrpbqr'" ascii // base64_decode

        // Hex encoded string payload construction
        // Regex matches the pattern ($var("H*", "hexstring"))
        $hex_pack_pattern = /\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\(\s*['"]H\*['"]\s*,\s*['"][0-9a-fA-F]{10,}/

        $req1 = "$_COOKIE" ascii
        $req2 = "$_POST" ascii

    condition:
        filesize < 100KB and
        (
            $str_rot13_func and
            ($r_pack or $r_b64decode) and
            $hex_pack_pattern and
            (any of ($req*))
        )
}
