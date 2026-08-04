rule PHP_SEO_Spam_Linkflow_CUST {
    meta:
        description = "Detects Advanced LinkFlow Control, an SEO redirect and link injection spam plugin."
        author = "Security Team"
        severity = "HIGH"
        date = "2026-06-07"
        hash = "d81d2e2e0a34a604b635ac6fefbd52c22ac2cebc84f7f356e8feaa66047c8460"
    strings:
        $php = "<?php" ascii
        $class = "class Advanced_LinkFlow_Control" ascii
        $obf_url = "\\x68\\x74\\x74\\x70:\\x2f/\\x73h\\x69z\\x61.\\x6ci\\x76e\\x2fg\\x65t\\x2ep\\x68p" ascii
        $cookie1 = "CURLOPT_LF_TEST" ascii
        $cookie2 = "LFD" ascii
        $testok = "XTESTOKX" ascii
        $offset_calc = "7200 + (strlen($html) % 1000)" ascii
    condition:
        filesize < 100KB and $php and $class and (2 of ($obf_url, $cookie1, $cookie2, $testok, $offset_calc))
}
