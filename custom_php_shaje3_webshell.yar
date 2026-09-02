rule PHP_Shaje3_Webshell_CUST {
    meta:
        description = "Detects the Shaje3 Yemeni hacker PHP webshell family"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-09-02"
        hash = "fb989ab97d47709a1b59d69705ca02e0d13ec99ac1e78e816410bce55fb49b0e"
    strings:
        $php = "<?php" ascii
        $family = "shaje3 <<YeMeNi HaCkeR>>" ascii
        $site = "www.shaja.net" ascii
        $decode = "eval(\"?>\".gzuncompress(base64_decode(" ascii
    condition:
        filesize < 100KB and $php and $family and $site and $decode
}
