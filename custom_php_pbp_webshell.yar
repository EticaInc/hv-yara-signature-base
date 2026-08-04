rule PHP_PBP_WebShell_CUST
{
    meta:
        description = "Detects highly obfuscated polymorphic PBP web shells utilizing the _pbp and _sf classes"
        author = "Security Team"
        severity = "HIGH"
        date = "2026-03-30"
        hash = "custom-file-1-1772608429.php"
    strings:
        $php = "<?php" ascii
        $s1 = "class _pbp" ascii
        $s2 = "class _sf" ascii
        $s3 = "private $_uss;" ascii
        $s4 = "private $_kco = array();" ascii
        $s5 = "private $_qtc = array();" ascii
    condition:
        $php and filesize < 3MB and (3 of ($s*))
}
