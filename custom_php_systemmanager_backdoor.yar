rule PHP_SystemManager_Backdoor_CUST {
    meta:
        description = "Detects SystemManager PHP backdoor that reconstructs function names using arithmetic arrays and executes payloads from a temp file."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-06-07"
        hash = "00e931efb5ebc5f8fa0bc07d64c0761d85e50ddae3a5e99b97f116565ccc0cc2"
    strings:
        $php = "<?php" ascii
        $class = "class SystemManager" ascii
        $calc1 = "array((106-5)" ascii
        $calc2 = "array((103*1)" ascii
        $calc3 = "array(((80+30))" ascii
        $calc4 = "array((89+12)" ascii
        $calc5 = "array(((2*51))" ascii
        $temp_file = "is-6819785ee297c" ascii
    condition:
        filesize < 50KB and $php and $class and (any of ($calc1, $calc2, $calc3, $calc4, $calc5) or $temp_file)
}
