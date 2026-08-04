rule PHP_Supervueity_Obfuscator_CUST
{
    meta:
        description = "Detects highly obfuscated PHP script with multijavascript/supervueity string patterns"
        author = "Security Team"
        severity = "HIGH"
        date = "2026-03-30"
    strings:
        $php = "<?php" ascii
        $s1 = "charles_multiapiment" ascii
        $s2 = "microapplicationic_megaalgorithmive" ascii
        $s3 = "uniinfrastructureist_multimicroserviceible" ascii
        $s4 = "trivuely applicationist nanoinfrastructuretion" ascii
    condition:
        $php at 0 and filesize < 3MB and (2 of ($s1, $s2, $s3, $s4))
}
