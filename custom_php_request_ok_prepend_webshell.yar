rule PHP_Request_OK_Prepend_Webshell_CUST {
    meta:
        description = "Detects a PHP compromise campaign that prepends an exact request-based liveness probe to backdoors"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-09-02"
        hash = "1d1ea2118cd965c757d76a64e707380ffe92d2c9890b647276beab697bda098e"
    strings:
        $probe = "<?php ?><?php if(isset($_REQUEST[\"ok\"])){die(\">ok<\");};?>" ascii
        $eval = "eval" ascii
        $file_get = "file_get_contents" ascii
    condition:
        filesize < 500KB and $probe at 0 and 1 of ($eval, $file_get)
}
