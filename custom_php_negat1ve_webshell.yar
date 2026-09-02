rule PHP_Negat1ve_Encoded_Webshell_CUST {
    meta:
        description = "Detects PHP webshells wrapped by the Negat1ve private encoder"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-09-02"
        hash = "40fc176db6a2be5e8d4679b5965d968179f1d00895acfdb715625258761292e0"
    strings:
        $php = "<?php" ascii
        $encoded_by = "Encoded By: Negat1ve" ascii
        $encoder_name = "Negat1ve Encoder is a private encoder" ascii
        $decode = "eval(base64_decode(" ascii
        $inflate = "gzinflate(base64_decode(" ascii
    condition:
        filesize < 100KB and $php and $encoded_by and $encoder_name and $decode and $inflate
}

rule PHP_Negat1ve_FilesManager_Webshell_CUST {
    meta:
        description = "Detects the decoded Negat1ve Shell PHP file-manager webshell"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-09-02"
        hash = "b6b3c81f45b79a3e33efe98aec473aec5583e3f880933e723b0c213f2f0140bb"
    strings:
        $php = "<?php" ascii
        $family = "Negat1ve Shell" ascii
        $hex_uname = "7068705f756e616d65" ascii
        $hex_file_put = "66696c655f7075745f636f6e74656e7473" ascii
        $hex_shell_exec = "7368656c6c5f65786563" ascii
        $files_manager = "Files Manager" ascii
    condition:
        filesize < 100KB and $php and $family and $files_manager and 2 of ($hex_*)
}
