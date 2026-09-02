rule ASP_Siliemor_Webshell_CUST {
    meta:
        description = "Detects the Siliemor classic ASP encoded webshell"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-09-02"
        hash = "0e306a92fd83e8e21013d18f9402e996914e55a68b0e0f5a3b7363a2814e9947"
    strings:
        $asp = "<%@ LANGUAGE = VBScript.Encode %>" ascii
        $family_name = "mName=\"Siliemor\"" ascii
        $family_author = "AD=\"Siliemor\"" ascii
        $password = "UserPass=" ascii
        $encoded_script = "#@~^" ascii
    condition:
        filesize < 250KB and $asp at 0 and $family_name and $family_author and $password and $encoded_script
}
