rule PHP_Webshell_Kapankapan_CUST {
    meta:
        description = "Detects password protected webshell using kapankapan password and hex obfuscation"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-03-04"

    strings:
        // Hardcoded credentials specific to this variant
        $cred1 = "$valid_user = 'admin';"
        $cred2 = "$valid_pass = 'kapankapan';"

        // Obfuscation method used to hide the shell payload
        $obf1 = "eval(hex2bin(" nocase

        // UI Indicators
        $ui1 = "<title>Login Admin</title>"
        $ui2 = "class=\"login-box\""

        // Specific asset linked in the malicious template
        $asset1 = "files.catbox.moe/l98njt.mp3"

    condition:
        // Match the obfuscation AND (credentials OR specific UI assets)
        $obf1 and (1 of ($cred*) or 2 of ($ui*) or $asset1)
}
