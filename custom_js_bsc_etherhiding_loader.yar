rule JS_BSC_EtherHiding_Loader_CUST {
    meta:
        description = "Detects the front-end companion loader for the 'BSC Script Loader' EtherHiding campaign (see PHP_BSC_EtherHiding_Loader_CUST). Requests a payload script from the site's own admin-ajax endpoint using a localized nonce/action pair, then executes the returned script by injecting it as an inline <script> element."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-08-17"
        hash = "2dd3cb0cd831f4967f58e4915959fe5fd248a2428fbf529d0b673b27ebcbd0bf"

    strings:
        $run_guard = "window.__bscSlRan" ascii
        $prop_action = "bscSl.action" ascii
        $prop_nonce = "bscSl.nonce" ascii
        $func_run_script = "function runScript(source)" ascii

    condition:
        filesize < 50KB and
        3 of ($run_guard, $prop_action, $prop_nonce, $func_run_script)
}
