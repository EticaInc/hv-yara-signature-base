rule PHP_WP_Polygon_EtherHiding_XOR_Injector_CUST {
    meta:
        description = "Detects the 'A11y Image Attributes Fix' fake WordPress plugin (header 'Author: Wordpress'), a single-file EtherHiding injector. The PHP side removes itself from the Plugins screen via an all_plugins filter that unsets plugin_basename(__FILE__), skips wp-login.php, administrators and the admin area, and prints an inline <script> on wp_head for every other visitor. The script is a base64 blob XORed with a single-byte key (124 in this drop), decoded with charCodeAt()^key and executed via new Function(new TextDecoder().decode(...)). The decrypted stage calls eth_call on a Polygon contract over a rotating list of public RPC endpoints, ABI-decodes the returned string as the current C2 base URL, and injects <c2>/api.php?s=<campaign id> as a remote script. Distinct from PHP_WP_Polygon_EtherHiding_Loader_CUST ('Speed Optimizer'): that kit leaves eth_call in plaintext and uses string-reversal and unicode-escaped property access, while here eth_call, the contract and the RPC list only exist inside the XOR-encrypted blob, so the at-rest file carries no blockchain marker at all."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-11-03"
        // sha256 of the sample as submitted (an RTF copy of the plugin file)
        hash = "5a5664adaae03e729845036078d1939d0def002326de28d290c2df9eb7ac93f6"

    strings:
        // nocase: PHP accepts the open tag in any case, so "<?PHP" executes too.
        $php = "<?php" ascii nocase

        // --- Identity: this drop's plugin name, callback name, and the base64 of
        //     "(function(){if(window['" XORed with key 124, i.e. the start of every
        //     blob this kit emits while the key stays the same.
        $id_name   = "A11y Image Attributes Fix" ascii
        $id_func   = "a11y_image_attributes_fix" ascii
        $id_prefix = "VBoJEh8IFRMSVFUHFRpUCxUSGBMLJ1s" ascii

        // --- Behavioral, client-side kit: a long base64 literal, a per-char XOR over
        //     charCodeAt (either operand order, dotted or bracketed access), and the
        //     decrypted text run through Function(TextDecoder.decode(...)). Benign
        //     code does not decrypt-and-execute an inline blob this way.
        //     Any quote style including backticks, dotted or bracketed atob, and no
        //     closing paren required, so splitting the blob with '+' still matches.
        $k_atob    = /atob['"`]?\]?\s*\(\s*['"`][A-Za-z0-9+\/]{400}/ ascii
        $k_xor_a   = /(\.charCodeAt|\[\s*['"]charCodeAt['"]\s*\])\s*\(\s*[\w$]+\s*\)\s*\^/ ascii
        $k_xor_b   = /\^\s*[\w$.\[\]'"]+(\.charCodeAt|\[\s*['"]charCodeAt['"]\s*\])\s*\(/ ascii
        $k_exec    = /\bFunction\s*\(\s*new\s+TextDecoder\s*\(/ ascii

        // --- Behavioral, PHP wrapper. WordPress API names the operator cannot rename.
        //     Self-hiding: drop this plugin's own entry from the Plugins list.
        $w_hide_filter = /add_filter\s*\(\s*['"]all_plugins['"]/ ascii
        $w_hide_unset  = /unset\s*\(\s*\$[\w]+\s*\[\s*plugin_basename\s*\(\s*__FILE__\s*\)\s*\]\s*\)/ ascii
        //     Front-end injection hooks.
        $w_hook_head   = /add_action\s*\(\s*['"]wp_head['"]/ ascii
        $w_hook_foot   = /add_action\s*\(\s*['"]wp_footer['"]/ ascii
        $w_hook_body   = /add_action\s*\(\s*['"]wp_body_open['"]/ ascii

    condition:
        filesize < 3MB and $php and
        (
            // Identity: this build. Name and callback derive from one string, so either
            // must be paired with a malicious marker rather than counted against the
            // other -- a benign plugin that happened to share the name stays clean.
            (1 of ($id_name, $id_func) and 1 of ($id_prefix, $w_hide_unset))
            or
            // Behavioral: the encrypted-JS kit, emitted from a front-end hook or a
            // self-hiding plugin. Survives renaming the plugin, callback and variables,
            // and changing the XOR key.
            ($k_atob and 1 of ($k_xor_*) and $k_exec and
                (1 of ($w_hook_*) or ($w_hide_filter and $w_hide_unset)))
            or
            // Behavioral: the PHP wrapper, should the executor be swapped out (eval,
            // script element, ...). A plugin that hides itself from the Plugins list and
            // prints a large base64 blob that is then XOR-decrypted, to every front-end
            // visitor. The XOR clause keeps a self-hiding white-label plugin that merely
            // inlines a base64 image or font out of this branch.
            ($w_hide_filter and $w_hide_unset and 1 of ($w_hook_*) and $k_atob and
                1 of ($k_xor_*))
        )
}
