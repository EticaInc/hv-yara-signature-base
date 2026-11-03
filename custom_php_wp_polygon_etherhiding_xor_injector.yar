rule PHP_WP_Polygon_EtherHiding_XOR_Injector_CUST {
    meta:
        description = "Detects the 'A11y Image Attributes Fix' fake WordPress plugin (header 'Author: Wordpress'), a single-file EtherHiding injector, and the encrypted-JS kit it uses. The PHP side removes itself from the Plugins screen via an all_plugins filter that unsets plugin_basename(__FILE__), skips wp-login.php and administrators, and prints an inline <script> on wp_head for every other visitor. The script is a base64 blob XORed with a single-byte key (124 in this drop), decoded with charCodeAt(i)^key and executed via new Function(new TextDecoder().decode(...)). The decrypted stage calls eth_call on a Polygon contract over a list of public RPC endpoints, ABI-decodes the returned string as the C2 base URL, and injects <c2>/api.php?s=<campaign id> as a remote script. eth_call, the contract and the RPC list only exist inside the encrypted blob, so the behavioral branches match the generic decrypt-and-execute kit rather than any blockchain marker. Distinct from PHP_WP_Polygon_EtherHiding_Loader_CUST ('Speed Optimizer'), which leaves eth_call in plaintext."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-11-03"
        // sha256 of the plugin PHP rebuilt from the submitted RTF copy (the on-disk
        // original was not available; the RTF itself is
        // 5a5664adaae03e729845036078d1939d0def002326de28d290c2df9eb7ac93f6).
        hash = "0bf7258fddd44d1f9e87f6f18e66d3d2336781d5afe757b980af106bdbd6c54a"

    strings:
        // nocase: PHP accepts the open tag in any case, so "<?PHP" executes too.
        $php = "<?php" ascii nocase

        // --- Identity: this drop's plugin name and callback, and the base64 of
        //     "(function(){if(window['" XORed with key 124 -- the start of every blob
        //     this kit emits while the key stays the same. Cut to the 30 characters
        //     fixed by those 23 bytes; the 31st also depends on the next byte.
        $id_name   = "A11y Image Attributes Fix" ascii
        $id_func   = "a11y_image_attributes_fix" ascii
        $id_prefix = "VBoJEh8IFRMSVFUHFRpUCxUSGBMLJ1" ascii

        // --- Behavioral, client-side kit.
        //     The blob: atob() on a long base64 literal. Dotted, bracketed or bare atob,
        //     any quote style, and an optional backslash before the quote so a script
        //     printed from a PHP echo string (atob(\"...\")) still matches.
        $k_atob      = /atob\\?['"`]?\]?\s{0,8}\(\s{0,8}\\?['"`][A-Za-z0-9+\/]{400}/ ascii
        //     Any atob() call, for a blob held in a variable first. Used only where
        //     the TextDecoder executor and a front-end hook are also required. (A
        //     standalone long-base64 pattern would be a YARA-X slow pattern.)
        $k_atob_call = /\batob\\?['"`]?\]?\s{0,8}\(/ ascii
        //     Per-char XOR over charCodeAt, either operand order, dotted or bracketed
        //     access. The index may be empty (charCodeAt() means index 0) or an
        //     expression such as i++ or i+1. In the "key ^ s.charCodeAt" order the
        //     receiver must start like an identifier, so a caret inside a string
        //     literal ("^".charCodeAt(0)) does not count.
        $k_xor_a = /(\.charCodeAt|\[\s{0,8}\\?['"`]charCodeAt\\?['"`]\s{0,8}\])\s{0,8}\(\s{0,8}[\w$+\-]{0,32}\s{0,8}\)\s{0,8}\^/ ascii
        $k_xor_b = /\^\s{0,8}[A-Za-z_$][\w$.\[\]]{0,64}(\.charCodeAt|\[\s{0,8}\\?['"`]charCodeAt\\?['"`]\s{0,8}\])\s{0,8}\(/ ascii
        //     The executor in this drop: Function(new TextDecoder(...)).
        $k_exec     = /(\bFunction|\[\s{0,8}\\?['"`]Function\\?['"`]\s{0,8}\])\s{0,8}\(\s{0,8}new\s{1,8}(window\s{0,8}\.\s{0,8})?TextDecoder\s{0,8}\(/ ascii
        //     The same pieces split across variables: a TextDecoder plus a code sink.
        $k_textdec  = /new\s{1,8}(window\s{0,8}\.\s{0,8})?TextDecoder\s{0,8}\(/ ascii
        $k_sink_fn  = /(\bnew\s{1,8}Function|\[\s{0,8}\\?['"`]Function\\?['"`]\s{0,8}\])\s{0,8}\(/ ascii
        $k_sink_ev  = /(\beval|\[\s{0,8}\\?['"`]eval\\?['"`]\s{0,8}\])\s{0,8}\(/ ascii
        $k_sink_scr = /createElement\s{0,8}\(\s{0,8}\\?['"`]script\\?['"`]\s{0,8}\)/ ascii

        // --- Behavioral, PHP wrapper. WordPress API names the operator cannot rename.
        //     nocase because PHP function names and __FILE__ are case-insensitive.
        //     Self-hiding: drop this plugin's own entry from the Plugins list.
        $w_hide_filter = /add_filter\s{0,8}\(\s{0,8}['"]all_plugins['"]/ ascii nocase
        $w_hide_unset  = /unset\s{0,8}\(\s{0,8}\$\w{1,64}\s{0,8}\[\s{0,8}\\?plugin_basename\s{0,8}\(\s{0,8}__FILE__\s{0,8}\)\s{0,8}\]\s{0,8}\)/ ascii nocase
        //     Front-end injection hooks.
        $w_hook_head   = /add_action\s{0,8}\(\s{0,8}['"]wp_head['"]/ ascii nocase
        $w_hook_foot   = /add_action\s{0,8}\(\s{0,8}['"]wp_footer['"]/ ascii nocase
        $w_hook_body   = /add_action\s{0,8}\(\s{0,8}['"]wp_body_open['"]/ ascii nocase

    condition:
        filesize < 500KB and $php and
        (
            // Identity: this build. The name and callback derive from one string, so
            // each must be paired with a malicious marker rather than with the other --
            // a benign plugin that happened to share the name stays clean.
            (1 of ($id_name, $id_func) and ($id_prefix or ($w_hide_filter and $w_hide_unset)))
            or
            // Identity: a renamed drop that keeps key 124. The 30-character prefix is
            // specific on its own; require that it is printed from a front-end hook or
            // a self-hiding plugin.
            ($id_prefix and (1 of ($w_hook_*) or $w_hide_filter))
            or
            // Behavioral: the encrypted-JS kit, emitted from a front-end hook or a
            // self-hiding plugin. Survives renaming the plugin, callback and variables,
            // and changing the XOR key.
            ($k_atob_call and 1 of ($k_xor_*) and
                ($k_exec or ($k_textdec and 1 of ($k_sink_*))) and
                (1 of ($w_hook_*) or ($w_hide_filter and $w_hide_unset)))
            or
            // Behavioral: the PHP wrapper, should the executor be swapped out. A plugin
            // that hides itself from the Plugins list and, on a front-end hook, prints a
            // large base64 blob that is XOR-decrypted and run through eval, Function or
            // a script element. The XOR and sink clauses keep a self-hiding white-label
            // plugin that merely inlines a base64 image or font out of this branch.
            ($w_hide_filter and $w_hide_unset and 1 of ($w_hook_*) and
                $k_atob and 1 of ($k_xor_*) and 1 of ($k_sink_*))
        )
}
