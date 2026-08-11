/*
    "SC" toolkit v4.0.3 — self-healing multi-slot WordPress persistence.
    Cover identities to date: "Byte Feeder IO", "Retro Generator Evo", "Sharp Harvester Orb".

    WHY EXISTING TOOLING MISSED IT — tested, not assumed.
    A full scheduled scan completed successfully on an affected host and reported
    finding_count: 0 while roughly 18 malicious files sat on disk. Three separate tests against
    five known-malicious files, including the COMPLETE public base ruleset with nothing skipped,
    produced ZERO matches. The payload uses a custom substitution cipher with no plaintext eval,
    base64_decode, gzinflate or str_rot13, so entropy- and eval-based rules never fire.

    WHY THE PREVIOUS CUSTOM RULE IS DEAD.
    custom_php_byte_feeder_io_backdoor.yar, removed in the same change that added this file,
    required `2 of ($plugin_*)` — "Byte Feeder IO", "charlottescott.com/wp/byte-feeder-io",
    "Text Domain: byte-feeder-io". All three vanished in the rebrand, so the condition became
    unsatisfiable: `grep -c charlottescott` returns 0 on every live copy. Cover metadata is
    generated per drop. DO NOT key on plugin identity for this family.

    SEVEN AUTO-EXECUTION SLOTS PER DOCROOT. Each can rewrite the others, so removing a subset is
    reseeded by the survivors. Three removal attempts failed for this reason.
      1. wp-content/.user.ini -> auto_prepend_file -> <hex8>.php stub -> .<hex8>.php payload (dotfile)
      2. wp-content/db.php                      (WordPress DB drop-in)
      3. wp-content/advanced-cache.php          (WordPress cache drop-in)
      4. wp-content/mu-plugins/<name>.php       (must-use, auto-loads)
      5. wp-content/plugins/<name>/             (ordinary plugin)
      6. wp_options 'sc_payload_persistent'     (DATABASE — a plain option, not a transient, so
                                                 transient purges and cache flushes never touch
                                                 it. Not reachable by a file scanner at all;
                                                 needs a separate database check.)
      7. active theme functions.php, tail block delimited by SC_TH_BEGIN / SC_TH_END
                                                (THE RESEEDER — loads on every page view, rewrote
                                                 slot 4 within 18s of removal. Never examined in
                                                 the three prior attempts.)

    DETECTION MUST BE STRUCTURAL AND MARKER-BASED, NOT SIGNATURE-BASED ON THE BINARY.
    Sample hashes rotate: 5af5afc…89c4 (137,386 B, superseded) -> 6d48cf5c…0262 (195,318 B) and
    7b043477…1e47 (197,059 B). The SC_* markers and the decoder shape survived the rebrand.
*/

rule PHP_SC_Toolkit_Marker_CUST {
    meta:
        description = "Detects the SC toolkit's own slot markers (SC_DB_BEGIN / SC_ADV_BEGIN / SC_TH_BEGIN / SC_TH_END). Highest-confidence indicator for this family; written deliberately by the toolkit and present in every observed drop-in and theme injection."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-08-06"
        family = "SC toolkit, observed version 4.0.3"
        note = "Version-generalised: matches 4.0.3 and any future x.y.z so the rule survives a toolkit bump."
        hash_variant_a = "6d48cf5c7c960b3a4aed7cc5ba58616d606899cf1f5e3d0f357c57bc7f0d0262"
        hash_variant_b = "7b043477210b65e1f18f54523aacd0cb9b1ecbbabc2e854feaf673ee23ce1e47"
    strings:
        // <slot>_BEGIN|END : <version> : <hex8>   e.g. SC_TH_BEGIN:4.0.3:9eb24bb1
        $marker = /SC_(DB|ADV|TH)_(BEGIN|END):[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}:[0-9a-f]{8}/ ascii
    condition:
        filesize < 2MB and $marker
}

rule PHP_SC_Toolkit_Theme_Injection_CUST {
    meta:
        description = "Detects the SC toolkit's theme functions.php tail injection: slot 7, the reseeder. Appended after the theme's own code, occasionally re-opening PHP with its own <?php after a legitimate ?>. Because functions.php loads on every request it rewrites the other slots within seconds of their removal."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-08-06"
        family = "SC toolkit, observed version 4.0.3"
        note = "Observed in two unrelated themes, one of them a child theme. Injected blocks were 83,305 B and 81,497 B; the legitimate theme code in those same files was 13,383 B and 26,173 B. A functions.php far larger than its theme warrants is the cheap manual tell."
        hash_theme_injected_a = "74d410b44121b98bcdd13f65fce8ca93ebb1ca543b1a87ec7f85bd284c8823c1"
        hash_theme_injected_b = "9b8dbe5c0f40610f756a50d204dcbe55443f9f55c2b5bee708ec2cdc3aa74b94"
    strings:
        $th_begin = /SC_TH_BEGIN:[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}:[0-9a-f]{8}/ ascii
        $th_end   = /SC_TH_END:[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}:[0-9a-f]{8}/ ascii
        // decoder wrapper: guard + randomly named function + cipher-array init, all on one line
        $decoder  = "static $a=null;if($a===null){$a=array(" ascii
        $guard    = /if\(!function_exists\('[a-z_][a-z0-9_]{9,23}'\)\)\{function [a-z_][a-z0-9_]{9,23}\(\$[a-z0-9_]{1,12}\)\{/ ascii
        // theme-file context, so this does not fire on arbitrary PHP
        $theme_a  = "add_action" ascii
        $theme_b  = "get_stylesheet_directory" ascii
        $theme_c  = "wp_enqueue_" ascii
    condition:
        filesize < 2MB
        and (
            any of ($th_begin, $th_end)
            or ($decoder and $guard and any of ($theme_a, $theme_b, $theme_c))
        )
}

rule PHP_SC_Toolkit_Cipher_Decoder_CUST {
    meta:
        description = "Detects the SC toolkit's substitution-cipher decoder shape, which survived the rebrand intact. Deliberately family-level rather than sample-level: the binary and all cover metadata rotate per drop, this does not."
        author = "Security Team"
        severity = "HIGH"
        date = "2026-08-06"
        family = "SC toolkit, observed version 4.0.3"
        note = "Carries NO plaintext eval/base64_decode/gzinflate/str_rot13, which is why the entire public base ruleset returned zero matches. Function names are per-drop random: aubxlskv8123dn, oqq5krm2g1nssrx3h, tywo2auctcfmj, esufhylw31pbu, _w3xwp7ztovlmiv4t, n25oj2q898ejyod45oc1, ugy96qqz0j7zq5vpoe."
    strings:
        $php     = "<?php" ascii
        // exact literal as seen in the drop-ins and theme injection
        $decoder = "static $a=null;if($a===null){$a=array(" ascii
        // whitespace-tolerant form. The large mu-plugin/plugin implant inserts runs of spaces
        // between tokens ("defined(x(0))     or    exit;"), which defeats the literal above.
        $decoder_ws = /static\s+\$[a-z]\s*=\s*null\s*;\s*if\s*\(\s*\$[a-z]\s*===\s*null\s*\)\s*\{\s*\$[a-z]\s*=\s*array\s*\(/ ascii
        $guard   = /if\s*\(\s*!\s*function_exists\s*\(\s*'[a-z_][a-z0-9_]{8,24}'\s*\)\s*\)\s*\{\s*function\s+[a-z_][a-z0-9_]{8,24}\s*\(\s*\$[a-z0-9_]{1,12}\s*\)\s*\{/ ascii
        // WordPress reach used by the payload
        $wp_a    = "wp_insert_user" ascii
        $wp_b    = "wp_set_auth_cookie" ascii
        $wp_c    = "WPMU_PLUGIN_DIR" ascii
        $wp_d    = "file_put_contents" ascii
    condition:
        filesize < 2MB
        and $php
        and (
            (any of ($decoder, $decoder_ws) and $guard)
            or (any of ($decoder, $decoder_ws) and 2 of ($wp_a, $wp_b, $wp_c, $wp_d))
        )
}

rule PHP_SC_Toolkit_Implant_Body_CUST {
    meta:
        description = "Detects the SC toolkit's large implant body as dropped into mu-plugins and as an ordinary plugin (slots 4 and 5). Carries NO SC_* marker, so the marker rule does not cover it. Identified structurally: an obfuscated ABSPATH guard, constant-returning trampoline functions, whitespace-insertion obfuscation, and randomly named identifiers reused hundreds of times."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-08-06"
        family = "SC toolkit, observed version 4.0.3"
        note = "Two observed drops of 195,318 B and 197,059 B; 5,231 lines, longest line 23,403 chars. Cover metadata rotates per drop and MUST NOT be keyed on: 'Retro Generator Evo'/Logan Young, 'Sharp Harvester Orb'/Isabella Young, 'Byte Feeder IO'/Charlotte Scott. Note this slot DOES contain plaintext gzinflate, unlike the superseded 137,386 B variant."
        hash_variant_a = "6d48cf5c7c960b3a4aed7cc5ba58616d606899cf1f5e3d0f357c57bc7f0d0262"
        hash_variant_b = "7b043477210b65e1f18f54523aacd0cb9b1ecbbabc2e854feaf673ee23ce1e47"
    strings:
        $php = "<?php" ascii
        // obfuscated direct-access guard: defined(<randfn>(0)) or exit;  -- ABSPATH string is encoded
        $abspath_guard = /defined\s*\(\s*[a-z_][a-z0-9_]{8,24}\s*\(\s*[0-9]{1,3}\s*\)\s*\)\s+or\s+exit/ ascii
        // trampolines that only forward to the decoder with a constant index
        $trampoline = /function\s+[a-z_][a-z0-9_]{8,24}\s*\(\s*\)\s*\{\s*return\s+[a-z_][a-z0-9_]{8,24}\s*\(\s*[0-9]{1,3}\s*\)\s*;\s*\}/ ascii
        // arithmetic-noise helpers used to pad the file
        $noise = /function\s+[a-z_][a-z0-9_]{8,24}\s*\(\s*\$[a-z0-9_]{1,12}\s*,\s*\$[a-z0-9_]{1,12}\s*\)\s*\{\s*\$[a-z0-9_]{1,12}\s*=\s*\(\s*\$[a-z0-9_]{1,12}\s*[-+^]\s*[0-9]{1,3}\s*\)\s*%\s*[0-9]{1,3}\s*;/ ascii
        $decoder_ws = /static\s+\$[a-z]\s*=\s*null\s*;\s*if\s*\(\s*\$[a-z]\s*===\s*null\s*\)/ ascii
        $gz = "gzinflate" ascii
        $mu = "WPMU_PLUGIN_DIR" ascii
    condition:
        filesize > 50KB and filesize < 2MB
        and $php
        and (
            ($abspath_guard and $decoder_ws)
            or ($trampoline and $noise and $decoder_ws)
            or ($decoder_ws and $gz and $mu)
            or (#trampoline > 8 and $noise)
        )
}

rule PHP_SC_Toolkit_Prepend_Loader_CUST {
    meta:
        description = "Detects slot 1's two-stage loader: a small, marker-free stub referenced by .user.ini auto_prepend_file which @include_once's a dotfile payload of the same hex8 name. The stub is deliberately clean-looking and passes any marker grep; the payload is a dotfile so `ls wp-content/*.php` never shows it."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-08-06"
        family = "SC toolkit, observed version 4.0.3"
        note = "Observed stubs 127-159 bytes. The pair is <hex8>.php alongside .<hex8>.php sharing the same 8 hex characters, regenerated per drop, so match the shape and never a specific name. PHP honours a removed .user.ini for user_ini.cache_ttl seconds (default 300), so php-fpm MUST be restarted after removal."
        hash_stub = "3e07127100f43d5d6e572575e03c008ae820460ae789236d851fd54ce92abbd2"
        hash_payload = "bf292e84f299767ded9034ba2c45e4ee1851a2396d1d56ab267f55de24a6896f"
    strings:
        // the stub: suppressed include of a same-named dotfile
        $stub = /@?include_once[\s(]*["'][^"']*\/\.[0-9a-f]{8}\.php["']/ ascii
        $isf  = "is_file" ascii
        // .user.ini content (matched when the scanner is pointed at ini files too)
        $ini  = "auto_prepend_file" ascii
    condition:
        (filesize < 4KB and $stub and $isf)
        or (filesize < 1KB and $ini)
}
