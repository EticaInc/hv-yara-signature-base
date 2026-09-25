rule PHP_WP_EtherHiding_ContentProfiler_CUST {
    meta:
        description = "Detects a fake WordPress performance plugin ('Advanced Content Profiler' / 'Core Studio') that injects a malicious client-side script and resolves its C2 from the Polygon blockchain (EtherHiding). The plugin stub self-assembles: an 8-byte-XOR-keyed blob under storage/ is decoded and written out as inc/class-handler.php on first run, so the readable PHP backdoor is absent until the plugin executes once. The handler unpacks a '6TVP' magic container (XOR, reversed, raw-deflate) holding the JavaScript payload, then injects it at wp_footer while skipping logged-in administrator, editor and author sessions and roughly eighteen crawler user agents. C2 is read from a smart contract via eth_call against several public Polygon RPC endpoints, with a hardcoded fallback host, and a heartbeat beacon reports domain, PHP and WordPress versions and plugin count. Also matches the two encrypted container formats on their own, so the payload is still caught where the PHP loader has already been cleaned. Distinct from PHP_WP_Polygon_EtherHiding_Loader_CUST, which covers the 'Speed Optimizer' build of the same technique: that build resolves the chain lookup in JavaScript and injects at wp_head/admin_head using a string-reversal and unicode-escaped-property obfuscation kit, whereas this one resolves it server-side in PHP, injects at wp_footer, uses three-way split-string concatenation, and ships its payload in a '6TVP' container with a self-assembling dropper. Neither rule matches the other's sample, so the two do not double-count. Unrelated to the scatter stub and WPM mu-plugin RAT families."
        author = "Security Team"
        severity = "HIGH"
        date = "2026-09-25"
        hash = "f18503743548ce9cb6aefb099412a5329e27980c2f3a06ea43b3375530239854"
        hash = "a194fdac8d78ca63c0440976e7a82a79d9cffd9a8d422d151e5cd0de55a18d3d"
        hash = "f2ba15aa6b66da6347374402daccc27b25dd4a37a1e23efd4f1824ce7d69acc7"
    strings:
        $php = "<?php" ascii

        // --- Identity
        $id_class = "Core_Engine_9f9f" ascii
        $id_c2    = "webanalytics-cdn.sbs" ascii
        $id_tick  = "wp_6ce55be6_tick" ascii
        $id_hb    = "_ffe2c7_hb" ascii
        $id_slug  = "advanced-content-profiler-5380" ascii

        // --- Behavioral, dropper stub: read a container, take its first 8 bytes as the XOR
        //     key, decode the remainder, confirm the plaintext is PHP, write it to disk.
        //     The '<?php' plaintext check alone appears in unrelated families, so the
        //     8-byte-prefix-key shape is what makes this branch specific.
        $d_keyprefix = /=\s*substr\(\$[A-Za-z0-9_]+,\s*0,\s*8\)\s*;\s*\$[A-Za-z0-9_]+\s*=\s*substr\(\$[A-Za-z0-9_]+,\s*8\)/ ascii
        $d_xorloop   = /chr\(\s*ord\(\$[A-Za-z0-9_]+\[\$[A-Za-z0-9_]+\]\)\s*\^\s*ord\(/ ascii
        $d_phpcheck  = "'<?php')===0" ascii

        // --- Behavioral, handler: WordPress core APIs the operator cannot rename, combined
        //     with the three-way split-string literal obfuscation this build uses throughout.
        // Counted, not merely present: an incidental 'a'.'b'.'c' concatenation in benign
        // code must not satisfy this. The real handler carries 70 occurrences.
        $c_split  = /'[a-z_]{1,4}'\.'[a-z_]{1,8}'\.'[a-z_]{1,8}'/ ascii
        $c_sched  = "wp_next_scheduled" ascii
        $c_inline = "wp_print_inline_script_tag" ascii
        $c_remote = "wp_remote_retrieve_body" ascii

        // --- Encrypted containers. These are not PHP, so the header itself is the
        //     file-type anchor in place of a '<?php' marker.
        $magic = "6TVP" ascii
    condition:
        (
            filesize < 3MB and $php and
            (
                (2 of ($id_*))
                or
                ($d_keyprefix and $d_xorloop and $d_phpcheck)
                or
                (#c_split > 20 and $c_sched and $c_inline and $c_remote)
            )
        )
        or
        // state.idx: '6TVP' magic, 1-byte cipher id, big-endian key length, then body.
        (
            filesize > 7 and filesize < 2MB and
            $magic at 0 and
            filesize > 7 + ((uint8(5) << 8) | uint8(6))
        )
        or
        // config.bin: headerless 8-byte repeating XOR key at offset 0, plaintext '<?php'.
        (
            filesize > 16 and filesize < 2MB and
            // An all-zero key leaves the payload in the clear, so plaintext PHP at
            // offset 8 is an ordinary zero-padded-header file, not a packed container.
            not $php at 0 and not $php at 8 and
            (uint8(8) ^ uint8(0)) == 0x3c and
            (uint8(9) ^ uint8(1)) == 0x3f and
            (uint8(10) ^ uint8(2)) == 0x70 and
            (uint8(11) ^ uint8(3)) == 0x68 and
            (uint8(12) ^ uint8(4)) == 0x70
        )
}
