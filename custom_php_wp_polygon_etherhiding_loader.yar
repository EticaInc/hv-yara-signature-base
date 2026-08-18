rule PHP_WP_Polygon_EtherHiding_Loader_CUST {
    meta:
        description = "Detects the 'Speed Optimizer' fake WordPress performance plugin, which injects a fake loading-spinner overlay plus a heavily self-obfuscated script into wp_head/admin_head. The injected script cloaks against bots/crawlers, calls eth_call on a Polygon contract across a rotating list of RPC endpoints to fetch a hidden payload location, decodes it with a custom XOR-based cipher, and dynamically loads the final script -- an 'EtherHiding' technique using the blockchain as a takedown-resistant dead drop instead of a conventional C2 domain. Distinct from the BSC-based variant (PHP_BSC_EtherHiding_Loader_CUST): different chain, no server-side AJAX bridge, and a different obfuscation kit (literal string-reversal plus unicode-escaped property/identifier access throughout)."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-08-17"
        hash = "fb9e61beb8613c90b5a71a09394d81e5b0001b4f747835a19c822da293dc71a6"

    strings:
        $php = "<?php" ascii

        // Distinctive function names in this exact build. Not trusted alone --
        // "decode"/"getServers" are generic enough to plausibly appear in
        // unrelated code, so the condition below always also requires a genuine
        // blockchain/EtherHiding marker, never these names by themselves.
        $func_decode = "function decode(token,key)" ascii
        $func_getservers = "async function getServers()" ascii
        $func_tryload = "function tryLoadScript(" ascii
        $func_createdeferred = "function createDeferredScript(" ascii

        // Obfuscation-kit structural fingerprints -- identifier-independent, so
        // these survive a full rename of the functions above. Two separate
        // tricks used throughout this kit: reversing a quoted literal at
        // runtime instead of writing it forwards, and accessing a property via
        // a fully \uXXXX-escaped key instead of its literal name, e.g.
        // str["length"] in place of str.length.
        $reverse_trick = /"[A-Za-z]{2,}"\.split\(""\)\.reverse\(\)\.join\(""\)/ ascii
        $unicode_bracket_access = /\[\s*"(\\u[0-9a-fA-F]{4}){3,}"\s*\]/ ascii

        // What actually makes this an EtherHiding loader rather than generic
        // obfuscated JS: real JSON-RPC eth_call markers, independent of any
        // function/variable name in this build
        $jsonrpc_lit = "\"jsonrpc\":" ascii
        $eth_call_lit = "\"method\":\"eth_call\"" ascii

    condition:
        filesize < 3MB and $php and
        (
            2 of ($func_decode, $func_getservers, $func_tryload, $func_createdeferred)
            or
            1 of ($reverse_trick, $unicode_bracket_access)
        )
        and
        1 of ($jsonrpc_lit, $eth_call_lit)
}
