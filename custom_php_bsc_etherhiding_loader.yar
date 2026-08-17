rule PHP_BSC_EtherHiding_Loader_CUST {
    meta:
        description = "Detects the 'BSC Script Loader' fake WordPress optimizer plugin, which uses an 'EtherHiding' technique: it stores/retrieves a malicious payload script via a Binance Smart Chain contract's eth_call getter (fetched server-side via JSON-RPC, ABI-decoded) instead of a conventional C2 domain, then serves the decoded script to front-end visitors through an authenticated AJAX action for client-side execution. Storing the payload on-chain makes conventional domain/host takedown ineffective."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-08-17"
        hash = "1c33c03654cd869422c9e5637317a6eb8ba70cdf1dd5e3634493dd4a856722af"

    strings:
        $php = "<?php" ascii

        // Loader class and its blockchain-fetch/decode methods
        $class_decl = "class BSC_Script_Loader" ascii
        $func_eth_call = "function eth_call_with_fallback(" ascii
        $func_abi_decode = "function abi_decode_string(" ascii

        // AJAX bridge that serves the on-chain payload to the front end
        $ajax_action = "bsc_sl_get_script" ascii
        $contract_const = "BSC_SL_CONTRACT" ascii

        // The JSON-RPC call itself
        $rpc_method = "=> 'eth_call'" ascii

    condition:
        filesize < 500KB and $php at 0 and
        (
            2 of ($class_decl, $func_eth_call, $func_abi_decode)
            or
            ($ajax_action and $contract_const and $rpc_method)
        )
}
