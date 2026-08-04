rule PHP_WP_Cloaked_Fraud_Redirector_CUST {
    meta:
        description = "Detects a fake WordPress analytics plugin that mimics PostHog branding while operating as a remote-controlled cloaking and script-injection engine."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-07-15"
        hash = "59fa783c333e009052a490b506095649a2e50376158fb4e069f6126ce49e15c4"

    strings:
        $php = "<?php" ascii

        // PostHog-mimicking JavaScript removes a previously injected script.
        $js_cloak_1 = "document.querySelector('script[" ascii
        $js_cloak_2 = "data-ph-pid=" ascii
        $js_cloak_3 = "prev.remove();" ascii

        // Encoded C2 and protocol markers used by this campaign.
        $c2_domain_enc = "2$YUhSMGNITTZMeTlrYjNOcGIyWnBiMnR2TG1OdmJTOD0=" ascii
        $marker_final_js_enc = "2$WDE5UVNGOUdTVTVCVEY5VFZFVlFYMHBUWDE4PQ==" ascii
        $marker_placeholder_enc = "4$VmxWV2IxcHNWa1psUlVwU1RVWmFTbFpFUWpSU1ZrcFhVMjFhVm1GNmJGRldhMWsxVVd4V2MxTnJTbGhWVkRBNQ==" ascii

        // Structural fingerprints for the encoder and word-salad padding.
        $encoded_secret = /['"][0-9]\$[A-Za-z0-9+\/]{16,}={0,2}['"]/ ascii
        $noise_word = /\b(meta|poly|micro|macro|mono)[a-z]{3,}\b/ ascii

    condition:
        $php at 0 and
        filesize < 500KB and
        (
            (2 of ($js_cloak_1, $js_cloak_2, $js_cloak_3))
            or
            (1 of ($c2_domain_enc, $marker_final_js_enc, $marker_placeholder_enc))
            or
            ($encoded_secret and #noise_word > 50)
        )
}
