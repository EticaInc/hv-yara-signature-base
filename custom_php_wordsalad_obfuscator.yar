rule Suspicious_PHP_WordSalad_Obfuscator_Megareactness {
    meta:
        description = "Detects PHP files obfuscated with a word-salad generator, characterized by extremely long alphanumeric strings and concatenated variable/function names."
        author = "Antigravity"
        severity = "HIGH"
        date = "2026-03-12"
    strings:
        $php = "<?php" ascii
        // Core elements of this specific obfuscator pattern
        $func1 = "system_quickdataable" ascii
        $func2 = "proapiic_tritypescriptment" ascii
        $func3 = "trialgorithmed_microendpointful" ascii
        // Huge concatenated payload signature strings
        $str1 = "maxtypescriptive_microreact_megareactsion_bivuement_bitypescriptment_quickjavascripted_ultraapping_quadapper" ascii
        $str2 = "superinfrastructureist_megavuely_multiendpointment_fastvuely_quickdataor_miniapplicationness_minijavascripttion_platformer_proclouded_nanoapplicationic_quadmicroserviceing_algorithmment_autovueist_triapplicationed_fastrestive_nanomicroservice_megatypescriptity_pentadataful_autorestic_autoappible_serverless_quicktypescriptable_smartreactist_maxreactive_uniinfrastructurement_multiapplicationment_megaapply_bivuetion_autoapied_fastserverness_megajavascriptness_microendpointic_daniel_restable_maxapplicationible_biapiive_minireactist_multicloudtion_smartangulared_miniendpointity_quadcloudly_ultrajavascriptment_ultradataful_multiendpointic_hyperapior_fastappness" ascii
    condition:
        filesize < 1MB and $php and 2 of ($func*, $str*)
}
