rule PHP_Byte_Feeder_IO_Backdoor_CUST {
    meta:
        description = "Detects the Byte Feeder IO malicious WordPress plugin using a substitution-table decoder to conceal credential theft, remote payload retrieval, hidden administrator access, and persistence"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-07-23"
        hash = "5af5afceeb6ef681d6becedac5b31b26a0a0d81bcc6023b2f03682b3679a89c4"

    strings:
        $php = "<?php" ascii

        // Malicious plugin disguise
        $plugin_name = "Byte Feeder IO" ascii nocase
        $plugin_uri = "charlottescott.com/wp/byte-feeder-io" ascii nocase
        $plugin_domain = "Text Domain:       byte-feeder-io" ascii nocase

        // Substitution-table decoder used to hide C2 and backdoor behavior
        $decoder_init = "static $a=null;if($a===null){$a=array(" ascii
        $alphabet_f = "$f='AB'.'SP'.'TH3'.'.1'.'0WMU'.'_LGI'.'NDR/'" ascii
        $alphabet_t = "$t='O7'.'Fnvt'.'W5.9'" ascii
        $decoder_loop = "$r=\"\";for($j=0;$j<strlen($e);$j++){$p=strpos($t,$e[$j]);" ascii
        $decoder_map = "$r.=($p===false)?$e[$j]:$f[$p];" ascii

    condition:
        filesize < 500KB and
        $php at 0 and
        2 of ($plugin_*) and
        3 of ($decoder_init, $alphabet_f, $alphabet_t, $decoder_loop, $decoder_map)
}
