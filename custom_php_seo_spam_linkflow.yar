/*
    LinkFlow family — SEO spam, cloaked redirects, and the "WP Defence" coordinator.

    Three rules, one family, sharing the `lf_` namespace:
      PHP_SEO_Spam_Linkflow_CUST                 Advanced_LinkFlow_Control (2026-06-07)
      PHP_WP_Defence_LinkFlow_Coordinator_CUST   "WP Defence" variant      (2026-08-03)
      PHP_WP_LinkFlow_Cloaked_Spam_Payload_CUST  cloaked payload           (2026-08-03)

    The 2026-06-07 rule does NOT match the 2026-08-03 variant: the class name changed and the
    newer variant carries no obfuscation at all.

    WHY EXISTING TOOLING MISSED THE VARIANT. The coordinator contains no eval, base64_decode,
    gzinflate or str_rot13. It is clean, readable, GPL-headered PHP carrying a plausible plugin
    header. A live endpoint security plugin, a second security plugin, and a full external
    vulnerability scan all failed to flag it. Detection must key on identity strings, not on
    entropy or eval patterns.

    CLEANUP NOTE FOR RESPONDERS. The coordinator replicates bidirectionally between
    wp-content/plugins/ and wp-content/mu-plugins/, so removing one copy while another survives
    restores it on the next page load. It also recreates the mu-plugins directory if deleted.
    Removal must cover every copy, and the mu-plugins copy never writes back — so plugins/
    copies go first.
*/

rule PHP_SEO_Spam_Linkflow_CUST {
    meta:
        description = "Detects Advanced LinkFlow Control, an SEO redirect and link injection spam plugin."
        author = "Security Team"
        severity = "HIGH"
        date = "2026-06-07"
        hash = "d81d2e2e0a34a604b635ac6fefbd52c22ac2cebc84f7f356e8feaa66047c8460"
    strings:
        $php = "<?php" ascii
        $class = "class Advanced_LinkFlow_Control" ascii
        $obf_url = "\\x68\\x74\\x74\\x70:\\x2f/\\x73h\\x69z\\x61.\\x6ci\\x76e\\x2fg\\x65t\\x2ep\\x68p" ascii
        $cookie1 = "CURLOPT_LF_TEST" ascii
        $cookie2 = "LFD" ascii
        $testok = "XTESTOKX" ascii
        $offset_calc = "7200 + (strlen($html) % 1000)" ascii
    condition:
        filesize < 100KB and $php and $class and (2 of ($obf_url, $cookie1, $cookie2, $testok, $offset_calc))
}

rule PHP_WP_Defence_LinkFlow_Coordinator_CUST {
    meta:
        description = "Detects the LinkFlow 'WP Defence' coordinator: a fake security/updater plugin that self-replicates into mu-plugins. Two class-name variants ship together to defeat their own class_exists guard."
        author = "Security Team"
        severity = "HIGH"
        date = "2026-08-03"
        family = "LinkFlow"
        hash_coordinator_a = "5a399183450747150a72df4b8cc5133b4e5f3af357beff94390107c9807cfbc4"
        hash_coordinator_b = "7664c174c3f8ea3be629f5bc45264027d5ffa8635a3067094110a75007c0938d"
        note = "Filename is not an indicator: copies were found under several names, including one impersonating an unrelated security vendor's file, and inside plugin directories with and without a unix-epoch suffix. Match on identity, never on name."
    strings:
        $php = "<?php" ascii
        // the self-replication routine — unique to this family, present in every copy
        $sync = "lf_sync_mu_plugin_copy" ascii
        // fake vendor identity in the plugin header
        $vendor = "wpninjas.ch/plugins/wp-defence" ascii
        $pretext = "Fetches plugin updates from a remote server" ascii
        // both shipped class names
        $class_a = "class WP_Defence" ascii
        $class_b = "class wpdefence" ascii
        // mu-plugins replication targets
        $mu1 = "WPMU_PLUGIN_DIR" ascii
        $mu2 = "WP_PLUGIN_DIR" ascii
    condition:
        filesize < 200KB
        and $php
        and (
            $sync
            or ($vendor and any of ($class_a, $class_b))
            or ($pretext and all of ($mu1, $mu2))
        )
}

rule PHP_WP_LinkFlow_Cloaked_Spam_Payload_CUST {
    meta:
        description = "Detects the LinkFlow cloaked SEO-spam/redirect payload dropped as xml_domit_rss.php inside a vendored plugin tree. Hides from logged-in admins, fingerprints crawlers, takes instructions from a remote host."
        author = "Security Team"
        severity = "HIGH"
        date = "2026-08-03"
        family = "LinkFlow"
        hash = "ba080a159122264e5d122af5de04f238d5c43b4c03f185df9149e657725cf551"
        note = "A second copy of the payload was found under an innocuous name in the same buried directory, so the filename in the description is illustrative only."
    strings:
        $php = "<?php" ascii
        // admin-cloaking flag, LinkFlow namespace
        $lf = "$lf_enable" ascii
        // cookie planted to suppress the payload for staff browsers
        $cookie = "http2_session_id" ascii
        // coordination guard against the WP Defence coordinator
        $guard = "class_exists('WP_Defence')" ascii
        // exclusion regex so only content pages are targeted
        $badurls = "$bad_urls" ascii
        $c2 = "sys-pys.com" ascii
        $cloak = "is_user_logged_in()" ascii
    condition:
        filesize < 200KB
        and $php
        and (
            $c2
            or ($lf and any of ($cookie, $guard, $badurls))
            or ($cookie and $cloak and $badurls)
        )
}
