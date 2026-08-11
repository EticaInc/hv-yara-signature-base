/*
    LinkFlow family — "WP Defence" variant.

    Family relationship: shares the `lf_` (LinkFlow) namespace with
    custom_php_seo_spam_linkflow.yar (Advanced_LinkFlow_Control, 2026-06-07).
    That rule does NOT match this variant — the class name changed and this
    variant carries no obfuscation at all.

    Why existing tooling missed it: the coordinator contains no eval,
    base64_decode, gzinflate or str_rot13. It is clean, readable, GPL-headered
    PHP carrying a plausible plugin header. A live endpoint security plugin, a
    second security plugin, and a full external vulnerability scan all failed to
    flag it. Detection must key on identity strings, not on entropy or eval
    patterns.

    Cleanup note for responders: the coordinator replicates bidirectionally
    between wp-content/plugins/ and wp-content/mu-plugins/, so removing one copy
    while another survives restores it on the next page load. It also recreates
    the mu-plugins directory if deleted. Removal must cover every copy, and the
    mu-plugins copy never writes back — so plugins/ copies go first.
*/

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

rule PHP_WP_Index_Padded_Include_Loader_CUST {
    meta:
        description = "Detects a WordPress bootstrap file whose opening tag is padded with a long whitespace run to push an injected @include_once off-screen in an editor. Technique-level rule, not family-specific."
        author = "Security Team"
        severity = "HIGH"
        date = "2026-08-03"
        hash = "b4fc94e2743439399434cfe8ef2ebe03adb75c1d13739c72ba980ce2b68d24f8"
        note = "Clean stock WordPress index.php is eea9347b1e266ca5407b92633958c148dbfebea307e511a3a226ea61828e2eba (405 bytes). Deliberately family-agnostic: it should catch unrelated actors using the same off-screen-padding trick. The observed injection loaded its payload from a sibling docroot, so a hit here means checking every docroot on the host, not just this one."
    strings:
        // <?php followed by 20+ tabs or spaces, then a suppressed include
        $padded = /<\?php[\t ]{20,}/
        $inc = "@include_once" ascii
        $wpboot = "wp-blog-header.php" ascii
    condition:
        filesize < 20KB
        and $wpboot
        and $inc
        and $padded
}
