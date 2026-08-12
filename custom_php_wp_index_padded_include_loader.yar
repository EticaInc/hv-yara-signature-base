/*
    Technique-level rule, deliberately not family-specific.

    Off-screen padding: a WordPress bootstrap file whose opening <?php tag is followed by a long
    whitespace run, pushing an injected @include_once far to the right where it is invisible in
    an editor or a `head` of the file. First observed in a LinkFlow incident, but the technique
    is generic and this rule should catch unrelated actors using it.
*/

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
