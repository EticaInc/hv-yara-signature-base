/*
    Custom Yara Rules - SEO Spam & Defacement
    Target: Madridbet SEO Campaign
    Created: 2026-01-13
*/

rule HTML_SEO_Spam_Madridbet_CUST {
    meta:
        description = "Detects Madridbet SEO Spam/Defacement pages often uploaded as wp-options.php"
        author = "Security Team"
        severity = "HIGH"
        date = "2026-01-13"
        threat_type = "SEO Spam"
        hash_sample = "Calculated from finding"

    strings:
        // Core Branding & Title Indicators
        $title_tag = "<title>Madridbet Premium Platform | Madridbet Elite Bonusu" nocase
        $meta_author = "<meta name=\"author\" content=\"Madridbet\">" nocase

        // Specific Campaign Redirects & Domains
        $shortener_link = "https://kisalt.app/MadridbetBossSeo"
        $spam_hreflang = "madridbetbosstgirissi.com"

        // Unique Template Artifacts (CSS)
        // This gradient definition matches the uploaded spam template exactly
        $css_var_1 = "--primary-gradient: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);"
        $css_var_2 = "--dark-bg: #0f0a1a;"

    condition:
        // Optimization: limit scan to files under 1MB (Spam pages are rarely larger)
        filesize < 1MB and
        (
            // Strong Indicator: Title + Shortener Link
            ($title_tag and $shortener_link) or

            // Strong Indicator: Spam Domain + CSS Artifact
            ($spam_hreflang and $css_var_1) or

            // Medium Indicator: Branding + Multiple Template Artifacts
            ($meta_author and $css_var_1 and $css_var_2)
        )
}
