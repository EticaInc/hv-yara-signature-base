rule custom_php_seo_spam_celtabet_CUST {
    meta:
        description = "Detects Celtabet gambling SEO spam/doorway pages"
        author = "Security Team"
        severity = "HIGH"
        date = "2026-03-04"

    strings:
        // Spam keywords and title patterns
        $title = "<title>Celtabet Resmi Giri" nocase
        $meta = "content=\"En iyi bahis ve casino sitesi" nocase

        // Redirect targets and domains found in the spam
        $url1 = "joinclubclean.com"
        $url2 = "kayitceltabet.live"

        // Structural recurring blocks in the spam page
        $struct1 = "<div class=\"info-box\">"
        $struct2 = "<h2>Celtabet"

    condition:
        // Require multiple weak indicators or one strong unique domain match combined with structure
        ($title and $meta) or
        (1 of ($url*) and 1 of ($struct*)) or
        3 of them
}
