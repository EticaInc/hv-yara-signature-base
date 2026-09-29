rule HTML_SEO_Spam_Teosbet_CUST {
    meta:
        description = "Detects a Turkish gambling SEO-spam / doorway page for the 'Teosbet' (and paired 'Realbahis') betting brand, of the kind dropped onto compromised WordPress sites (here as amp.php). The page is pure HTML/JS promoting a betting site while carrying a canonical tag pointing at the hijacked host -- parasite SEO. Keyed on the campaign's doorway-generator host scheme <brand>.guncelgirisYYYY.club plus the brand tokens, so it generalises across the campaign's rotating brand subdomains and yearly host rolls. Sibling of the existing Madridbet / Celtabet gambling-spam rules."
        author = "Security Team"
        family = "Teosbet gambling SEO spam"
        severity = "HIGH"
        date = "2026-09-23"
        hash = "ee6b7923897183b5e122d4cb864bcd2d3d42869d36310dc9369636329907fd20"

    strings:
        // Light file-type anchor: these are served HTML doorway pages. Either marker
        // satisfies it -- requiring the doctype alone made the whole rule, branch (a)
        // included, miss a doorway page served without one, which is both common and a
        // one-line edit for the operator.
        $doctype = "<!DOCTYPE html" ascii nocase
        $html_open = "<html" ascii nocase

        // Campaign doorway-generator host: <brand>.guncelgiris<year>.club
        // (e.g. teosbet.guncelgiris2026.club). This host scheme is the
        // campaign infrastructure fingerprint and rotates brand/year.
        $doorway_host = /[a-z0-9-]{2,40}\.guncelgiris[0-9]{4}\.club/ ascii nocase

        // Brand tokens (this drop promotes Teosbet, paired with Realbahis)
        $brand_teosbet = "Teosbet" ascii nocase
        $brand_realbahis = "Realbahis" ascii nocase

        // Turkish gambling-doorway phrasing ("current login")
        $tr_login = "güncel giriş" ascii nocase
        // Keywords meta listing both campaign brands (byte-safe; no literal
        // non-ASCII inside a regex class, which YARA-X rejects)
        $kw_meta = /name="keywords"[^>]{0,200}Teosbet[^>]{0,200}Realbahis/ ascii nocase

        // Doorway-generator template artifact: the page is laid out from a fixed set of
        // uppercase, accent-stripped Turkish section labels. These are the specific
        // labels the generator emits, not a count of uppercase comments -- counting the
        // generic shape let six ordinary section comments (HEADER, NAVIGATION, MAIN
        // CONTENT, ...), or six repetitions of one comment, stand in for the template.
        // Only the brand-independent labels are listed, so this keeps working when the
        // campaign rotates its brand, which is the case branch (b) exists to cover.
        // Whitespace-tolerant, so ordinary reformatting of the comment does not defeat
        // them. CEKIM GARANTIISI carries the generator's own doubled-I typo.
        $tpl_cekim    = /<!--\s*CEKIM GARANTIISI\s*-->/ ascii
        $tpl_ekbilgi  = /<!--\s*EK BILGI BOLUMU\s*-->/ ascii
        $tpl_guvenlik = /<!--\s*GUVENLIK REHBERI\s*-->/ ascii
        $tpl_hero     = /<!--\s*HERO \/ ANA SAYFA\s*-->/ ascii
        $tpl_iliskili = /<!--\s*ILISKILI MAKALELER\s*-->/ ascii
        $tpl_lisans   = /<!--\s*LISANS DOGRULAMA\s*-->/ ascii
        $tpl_mobil    = /<!--\s*MOBIL ERISIM\s*-->/ ascii
        $tpl_sss      = /<!--\s*SSS\s*-->/ ascii
        $tpl_vip      = /<!--\s*VIP AVANTAJLAR\s*-->/ ascii

    condition:
        filesize < 2MB and 1 of ($doctype, $html_open) and
        (
            // (a) campaign doorway host + a gambling brand -> conclusive
            ($doorway_host and 1 of ($brand_teosbet, $brand_realbahis))
            or
            // (b) heavy Teosbet doorway branding + Realbahis pairing + login phrasing,
            //     resilient if the doorway host rotates away. Brand frequency alone does
            //     not establish compromise -- a consumer-comparison article naming the
            //     brand repeatedly satisfied the first three clauses -- so this branch
            //     also requires the generator's section-comment scaffold, which is a
            //     property of the doorway template rather than of the subject matter.
            (
                #brand_teosbet > 10 and $brand_realbahis and
                1 of ($tr_login, $kw_meta) and
                3 of ($tpl_*)
            )
        )
}
