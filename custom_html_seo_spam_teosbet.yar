rule HTML_SEO_Spam_Teosbet_CUST {
    meta:
        description = "Detects a Turkish gambling SEO-spam / doorway page for the 'Teosbet' (and paired 'Realbahis') betting brand, of the kind dropped onto compromised WordPress sites (here as amp.php). The page is pure HTML/JS promoting a betting site while carrying a canonical tag pointing at the hijacked host -- parasite SEO. Keyed on the campaign's doorway-generator host scheme <brand>.guncelgirisYYYY.club plus the brand tokens, so it generalises across the campaign's rotating brand subdomains and yearly host rolls. Sibling of the existing Madridbet / Celtabet gambling-spam rules."
        author = "Security Team"
        family = "Teosbet gambling SEO spam"
        severity = "HIGH"
        date = "2026-09-23"
        hash = "ee6b7923897183b5e122d4cb864bcd2d3d42869d36310dc9369636329907fd20"

    strings:
        // Light file-type anchor: these are served HTML doorway pages.
        $doctype = "<!DOCTYPE html" ascii nocase

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

    condition:
        filesize < 2MB and $doctype and
        (
            // (a) campaign doorway host + a gambling brand -> conclusive
            ($doorway_host and 1 of ($brand_teosbet, $brand_realbahis))
            or
            // (b) heavy Teosbet doorway branding + Realbahis pairing + login
            //     phrasing, resilient if the doorway host rotates away
            (#brand_teosbet > 10 and $brand_realbahis and 1 of ($tr_login, $kw_meta))
        )
}
