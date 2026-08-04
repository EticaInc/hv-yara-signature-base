rule TEXT_Fake_PNG_Cred_Dump_CUST {
    meta:
        description = "Detects files containing dumped colon-separated credentials (often disguised as fake PNGs) matching a specific stealer variant format."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-04-12"
        hash = "Stained_Heart_Red-600x500.png"
    strings:
        // Frequent base64-encoded spacer lines used by this specific stealer variant
        $spacer1 = "U1xLElwWDVdFCFFbB3QMC1YLRhUUHFAXAw8GQBkAXlsDChIIY2EAXFweagdW" ascii
        $spacer2 = "WF1VCFcCIXMLAlddUgBZQ3hBEQ==" ascii
        $spacer3 = "VUxTBFtKGlNcJENdAkYEBFkLQQlIBl0IWFNSAQEaUF4JCRk=" ascii
        $spacer4 = "WF1VCFdaAlFZEUAEVlJXUglYTzhfVFwLJQYPelUpRFVKYw==" ascii

        // Spacer prefixes removed to fix compilation error

        // Regex for Email:Password format (e.g., user@domain.com:Password123)
        // Restricted to start at line boundaries and only use printable ascii for the actual password
        $email_pass = /(^|\n)[a-zA-Z0-9\.\_\+\-]{3,50}\@[a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,10}\:[\x21-\x7E]{5,50}(\r|\n|$)/ ascii

        // Actual binary Magic Bytes to prevent false positives on valid target files
        $fp_png = { 89 50 4E 47 0D 0A 1A 0A }
        $fp_jpg = { FF D8 FF }
        $fp_bmp = "BM"
        $fp_gif = "GIF8"
        $fp_zip = "PK\x03\x04"
        $fp_php = "<?php" ascii

    condition:
        // Artificial file size limit to prevent massive log scanning
        filesize < 5MB and

        // Ensure this isn't a legitimate binary file or a PHP script
        not $fp_png at 0 and
        not $fp_jpg at 0 and
        not $fp_bmp at 0 and
        not $fp_gif at 0 and
        not $fp_zip at 0 and
        not $fp_php at 0 and

        (
            // Match the exact variant's spacer lines
            any of ($spacer*) or
            // OR broadly match 4 or more dumped email/password pairs
            #email_pass > 3
        )
}
