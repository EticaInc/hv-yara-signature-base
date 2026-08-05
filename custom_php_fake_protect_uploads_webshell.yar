/*
    Both rules below detect webshells found dropped as index.php inside a
    wholesale clone of the legitimate "Protect Uploads" plugin
    (alticreation.com/en/protect-uploads/, normal index.php is a tiny
    directory-listing stub). The rest of the cloned plugin (protect-uploads.php,
    admin/, includes/, languages/) is byte-identical to the real plugin and used
    purely as camouflage -- do NOT key any rule here off the plugin's real files
    or its directory layout, only off the malicious index.php content itself,
    since the genuine plugin is legitimately installed on unrelated sites.
*/

rule PHP_HEX80_FileManager_Webshell_CUST {
    meta:
        description = "Detects the unauthenticated 'HEX' file manager webshell (credited to Telegram handle @HEX80), found dropped as index.php inside a cloned copy of the legitimate Protect Uploads plugin."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-08-05"

    strings:
        $php = "<?php" ascii

        // Author credit link embedded in the shell's UI footer
        $credit = "t.me/HEX80" ascii

        // UI title + distinctive helper function names
        $title = "<title>HEX</title>" ascii
        $func_cekdir = "function cekdir()" ascii
        $func_cekroot = "function cekroot()" ascii

        // Distinctive (Indonesian-slang) parameter names used for unauthenticated
        // file upload / delete / rename / edit actions
        $param_upwkwk = "'upwkwk'" ascii
        $param_berkasnya = "'berkasnya'" ascii
        $param_pilihan = "'pilihan'" ascii

    condition:
        filesize < 3MB and $php and
        (
            $credit
            or
            ($title and (1 of ($func_*)))
            or
            (2 of ($param_*))
        )
}

rule PHP_X7ROOT_FileManager_Webshell_CUST {
    meta:
        description = "Detects the unauthenticated 'X7ROOT File Manager' webshell, found dropped as index.php inside a cloned copy of the legitimate Protect Uploads plugin."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-08-05"

    strings:
        $php = "<?php" ascii

        // Banner comment and UI title/heading unique to this shell
        $banner = "Dark X7ROOT X7ROOT File Manager" ascii
        $title = "X7ROOT File Manager" ascii

        // Distinctive helper function signatures defined verbatim in the shell
        $func_write = "function writeFile($file, $data)" ascii
        $func_read = "function readFileContent($file)" ascii
        $func_scan = "function scanDirectory($dir)" ascii

    condition:
        filesize < 3MB and $php and
        (
            $banner
            or
            $title
            or
            (2 of ($func_*))
        )
}
