rule PHP_WP_Remote_File_Dropper_CUST
{
    meta:
        description = "Detects a PHP file dropper disguised as a WordPress widget file (class-wp-widget-tag.php). Downloads remote payloads from ecolider.pl and writes them to legitimate WordPress and Joomla paths. Accompanied by a malicious php.ini that disables safe_mode and all security functions."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-06-26"
        hash = "cd40bdd3ba7c9fec8e3d238b93145b4ad44c361c81eaec7621bd10892adbecd2"

    strings:
        $php = "<?php" ascii

        // Remote download URL and path construction
        $url_ecolider = "ecolider.pl" ascii
        $path_widget = "/wp-includes/widgets/class-wp-widget-tag" ascii
        $path_joomla = "/administrator/includes/faq.php" ascii

        // HTTP download function pattern
        $http_func = "function http_get(" ascii
        $curl_return = "CURLOPT_RETURNTRANSFER" ascii
        $curl_follow = "CURLOPT_FOLLOWLOCATION" ascii

        // File write after remote fetch
        $doc_root = "$_SERVER['DOCUMENT_ROOT']" ascii
        $fwrite = "fwrite(" ascii
        $fopen_w = "fopen(" ascii

    condition:
        $php at 0 and
        filesize < 3KB and
        $url_ecolider and
        all of ($path_*) and
        $http_func and
        $curl_return and
        $curl_follow and
        $doc_root and
        $fwrite and
        $fopen_w
}
