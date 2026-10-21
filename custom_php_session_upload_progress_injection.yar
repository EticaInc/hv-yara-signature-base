/*
   PHP session.upload_progress injection artifacts (php2shell, CVE-2026-109619 related)
   ------------------------------------------------------------------
   The CVE-2026-109618 / CVE-2026-109619 memory corruption itself leaves nothing on
   disk. These rules detect the session-file artifact of the upload_progress
   technique used by the public php2shell PoC: attacker-controlled upload filenames
   or progress names written raw into a PHP session file.

   Anchored on the upload-progress array keys PHP always serializes (start_time,
   content_length, bytes_processed, done, files), so they work for the php,
   php_serialize and php_binary handlers and for any session.upload_progress.prefix.

   Session save paths (/var/lib/php/session*, /tmp, ea-php session dirs) are outside
   scheduled scan scope; use a manual --target scan of the session directory.
   The artifact is transient when session.upload_progress.cleanup=On (default).
*/

rule PHP_Session_UploadProgress_Code_Injection_CUST {
    meta:
        description = "PHP session file holding a session.upload_progress tracking array plus a PHP open tag, from a malicious upload filename or progress name (php2shell / upload_progress LFI-to-RCE session injection artifact)"
        author = "Security Team"
        severity = "HIGH"
        date = "2026-10-21"
        reference = "CVE-2026-109619, GHSA-6wmf-4rv5-p3rp"
    strings:
        $k1 = "s:10:\"start_time\";i:" ascii
        $k2 = "s:14:\"content_length\";i:" ascii
        $k3 = "s:15:\"bytes_processed\";i:" ascii
        $k4 = "s:4:\"done\";b:" ascii
        $k5 = "s:5:\"files\";a:" ascii
        $tag = "<?" ascii
    condition:
        filesize < 1MB and 4 of ($k*) and $tag
}

rule PHP_Session_UploadProgress_Object_Injection_CUST {
    meta:
        description = "PHP session upload_progress entry whose uploaded filename carries a pipe followed by a serialized object (php/php_serialize session handler mismatch object injection, php2shell chain)"
        author = "Security Team"
        severity = "MEDIUM"
        date = "2026-10-21"
        reference = "CVE-2026-109619, GHSA-6wmf-4rv5-p3rp"
    strings:
        $k1 = "s:10:\"start_time\";i:" ascii
        $k2 = "s:15:\"bytes_processed\";i:" ascii
        $k3 = "s:5:\"files\";a:" ascii
        $obj = /s:4:"name";s:[0-9]{1,5}:".{0,256}\|[OC]:[0-9]{1,5}:"/s
    condition:
        filesize < 1MB and 2 of ($k*) and $obj
}
