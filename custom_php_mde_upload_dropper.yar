rule PHP_MDE_Upload_Dropper_CUST {
    meta:
        description = "Detects a minimal, unauthenticated file-upload webshell dropper that creates a world-writable mde directory, preserves PHP upload filenames, and returns the uploaded file's public URL."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-07-15"
        hash = "f558954e32b48b010365a8a2f74f877988c6d18bf105dd40e579e0ec5f334877"

    strings:
        $php = "<?php" ascii
        $mkdir_mde = "mkdir('mde', 0777, true)" ascii
        $move_upload = "move_uploaded_file($_FILES['file']['tmp_name'],'mde/'.$file)" ascii
        $ext_check = "pathinfo($_FILES['file']['name'],PATHINFO_EXTENSION)" ascii
        $php_passthrough = "$file=$_FILES['file']['name'];" ascii
        $echo_back = "print_r( $_SERVER['HTTP_HOST'] .'/mde/'.$file);" ascii

    condition:
        $php at 0 and
        filesize < 5KB and
        $mkdir_mde and
        $move_upload and
        (1 of ($ext_check, $php_passthrough, $echo_back))
}
