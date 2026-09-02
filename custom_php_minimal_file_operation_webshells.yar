rule PHP_Minimal_Rename_Uploader_CUST {
    meta:
        description = "Detects a minimal PHP webshell that renames attacker-selected paths and accepts arbitrary uploads"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-09-02"
        hash = "030d20dc56909c3a22b4d45455b79454479dbca05599013b2561ca70b80842f1"
    strings:
        $php = "<?php" ascii
        $rename_source = "rename(trim($_POST['fname']), trim($_POST['sname']))" ascii
        $upload = "move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name'])" ascii
    condition:
        filesize < 10KB and $php and $rename_source and $upload
}

rule PHP_Minimal_GET_File_Writer_CUST {
    meta:
        description = "Detects a minimal PHP webshell that downloads attacker-selected content to an attacker-selected document-root path"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-09-02"
        hash = "3281b40225caaa99bf9024fb5ba9e0ece2c2153c154bbfd1d0525678dcacf7db"
    strings:
        $php = "<?php" ascii
        $destination = "$_SERVER['DOCUMENT_ROOT'].$_GET['a']" ascii
        $source = "$_GET['b']" ascii
        $download = "file_get_contents($b)" ascii
        $open = "fopen($a, \"w\")" ascii
        $write = "fwrite($fp,$acticle" ascii
    condition:
        filesize < 10KB and $php and all of ($destination, $source, $download, $open, $write)
}
