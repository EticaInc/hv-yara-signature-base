rule PHP_Polymorphic_POST_Dropper_CUST {
    meta:
        description = "Detects a polymorphic PHP POST dropper that decodes keyed data and writes a random PHP file into a writable directory"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-09-02"
        hash = "08dc038812b139651101dada3088efdd6edef6cda5f1b2fc6c4d65b733937395"
    strings:
        $php = "<?php" ascii
        $uuid = /[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/ ascii
        $post_loop = "foreach ($_POST as" ascii
        $key_stretch = "array_slice(str_split(str_repeat(" ascii
        $random_php = "substr(md5(time()), 0, 8)" ascii
        $directory_walk = "GLOB_ONLYDIR" ascii
    condition:
        filesize < 20KB and $php and $uuid and $post_loop and $key_stretch and $random_php and $directory_walk
}
