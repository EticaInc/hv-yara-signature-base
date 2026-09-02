rule PHP_Comment_Fragmented_Request_Backdoor_CUST {
    meta:
        description = "Detects comment-fragmented PHP backdoors that combine cookie and POST data before dynamic execution"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-09-02"
        hash = "49186378892379aa5b91df5e756e5d7e983a19ae9bd1a855e2a319fd357b24a6"
    strings:
        $php = "<?php" ascii
        $cookie = "$_COOKIE" ascii
        $post = "$_POST" ascii
        $comment_noise = /\/\*\s*[A-Za-z_]{1,12}\s*\*\// ascii

        $eval = "eval" ascii
        $die = "die" ascii
        $explode = "explode" ascii
        $pack = "pack" ascii
        $chr = "chr" ascii

        $merge = "array_merge" ascii
        $base64 = "base64_decode" ascii
        $unserialize = "unserialize" ascii
        $file_put = "file_put_contents" ascii
        $include = "include" ascii
        $unlink = "unlink" ascii
    condition:
        filesize < 20KB and $php and $cookie and $post and #comment_noise >= 3 and
        (
            ($eval and $die and $explode and 1 of ($pack, $chr)) or
            ($merge and $base64 and $unserialize and $file_put and $include and $unlink)
        )
}
