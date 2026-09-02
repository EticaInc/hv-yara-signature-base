rule PHP_Numeric_Dispatch_Loader_CUST {
    meta:
        description = "Detects a PHP loader that reverses a delimited function-name table into numeric variable dispatch"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-09-02"
        hash = "2e3564913a427750845f6f491071852322e63a325c4bef35bf371d17b3588d90"
    strings:
        $php = "<?php" ascii
        $reversed_table = "teg_ini1ledoced_46esab1lbolg1lrhc1ledocne_46esab" ascii
        $delimiter = "explode(\"1l\"," ascii
        $reverse = "array_reverse(" ascii
        $split = "PREG_SPLIT_NO_EMPTY" ascii
        $globals = "$GLOBALS[" ascii
    condition:
        filesize < 100KB and $php and $reversed_table and $delimiter and 3 of ($reverse, $split, $globals)
}

rule PHP_Split_Base64_Eval_Loader_CUST {
    meta:
        description = "Detects a PHP loader that reconstructs base64_decode from string fragments and evaluates the decoded payload"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-09-02"
        hash = "45cab225115937554c7c43cc7318c941c2d3bed0ee604606c2c8d256632be726"
    strings:
        $php = "<?php" ascii
        $split_decoder = "array_map(\"base64\".\"_deco\".\"de\"" ascii
        $strip_spaces = "str_replace(\" \",\"\"" ascii
        $mapped_eval = "eval($ftkkzwyqklz[0])" ascii
    condition:
        filesize < 100KB and $php and all of ($split_decoder, $strip_spaces, $mapped_eval)
}

rule PHP_Self_Embedded_Rot13_Loader_CUST {
    meta:
        description = "Detects a self-embedded PHP loader that reverses ROT13/base64 data and evaluates it through preg_replace"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-09-02"
        hash = "96b2ad93d46ebed202db7cafcee19ab5d97cafecc19e8b494167c4bcae493b34"
    strings:
        $php = "<?php" ascii
        $self_read = "explode(base64_decode(\"Pz4=\"),file_get_contents(__FILE__))" ascii
        $decode_chain = "base64_decode(strrev(str_rot13(" ascii
        $eval = "serialize(eval(" ascii
        $replace = "preg_replace(" ascii
    condition:
        filesize < 100KB and $php and all of ($self_read, $decode_chain, $eval, $replace)
}

rule PHP_Revert_Data_Eval_Loader_CUST {
    meta:
        description = "Detects a PHP loader that reverses a keyed transformed-data format and evaluates the recovered content"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-09-02"
        hash = "2981a21a09df59e872ebb2585f4fc53001fbd89ea46c1ef12042f89245b5d5e3"
    strings:
        $php = "<?php" ascii
        $payload = "$transformedResult =" ascii
        $revert = "function revert_data(" ascii
        $safe_revert = "function safe_revert(" ascii
        $key = "hash('sha256', 'framework', true)" ascii
        $eval = "eval($revertedContent)" ascii
    condition:
        filesize < 100KB and $php and all of ($payload, $revert, $safe_revert, $key, $eval)
}

rule PHP_FilesQuarantines_AES_Loader_CUST {
    meta:
        description = "Detects a fake WordPress skeleton file that decrypts and evaluates an embedded AES-256-CBC payload"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-09-02"
        hash = "dbfabce948a98aaee435b4afe6096ff65c04175f51e12952261dcb813424174b"
    strings:
        $php = "<?php" ascii
        $class = "class FilesQuarantines" ascii
        $decryptor = "aesEcbDecLegacy" ascii
        $cipher = "AES-256-CBC" ascii
        $payload = "generateEncryptedCertStringFromCsr" ascii
        $eval = "eval($sendMessage)" ascii
    condition:
        filesize < 100KB and $php and all of ($class, $decryptor, $cipher, $payload, $eval)
}

rule PHP_UserAgent_RC4_Loader_CUST {
    meta:
        description = "Detects a PHP loader that decrypts a comment payload with a User-Agent-derived RC4-like stream before evaluation"
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-09-02"
        hash = "137a0eec5cc2a5a910bd21f3bf39f4eb2e2114db1146e291d562f113e63c564d"
    strings:
        $php = "<?php" ascii
        $comment_extract = "preg_match('#/\\*(.*?)\\*/#si'" ascii
        $user_agent = "$_SERVER['HTTP_USER_AGENT']" ascii
        $key_hash = "$key = md5($key)" ascii
        $stream = "$box[$i]=ord($key[$i%$key_length])" ascii
        $integrity = "substr(md5(substr($result,8).$key),0,8)" ascii
        $eval = "eval($result)" ascii
    condition:
        filesize < 100KB and $php and all of ($comment_extract, $user_agent, $key_hash, $stream, $integrity, $eval)
}
