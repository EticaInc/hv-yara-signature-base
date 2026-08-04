rule PHP_SDCZZ_PHPDecryptor_Backdoor_CUST
{
    meta:
        description = "Detects the SDCZZ (sdczz.com) PHPDecryptor encrypted backdoor. Uses AES-256-GCM chunked encryption with base64-encoded payloads stored in class properties (fileKey, salt, integrityHash, chunks). Decrypts and eval()s arbitrary code at runtime via a closure-based execution pattern that injects variables into the global scope."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-06-26"
        hash = "ab28ecc7f1ca4bae0186589084ae826092748e87f177337684d667fc1a894905"

    strings:
        $php = "<?php" ascii

        // PHPDecryptor class structure
        $class_decl = "class PHPDecryptor" ascii
        $prop_filekey = "$fileKey" ascii
        $prop_salt = "$salt" ascii
        $prop_integrity = "$integrityHash" ascii
        $prop_chunks = "$chunks" ascii

        // Decryption and execution logic
        $decrypt_func = "decryptChunks" ascii
        $verify_func = "verifyIntegrity" ascii
        $aes_gcm = "aes-256-gcm" ascii
        $eval_code = "eval('?>' . $code)" ascii

        // Global scope injection pattern
        $globals_inject = "$GLOBALS[$name] = $value" ascii
        $capture_vars = "capture_vars" ascii
        $get_defined = "get_defined_vars()" ascii

        // Instantiation trigger
        $new_inst = "new PHPDecryptor()" ascii

    condition:
        $php at 0 and
        filesize < 1MB and
        $class_decl and
        all of ($prop_*) and
        $decrypt_func and
        $verify_func and
        $aes_gcm and
        ($eval_code or ($globals_inject and $capture_vars and $get_defined)) and
        $new_inst
}

rule PHP_SDCZZ_Obfuscated_Payload_CUST
{
    meta:
        description = "Detects SDCZZ (sdczz.com / 声达网络加密) obfuscated PHP payloads. These files contain a massive base64/custom-encoded string assigned to a variable with a confusing alphanumeric name pattern (e.g., $GII10OOII1l), prefixed with the SDCZZ encryption branding comment. Used as encrypted backdoor payloads within fake WordPress plugins."
        author = "Security Team"
        severity = "HIGH"
        date = "2026-06-26"
        hash = "4b7406c0197c86088e23ef6f140b30f431c76c821fdd347976a49de2cd9199ab"

    strings:
        $php = "<?php" ascii

        // SDCZZ encryption branding (Chinese and English)
        $brand_cn = /\/\*\s*sdczz\.com\s+\xe5\xa3\xb0\xe8\xbe\xbe\xe7\xbd\x91\xe7\xbb\x9c\xe5\x8a\xa0\xe5\xaf\x86/ ascii
        $brand_en = "HIGH SECURITY ENCRYPTION - SDCZZ.COM" ascii

        // Variable assignment pattern: variable name uses mixed-case and digits in a confusing pattern
        $var_assign = /\$[A-Z]{1,3}[I10O]{3,}[A-Za-z0-9]{1,5}\s*=\s*"[A-Za-z0-9\/\+=]{100,}/ ascii

    condition:
        $php at 0 and
        filesize < 500KB and
        ($brand_cn or $brand_en) and
        $var_assign
}
