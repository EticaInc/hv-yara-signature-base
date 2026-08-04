rule JS_Obfuscated_Downloader_CUST {
    meta:
        description = "Detects obfuscated JavaScript downloader/injector malware commonly appended to legitimate JS files."
        author = "Security Team"
        severity = "CRITICAL"
        date = "2026-06-07"
        hash_cf7 = "a46ff4a1b17acc84b7895bdd31277b4de7ab9dfaef1393b18437e9f64377e353"
        hash_woo = "d8eb97deb94c2f9be2bcad489afe9399dc329d5afe926ba794b386306158d55f"
    strings:
        $vqsq = "vqsq" ascii
        $a0g = "function a0g()" ascii
        $a0x = "function a0x(" ascii
        $token = "token=function()" ascii
        $httpclient = "HttpClient=function()" ascii
        $dec_loop = "while(!![]){try{var X=-parseInt(" ascii
    condition:
        filesize < 300KB and ($vqsq and $a0g and $a0x and ($token or $httpclient or $dec_loop))
}
