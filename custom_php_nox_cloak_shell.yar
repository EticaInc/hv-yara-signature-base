rule PHP_NOX_Cloak_Shell_CUST {
    meta:
        description = "Detects the 'NOX' single-file cloaking backdoor / panel (dropped here as wp-security.php). It authenticates via a token whose sha256 hash it writes into its own source (self-rewriting define('_NOX_HASH',...) with forced OPcache invalidation to beat token churn), exposes a hidden ?wpmc=1 panel, and installs a UA-gated cloak by writing a 'NOX-RENDER-PREPEND-V1' prepend into the docroot index.php that serves spam/doorway content to crawlers while keeping the original site at a hidden .render-orig.php dotfile. Includes a base64-parameter file manager. Turkish operator comments throughout."
        author = "Security Team"
        family = "NOX cloak shell"
        severity = "CRITICAL"
        date = "2026-09-23"
        hash = "fee68741846350f457d6c6291574e76050e2aa4868a2d0f7f784eee5835c4a49"

    strings:
        $php = "<?php" ascii

        // --- NOX family identifiers ---
        $nox_hash = "_NOX_HASH" ascii
        $nox_prepend = "NOX-RENDER-PREPEND-V1" ascii
        $nox_render = "NOX-RENDER" ascii
        $nox_panel = "_nox_panel" ascii
        $render_orig = ".render-orig.php" ascii
        $cloak_comment = "vi-fm3-cloak" ascii

        // --- Behavioral markers (technique, less tied to the NOX name) ---
        // Hidden panel gate. Whitespace/quote-tolerant: the literal form
        // "$_GET['wpmc']==='1'" is defeated by ordinary PHP formatting (a
        // single space around ===, or double quotes on the key), and this is
        // one of only two strings gating branch (b), so a brittle match there
        // would quietly disable the rename-resistant branch.
        $wpmc_gate = /\$_GET\s*\[\s*['"]wpmc['"]\s*\]\s*===?\s*['"]1['"]/ ascii
        // Self-rewriting single-file token auth: compare a hardcoded CONST hash
        // against sha256 of the request token
        // hash_equals() takes its arguments in either order without changing
        // behaviour, so both are matched; keying on one of them let a swap of the
        // two arguments silence this branch.
        $token_auth = /hash_equals\(\s*_?[A-Z][A-Z0-9_]{3,}\s*,\s*hash\(\s*['"]sha256['"]\s*,/ ascii
        $token_auth_rev = /hash_equals\(\s*hash\(\s*['"]sha256['"]\s*,[^;]{0,160}\)\s*,\s*_?[A-Z][A-Z0-9_]{3,}/ ascii
        // Self-modifying persistence: rewrites its own file and force-invalidates
        // OPcache so the next request sees the new copy. Whitespace-tolerant for the
        // same reason as $wpmc_gate above -- as bare literals, a single space after
        // the opening parenthesis defeated branch (c).
        $self_write = /file_put_contents\s*\(\s*__FILE__/ ascii
        $opcache_self = /opcache_invalidate\s*\(\s*__FILE__/ ascii

    condition:
        // PHP marker, but not anchored at byte zero: PHP enters code mode wherever the
        // opening tag appears, so a UTF-8 BOM, a stray newline or leading HTML -- all
        // confirmed to still execute against PHP 8.3 -- would otherwise disable every
        // branch below, which a single prepended newline makes trivial to arrange.
        filesize < 3MB and $php and
        (
            // (a) NOX family literals -- highest confidence
            2 of ($nox_hash, $nox_prepend, $nox_panel, $render_orig, $cloak_comment)
            or
            // (b) self-rewriting single-file token auth + hidden panel gate
            (1 of ($token_auth, $token_auth_rev) and $wpmc_gate)
            or
            // (c) self-modifying persistence that plants a NOX render-prepend
            ($self_write and $opcache_self and 1 of ($nox_render, $nox_prepend, $nox_panel))
        )
}
