<?php
/**
 * Legitimate plugin file that happens to contain BOTH include_once and
 * base64_decode — the two markers a heuristic scanner keys on.
 *
 * The LinkFlow rules must key on identity, not on generic obfuscation markers,
 * so this file must not match anything.
 *
 * It is also the inverse of the real finding: the actual coordinator contains
 * zero instances of eval, base64_decode, gzinflate, str_rot13, create_function
 * or assert. Marker-based detection fires here and stays silent there — exactly
 * backwards. That is why these rules exist.
 */

include_once __DIR__ . '/includes/class-settings.php';

function fixture_decode_stored_option( $raw ) {
    // ordinary use: an option persisted base64-encoded by this plugin
    return json_decode( base64_decode( $raw ), true );
}
