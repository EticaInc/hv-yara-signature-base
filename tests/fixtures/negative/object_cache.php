<?php
/**
 * Legitimate object-cache.php drop-in, Redis-style.
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }
function wp_cache_init() { $GLOBALS['wp_object_cache'] = new WP_Object_Cache(); }
function wp_cache_get( $key, $group = '', $force = false, &$found = null ) { return false; }
