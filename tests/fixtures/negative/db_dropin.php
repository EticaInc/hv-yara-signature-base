<?php
/**
 * Legitimate database drop-in of the kind shipped by caching plugins.
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }
class Cache_DB_Dropin { public function query( $sql ) { return $sql; } }
