<?php
/**
 * Plugin Name:  wp-defence
 * Plugin URI:   https://wpninjas.ch/plugins/wp-defence
 * Version:      1.6.1
 * License:      GPL v2
 *
 * Synthetic fixture — second class-name variant.
 * Identity strings only. No working payload.
 *
 * Targets PHP_WP_Defence_LinkFlow_Coordinator_CUST, branch 2 with $class_b.
 * The actor ships `WP_Defence` and `wpdefence` as separate plugins 65 minutes
 * apart so each defeats the other's class_exists() guard and both load. This
 * fixture is the second one; it also stands in for the third build, which was
 * found as `sucuri-link.php` — a filename that defeats filename-based hunting.
 */

class wpdefence {
    // inert
}
