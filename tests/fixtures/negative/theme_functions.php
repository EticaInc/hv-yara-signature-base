<?php
/**
 * Legitimate child-theme functions.php.
 */
add_action( 'wp_enqueue_scripts', function () {
    wp_enqueue_style( 'child', get_stylesheet_directory_uri() . '/style.css', array(), '1.0.0' );
} );
add_filter( 'body_class', function ( $classes ) { $classes[] = 'child-theme'; return $classes; } );
