<?php
/**
 * Synthetic theme functions.php with the injected tail block reproduced in shape only.
 */
add_action( 'wp_enqueue_scripts', 'fixture_enqueue' );
function fixture_enqueue() { wp_enqueue_style( 'fixture', get_stylesheet_directory() . '/style.css' ); }
?>
<?php

/* SC_TH_BEGIN:4.0.3:9eb24bb1 */
if(!function_exists('fixturealpha01')){function fixturebeta02($i){static $a=null;if($a===null){$a=array(0,1,2);}return $a[$i];}}
/* SC_TH_END:4.0.3:9eb24bb1 */
