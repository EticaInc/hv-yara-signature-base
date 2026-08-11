<?php
/**
 * Minified/short-named but legitimate code. Exercises the rules' precision:
 * short random-looking names alone must not be enough to match.
 */
function ab12($c){return $c*2;}
function cd34($e,$f){$g=($e+50)%7;return $g*$f;}
$h = gzinflate( gzdeflate( 'benign' ) );
