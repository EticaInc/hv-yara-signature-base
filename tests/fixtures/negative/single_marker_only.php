<?php
/**
 * Negative control for PHP_Supervueity_Obfuscator_CUST.
 *
 * Carries exactly ONE of the four markers, so the rule's "2 of" threshold must hold and this
 * must NOT match. Pairs with tests/fixtures/positive/obfuscator_two_markers.php: together they
 * pin the threshold from both sides, so loosening the rule to "1 of" fails a named test
 * instead of quietly widening into false positives.
 */

$charles_multiapiment = 1;
