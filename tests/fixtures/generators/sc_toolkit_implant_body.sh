#!/usr/bin/env bash
#
# Generates a positive fixture for PHP_SC_Toolkit_Implant_Body_CUST.
#
# That rule has a `filesize > 50KB` floor, so the fixture has to be bulky. It is generated at
# run time rather than committed, to keep a large malware-shaped artifact out of the repository.
#
# Reproduces four structural traits the rule keys on -- the obfuscated ABSPATH guard, the
# constant-returning trampolines, the arithmetic-noise padding, and the decoder init -- and
# nothing else. There is no payload, no cipher table, no network code and no persistence logic;
# the trampolines return array indices from a one-element array and the noise helpers do
# arithmetic on their arguments.
#
# Usage: sc_toolkit_implant_body.sh <output-path>
#
set -euo pipefail
out="${1:?usage: $0 <output-path>}"

{
  echo '<?php'
  # decoder init + guard, matching $decoder_ws and the randomly-named-function shape
  echo 'if(!function_exists('"'"'fixtureimplant01'"'"')){function fixtureimplant02($i){static $a=null;if($a===null){$a=array(0);}return $a[$i];}}'
  # obfuscated direct-access guard, with the whitespace insertion the rule tolerates
  echo 'defined(fixtureimplant02(0))     or    exit;'
  # $gz and $mu anchors
  echo '$z = WPMU_PLUGIN_DIR; $y = gzinflate("");'
  # trampolines and arithmetic noise, enough to clear both the 50KB floor and #trampoline > 8
  for i in $(seq 1 900); do
    echo "function fixtureimp_t${i}(){return fixtureimplant02(${i});}"
    echo "function fixtureimp_n${i}(\$a${i},\$b${i}){\$c${i}=(\$a${i}+${i})%7;return \$c${i}*\$b${i};}"
  done
} > "$out"
