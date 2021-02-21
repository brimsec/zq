#!/bin/bash

# zq is currently the only known tool that outputs data in ZNG formats. Sample
# ZNG data from zq is stored in the https://github.com/brimsec/zq-sample-data
# repo. Therefore, if a change in zq causes the ZNG output format to change,
# we'll want to know about it ASAP, since if it's a bug we'll want to fix it
# in zq, and if it's an intentional enhancement we'll want to update the ZNG
# files in zq-sample-data so users are always finding a current copy.
#
# This script automates this check by running the Zeek TSV logs from
# zq-sample-data through zq, produces output in four ZNG variations, and
# checks that the MD5 hashes for the outputs still match the hashes stored
# in the zq-sample-data repo.

# We're intentionally not running with "set -eo pipefail" because we want to
# let all permutations run and allow the final error text to be seen before
# explicitly returning the intended error code.

cd zq-sample-data
scripts/check_md5sums.sh zng
ZNG_SUCCESS="$?"
echo
scripts/check_md5sums.sh zng-uncompressed
ZNG_UNCOMPRESSED_SUCCESS="$?"
echo
scripts/check_md5sums.sh zson
ZSON_SUCCESS="$?"
echo
scripts/check_md5sums.sh tzng
TZNG_SUCCESS="$?"

if (( ZNG_SUCCESS == 0 && TZNG_SUCCESS == 0 && ZNG_UNCOMPRESSED_SUCCESS == 0 && ZSON_SUCCESS == 0)); then
  exit 0
else
  echo
  echo "------------------------------------------------------------------------------"
  echo "Output format has changed. If your work intentionally changed ZNG/ZSON/TZNG"
  echo "output and hence you do not suspect a bug, either update the zq-sample-data"
  echo "repo with new output files and MD5 hashes to make this test pass, or open a zq"
  echo "issue and include the output from this script and someone else will take care"
  echo "of it ASAP."
  exit 1
fi
