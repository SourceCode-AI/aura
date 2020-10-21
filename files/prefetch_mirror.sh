#!/bin/bash
set -e

if [ "$#" -ne 1 ]; then
  echo "You must provide a path to the offline PyPI mirror web folder" >>2;
  exit 1;
fi;

if [ ! -d "${AURA_MIRROR_PATH}/json" ]; then
  echo "JSON directory not found at ${AURA_MIRROR_PATH}. You probably have not provided a correct path to the web mirror directory" >>2;
  exit 1;
fi

export AURA_MIRROR_PATH=$1;
PKGS=$(cat aura_mirror_scan/package_cache)

prefetch() {
  AURA_NO_PROGRESS=true aura scan --download-only mirror://$1
}

export -f prefetch
echo "Starting prefetch of mirror packages into cache"
echo $PKGS|tr ' \r' '\n'| parallel --progress --timeout 600 --max-args 1 prefetch
