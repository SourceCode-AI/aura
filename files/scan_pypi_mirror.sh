#!/bin/bash
set -e

if [ "$#" -ne 1 ]; then
  echo "You must provide a path to the offline PyPI mirror web folder" >>2;
  exit 1;
fi;

export AURA_MIRROR_PATH=$1;
export PYTHONWARNINGS=ignore;
export TEMPDIR=$(dirname $(mktemp -u))


if [ ! -d "${AURA_MIRROR_PATH}/json" ]; then
  echo "JSON directory not found at ${AURA_MIRROR_PATH}. You probably have not provided a correct path to the web mirror directory" >>2;
  exit 1;
fi

if [ ! -f "aura_mirror_scan/package_cache" ]; then
  ls $AURA_MIRROR_PATH/json >aura_mirror_scan/package_cache;
fi

if [ ! -f "aura_mirror_scan/processed_packages.log" ];then
  touch aura_mirror_scan/processed_packages.log
  PKGS=$(cat aura_mirror_scan/package_cache)
else
  PKGS=$(cat aura_mirror_scan/package_cache|fgrep -vf aura_mirror_scan/processed_packages.log)
fi

scan() {
  AURA_LOG_LEVEL="ERROR" AURA_NO_PROGRESS=true aura scan --async -f json mirror://$1 -v 1> >(tee -a "aura_mirror_scan/$1.results.json" |jq .) 2> >(tee -a aura_mirror_scan/$1.errors.log >&2)
  if [ $? -ne 0 ]; then
    echo $1 >>aura_mirror_scan/failed_packages.log
  else
    echo $1 >>aura_mirror_scan/processed_packages.log
  fi

  if [ -s aura_mirror_scan/$1.errors.log ]; then
    rm aura_mirror_scan/$1.errors.log
  fi

}

export -f scan

echo "Starting Aura scan"

echo $PKGS|tr ' \r' '\n'| parallel --load 80 --memfree 5G --progress --timeout 600 --joblog ${TEMPDIR}/aura_pypi_scan_joblog --max-args 1 scan
