#!/bin/bash
set -e

export AURA_ALL_MODULE_IMPORTS=true;
export PYTHONWARNINGS=ignore;
export OUTDIR=${AURA_SCAN_DIR:=aura_mirror_scan}


if [[ -z "${AURA_MIRROR_PATH}" ]]; then
  echo "You must set the AURA_MIRROR_PATH env variable!" >>2;
  exit 1
fi;


# Create directory structure
[ -d $OUTDIR ] || mkdir $OUTDIR
[ -d $OUTDIR/package_errors ] || mkdir -p $OUTDIR/package_errors
[ -d $OUTDIR/package_results ] || mkdir -p $OUTDIR/package_results


if [ ! -d "${AURA_MIRROR_PATH}/json" ]; then
  echo "JSON directory not found at ${AURA_MIRROR_PATH}. You probably have not provided a correct path to the web mirror directory" >>2;
  exit 1;
fi

if [ ! -f "$OUTDIR/package_cache" ]; then
  if [ -f $AURA_MIRROR_PATH/pypi_package_list.txt]; then
    cp $AURA_MIRROR_PATH/pypi_package_list.txt $OUTDIR/package_cache;
  else
    ls $AURA_MIRROR_PATH/json >$OUTDIR/package_cache;
fi


PKGS=$(cat $OUTDIR/package_cache)

scan() {
  ERROR_FILE=$OUTDIR/package_errors/$1.errors.log
  RESULTS_FILE=$OUTDIR/package_results/$1.results.json

  AURA_LOG_LEVEL="ERROR" AURA_NO_PROGRESS=true aura scan -f json mirror://$1 -v 1> >(tee -a $RESULTS_FILE |jq .) 2> >(tee -a $ERROR_FILE >&2)
  if [ $? -ne 0 ]; then
    echo $1 >>$OUTDIR/failed_packages.log
  else
    echo $1 >>$OUTDIR/processed_packages.log
  fi

  if [ -s $RESULTS_FILE ]; then
    echo "Removing empty $RESULTS_FILE"
    rm $RESULTS_FILE
  fi

  if [ -s $ERROR_FILE ]; then
    echo "Removing empty $ERROR_FILE"
    rm $ERROR_FILE
  fi

}

export -f scan

echo "Starting Aura scan"

echo $PKGS|tr ' \r' '\n'| parallel --memfree 5G -j30 --progress --resume-failed --timeout 1200 --joblog $OUTDIR/joblog --max-args 1 scan
