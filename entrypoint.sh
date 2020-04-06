#!/bin/bash
set -e

AURA_CFG=${AURA_CFG:=/config/config.ini}
PTH=$(dirname $AURA_CFG)
CWD=$(pwd)

if [ ! -f "$AURA_CFG" ] && [ $PTH == "/config" ]; then
    echo "Configuration file does not exists. Copying from examples..." >>/dev/stderr
    cd /analyzer
    cp config.ini /config/config.ini
    cp files/example_rules.yara /config/rules.yara
    cp files/pypi_stats.json /config/pypi_stats.json
    echo "CFG path: ${AURA_CFG}" >>/dev/stderr
    tree /config >>/dev/stderr
    cd $CWD
fi

if [ ! -f "/config/signatures" ] && [ $PTH == "/config" ]; then
  cp /analyzer/signatures.json /config/signatures.json
fi

if [ $1 == "run_tests" ]; then
    cd /analyzer
    #rm .coverage || true
    #echo |sqlite3 .coverage
    exec pytest --no-cov tests/
fi;

export AURA_CFG
exec aura "$@"
