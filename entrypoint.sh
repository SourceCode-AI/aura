#!/bin/bash
set -e

AURA_CFG=${AURA_CFG:=/config/config.ini}
PTH=$(dirname $AURA_CFG)
CWD=$(pwd)

if [ ! -f "$AURA_CFG" ] && [ $PTH == "/config" ]; then
    echo "Configuration file does not exists. Copying from examples..." >>/dev/stderr
    cd /analyzer
    cp config.ini /config/config.ini
    cat files/example_signatures.json | sed -e 's/^\s*#.*$//' >/config/signatures.json
    cp files/example_rules.yara /config/rules.yara
    cp files/pypi_stats.json /config/pypi_stats.json
    echo "CFG path: ${AURA_CFG}"
    tree /config
    cd $CWD
fi

if [ $1 == "run_tests" ]; then
    cd /analyzer
    exec pytest --cov aura tests/
fi;

export AURA_CFG
exec aura "$@"
