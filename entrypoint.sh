#!/bin/bash
set -e


if [ $1 == "run_tests" ]; then
    cd /analyzer
    exec pytest --cov=aura tests/
fi;

exec aura "$@"
