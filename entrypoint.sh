#!/bin/bash
set -e


if [ $1 == "run_tests" ]; then
    cd /analyzer
    exec pytest --cov=aura --cov-report xml --cov-report term tests/

    if [[ -d "/shared" && -f coverage.xml ]]; then
      echo "Copying coverage report to the /shared folder"
      cp coverage.xml /shared/
    fi

fi;

exec aura "$@"
