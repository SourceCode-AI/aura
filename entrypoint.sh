#!/bin/bash
set -e


if [ $1 == "run_tests" ]; then
    cd /analyzer
    exec pytest --cov=aura --cov-report xml --cov-report term tests/

    if [[ -z "${CODECOV_TOKEN}" ]]; then
      bash <(curl -s https://codecov.io/bash)
    fi

    exit
fi;

if [ $1 == "make_docs" ]; then
  cd /analyzer
  poetry install
  cd /analyzer/docs
  make html
  exit
fi;

exec aura "$@"
