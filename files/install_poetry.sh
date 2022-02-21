#!/bin/sh

curl -sSL https://install.python-poetry.org | python3 -
retVal=$?

if [ $retVal -ne 0 ]; then
  cat poetry-installer-error-*.log >/dev/stderr
  exit $retVal
fi

poetry config virtualenvs.create false
