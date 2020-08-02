FROM python:3.8.3-alpine3.12

# This is a specific order of installing the dependencies first so we can use caching mechanism to quickly rebuild the image in case only aura source code changed
RUN addgroup analysis && adduser -S -G analysis analysis

RUN apk add --no-cache \
    python2 \
    curl \
    automake \
    file-dev \
    openssl-dev \
    autoconf \
    libtool \
    git \
    build-base \
    libxml2-dev \
    libxslt-dev \
    tree

RUN mkdir /analyzer && \
    mkdir /config && \
    curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python

WORKDIR /analyzer

# Aura specific installation steps
ADD custom_analyzer.py \
    entrypoint.sh \
    rules.yara \
    signatures.json \
    config.ini \
    LICENSE.txt \
    README.md \
    pyproject.toml \
    poetry.lock \
    files/pypi_stats.json \
    /analyzer/

ADD aura /analyzer/aura
ADD tests /analyzer/tests
ADD files /analyzer/files

# Install Aura
RUN cd /analyzer &&\
    source $HOME/.poetry/env && \
    poetry config virtualenvs.create false && \
    poetry install -E full &&\
    python -c "import aura;"  &&\
    find /analyzer -name '*.pyc' -delete -print &&\
    chown -R analysis /analyzer /config &&\
    chmod +x /analyzer/entrypoint.sh &&\
    chmod 777 -R /analyzer

USER analysis
ENTRYPOINT ["/analyzer/entrypoint.sh"]
CMD ["--help"]
