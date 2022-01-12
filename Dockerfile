ARG pythonver=3.10
ARG alpinever=3.15

FROM python:${pythonver}-alpine${alpinever} AS aura-base

ENV PATH="/root/.local/bin:${PATH}"

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
    build-base \
    libffi-dev \
    git

RUN mkdir /analyzer && \
    curl -sSL https://install.python-poetry.org | python3 - && \
    poetry config virtualenvs.create false

WORKDIR /analyzer

FROM aura-base AS aura-lite

WORKDIR /analyzer

# Aura specific installation steps
ADD custom_analyzer.py \
    entrypoint.sh \
    LICENSE.txt \
    README.rst \
    pyproject.toml \
    poetry.lock \
    /analyzer/

ADD aura /analyzer/aura
ADD tests /analyzer/tests


ENV AURA_NO_CACHE=true

# Install Aura
RUN poetry install --no-dev &&\
    python -c "import aura;"  &&\
    find /analyzer -name '*.pyc' -delete -print &&\
    chmod +x /analyzer/entrypoint.sh &&\
    chmod 777 -R /analyzer  &&\
    cd /analyzer &&\
    aura update

ENTRYPOINT ["/analyzer/entrypoint.sh"]
CMD ["--help"]


FROM aura-lite AS aura-lite-tests

RUN poetry install

RUN pytest tests/

ENTRYPOINT ["/analyzer/entrypoint.sh"]
CMD ["run_tests"]

FROM aura-lite AS aura-full

RUN apk add --no-cache \
    libxml2-dev \
    libxslt-dev \
    postgresql-dev

RUN poetry install --no-dev -E full

ADD docs /analyzer/docs


ENTRYPOINT ["/analyzer/entrypoint.sh"]
CMD ["--help"]


FROM aura-full AS aura-full-tests

RUN poetry install -E full

RUN pytest tests/

ENTRYPOINT ["/analyzer/entrypoint.sh"]
CMD ["run_tests"]
