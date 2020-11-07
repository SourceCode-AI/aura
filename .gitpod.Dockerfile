ARG pythonver=3.8.3
ARG alpinever=3.12
FROM python:${pythonver}-alpine${alpinever}

RUN apk add --no-cache \
    python2 \
    curl \
    automake \
    file-dev \
    openssl-dev \
    autoconf \
    libtool \
    build-base \
    git

RUN addgroup gitpod && adduser -S -G gitpod gitpod


USER gitpod
RUN curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -
RUN source $HOME/.poetry/env && poetry config virtualenvs.create false
