FROM python:3.7-alpine3.11

# This is a specific order of installing the dependencies first so we can use caching mechanism to quickly rebuild the image in case only aura source code changed
RUN addgroup analysis && adduser -S -G analysis analysis

RUN apk add --no-cache \
    python2 \
    automake \
    file-dev \
    openssl-dev \
    autoconf \
    libtool \
    bison \
    flex \
    git \
    build-base \
    libxml2-dev \
    libxslt-dev \
    tree \
    sqlite

RUN mkdir /analyzer && mkdir /config
ADD requirements.txt /analyzer/
WORKDIR /analyzer

# Install Yara and yara-python bindings
RUN git clone --recursive https://github.com/VirusTotal/yara-python.git &&\
    cd /analyzer/yara-python/yara &&\
    autoreconf -fiv &&\
    ./configure &&\
    make &&\
    make check &&\
    make install &&\
    cd /analyzer/yara-python &&\
    python3 setup.py build &&\
    python3 setup.py install &&\
    python3 tests.py &&\
    cd /analyzer &&\
    rm -r yara-python

RUN cd /analyzer &&\
     pip3 install -r requirements.txt

# Aura specific installation steps
ADD setup.py \
    custom_analyzer.py \
    setup.cfg \
    entrypoint.sh \
    rules.yara \
    signatures.json \
    config.ini \
    LICENSE.txt \
    README.md \
    MANIFEST.in \
    files/pypi_stats.json \
    /analyzer/

ADD aura /analyzer/aura
ADD tests /analyzer/tests
ADD files /analyzer/files

# Install Aura
RUN cd /analyzer &&\
    python setup.py install &&\
    python -c "import aura;"  &&\
    find /analyzer -name '*.pyc' -delete -print &&\
    chown -R analysis /analyzer /config &&\
    chmod +x /analyzer/entrypoint.sh &&\
    chmod 777 -R /analyzer

USER analysis
ENTRYPOINT ["/analyzer/entrypoint.sh"]
CMD ["--help"]
