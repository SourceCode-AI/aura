FROM archlinux/base
RUN groupadd -r analysis && useradd -m --no-log-init --gid analysis analysis

RUN pacman -Syyu --noconfirm python python2 python-pip gcc ssdeep python-yara git wget tree
RUN mkdir /analyzer && mkdir /config

ADD requirements.txt setup.py setup.cfg entrypoint.sh config.ini files/pypi_stats.json /analyzer/
ADD aura /analyzer/aura
ADD tests /analyzer/tests
ADD files /analyzer/files

RUN chown -R analysis /analyzer /config && chmod +x /analyzer/entrypoint.sh && find /analyzer -name '*.pyc' -delete -print
RUN cd /analyzer &&pip install -r requirements.txt && python setup.py install && python -c "import aura;"

USER analysis
WORKDIR /analyzer
ENTRYPOINT ["/analyzer/entrypoint.sh"]
CMD ["--help"]
