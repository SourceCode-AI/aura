FROM python:3.9-buster


RUN addgroup gitpod && adduser -S -G gitpod gitpod


USER gitpod
RUN curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -
RUN source $HOME/.poetry/env && poetry config virtualenvs.create false
