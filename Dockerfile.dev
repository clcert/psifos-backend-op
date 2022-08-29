FROM python:3.10

COPY ./requirements.txt /tmp/requirements.txt

RUN pip install -r /tmp/requirements.txt

COPY ./ /app

WORKDIR /app

CMD uvicorn app.main:app --host 0.0.0.0 --port 8000
