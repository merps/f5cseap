FROM python:3
ENV PYTHONUNBUFFERED 1
RUN mkdir /logstream
WORKDIR /code
COPY requirements.txt /logstream/
RUN pip install -r requirements.txt
COPY . /logstream/
