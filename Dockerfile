FROM python:3
RUN mkdir /LogStream
WORKDIR /LogStream
COPY requirements.txt /LogStream/
RUN pip install -r requirements.txt
COPY . /LogStream/
