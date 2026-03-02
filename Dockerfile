FROM ubuntu:latest

RUN apt update

RUN apt install -y cmake libelf-dev libzydis-dev zydis-tools libreadline-dev

ADD . /sdb

WORKDIR /sdb

RUN cmake src/ && cmake --build .

RUN cp /sdb/sdb /usr/bin/sdb