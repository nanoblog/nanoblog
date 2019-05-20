FROM phusion/baseimage:0.11
MAINTAINER github.com/nanoblog/nanoblog

COPY ./nanoblog-linux-amd64 /usr/bin/nanoblog
COPY ./entrypoint.sh /usr/local/bin/entrypoint.sh

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y tzdata

RUN chmod +x /usr/bin/nanoblog /usr/local/bin/entrypoint.sh

ENTRYPOINT [ "/usr/local/bin/entrypoint.sh" ]

CMD [ "/sbin/my_init" ]
