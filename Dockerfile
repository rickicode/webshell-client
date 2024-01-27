FROM debian
MAINTAINER Bitworks Software info@bitworks.software

EXPOSE 80

ENV SSH_PORT 22
ENV USERNAME root
ENV DEFAULT_IP 0.0.0.0
ENV ALLOWED_NETWORKS 0.0.0.0/0
ENV INACTIVITY_INTERVAL 60

COPY ./shellinabox.py ./shellinabox.init /opt/

# RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
RUN apt update -y && apt-get install -y -q python3 shellinabox strace ssh && useradd -ms /bin/bash webshell && chmod 755 /opt/shellinabox.py /opt/shellinabox.init

EXPOSE 10000

ENTRYPOINT ["/opt/shellinabox.init"]
