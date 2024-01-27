FROM debian
MAINTAINER Bitworks Software info@bitworks.software

EXPOSE 80

ENV SSH_PORT 22
ENV USERNAME root
ENV DEFAULT_IP 0.0.0.0
ENV ALLOWED_NETWORKS 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7
ENV INACTIVITY_INTERVAL 60

COPY ./shellinabox.py ./shellinabox.init /opt/

# RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
RUN apt update -y && apt-get install -y -q python3 shellinabox strace ssh && useradd -ms /bin/bash webshell && chmod 755 /opt/shellinabox.py /opt/shellinabox.init

ENTRYPOINT ["/opt/shellinabox.init"]