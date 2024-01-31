FROM debian:buster-slim

COPY ./shellinabox.py ./shellinabox.init /opt/

RUN apt update -y && apt-get install -y -q python3 shellinabox strace ssh git libssl-dev libpam0g-dev zlib1g-dev dh-autoreconf make \
    && useradd -ms /bin/bash webshell \
    && chmod 755 /opt/shellinabox.py /opt/shellinabox.init \
    && git clone https://github.com/rickicode/shellinabox.git \
    && cd shellinabox && autoupdate && autoreconf -i \
    && ./configure --enable-static CFLAGS="-Wall -W -O2" CPPFLAGS="-I./openssl/include" LDFLAGS="-static -static-libgcc -L." LIBS="-lssl -lcrypto -lpthread -ldl -lutil -lc" --with-gnu-ld --host=mipsel-unknown-linux-gnu && make \
    && mv shellinaboxd /usr/local/bin/shellinaboxd && cd .. && rm -rf shellinabox && \
    rm -rf /usr/bin/shellinaboxd

EXPOSE 80 8018

ENV SSH_PORT 22
ENV USERNAME root
ENV DEFAULT_IP 0.0.0.0
# ENV ALLOWED_NETWORKS 0.0.0.0/0
ENV INACTIVITY_INTERVAL 600


WORKDIR /root

ENTRYPOINT ["/opt/shellinabox.init"]
