FROM alpine:3.14
COPY rg32hash.tar.gz /tmp/
COPY run.tests.sh /
RUN apk add --no-cache gcc && apk add --no-cache libc-dev && \
    apk add --no-cache lua5.1 && apk add --no-cache git && \
    apk add --no-cache make && apk add --no-cache valgrind && \
    apk add --no-cache clang && cd /tmp && git clone \
    https://github.com/samboy/MaraDNS && cd MaraDNS && \
    ./configure && make && make install && export FLAGS=-O3 && \
    cd deadwood-* && cd src/ && ./make.version.h && \
    mkdir /usr/local/sbin/ && \
    make -f Makefile.sl6 && cp Deadwood /usr/local/sbin/ && \
    cp /tmp/MaraDNS/tools/askmara-tcp /usr/bin/ && \
    cp /tmp/MaraDNS/tools/OneSourceOfTruth/do.osot.tests /tmp && \
    rm -fr /tmp/MaraDNS && cd /tmp && tar xvzf rg32hash.tar.gz && \
    cd rg32hash-source && make && cp rg32hash /usr/bin && \
    mkdir /etc/deadwood/ && \
    true
