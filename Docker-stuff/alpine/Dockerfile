FROM alpine:3.14
COPY maramake-2022-11-01.tar.gz /tmp/
COPY rg32hash.tar.gz /tmp/
COPY run.tests.sh /
RUN apk add --no-cache gcc && apk add --no-cache libc-dev && \
    apk add --no-cache lua5.1 && apk add --no-cache git && \
    apk add --no-cache lua5.1-bit32 && apk add --no-cache patch && \
    apk add --no-cache valgrind && \
    apk add --no-cache clang && cd /tmp && \
    tar xvzf maramake-2022-11-01.tar.gz && cd maramake-2022-11-01 && \
    cc -O3 -o make *.c && cp make /usr/bin/ && cd .. && \
    git clone https://github.com/samboy/MaraDNS && cd MaraDNS && \
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
