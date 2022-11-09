# This is a Dockerfile to make a Docker image to test installing MaraDNS on
# a fresh Ubuntu 22.04 virtual machine.
# This image can also run the "one source of truth" tests

FROM ubuntu:22.04
COPY killall /usr/bin/
COPY rg32hash.tar.gz /tmp/
COPY run.tests.sh /
COPY maramake-2022-11-01.tar.gz /tmp/

RUN apt-get -y update && apt-get -y install unattended-upgrades && \
        unattended-upgrades -d && apt-get -y install gcc && \
        apt-get -y install git && apt-get -y install lua5.1 && \
	apt-get -y install busybox && \
        cd /tmp && \
        tar xvzf maramake-2022-11-01.tar.gz && cd maramake-2022-11-01 && \
        cc -O3 -o make *.c && cp make /usr/bin/ && cd .. && \
        git clone https://github.com/samboy/MaraDNS && cd MaraDNS && \
	./configure && make && make install && export FLAGS=-O3 && \
	cd deadwood-* && cd src/ && ./make.version.h && \
	make -f Makefile.sl6 && cp Deadwood /usr/local/sbin/ && \
	apt-get -y install net-tools && \
	cp /tmp/MaraDNS/tools/askmara-tcp /usr/bin/ && \
	cp /tmp/MaraDNS/tools/OneSourceOfTruth/do.osot.tests /tmp && \
	rm -fr /tmp/MaraDNS && cd /tmp && tar xvzf rg32hash.tar.gz && \
	cd rg32hash-source && make && cp rg32hash /usr/bin && \
	mkdir /etc/deadwood/ && apt-get -y install valgrind && \
	apt-get -y install clang && apt-get -y install diffutils 

CMD ["/bin/bash"]
