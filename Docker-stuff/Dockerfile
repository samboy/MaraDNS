# This is a Dockerfile to make a Docker image to test installing MaraDNS on
# a fresh CentOS 8 virtual machine.
# This image can also run the "one source of truth" tests

FROM centos:8
COPY killall /usr/bin/
COPY rg32hash.tar.gz /tmp/
COPY run.tests.sh /

RUN yum -y update && yum -y install gcc && yum -y install git && \
	yum -y install make && cd /tmp && git clone \
	https://github.com/samboy/MaraDNS && cd MaraDNS && \
	./configure && make && make install && export FLAGS=-O3 && \
	cd deadwood-* && cd src/ && ./make.version.h && \
	make -f Makefile.sl6 && cp Deadwood /usr/local/sbin/ && \
	yum -y install net-tools && \
	cp /tmp/MaraDNS/tools/askmara-tcp /usr/bin/ && \
	cp /tmp/MaraDNS/tools/OneSourceOfTruth/do.osot.tests /tmp && \
	rm -fr /tmp/MaraDNS && cd /tmp && tar xvzf rg32hash.tar.gz && \
	cd rg32hash-source && make && cp rg32hash /usr/bin && \
	mkdir /etc/deadwood/ && yum -y install valgrind && \
	yum -y install clang

CMD ["/bin/bash"]
