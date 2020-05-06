# This is a Dockerfile to make a Docker image to test installing MaraDNS on
# a fresh CentOS 8 virtual machine.

FROM centos:8

RUN yum -y update && yum -y install gcc && yum -y install git && \
	yum -y install make && cd /tmp && git clone \
	https://github.com/samboy/MaraDNS && cd MaraDNS && \
	./configure && make && make install && export FLAGS=-O3 && \
	cd deadwood-* && cd src/ && ./make.version.h && \
	make -f Makefile.sl6 && cp Deadwood /usr/local/sbin/

CMD ["/bin/bash"]
