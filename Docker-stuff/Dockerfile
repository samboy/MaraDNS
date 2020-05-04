# This is a Dockerfile to make a Docker image to test installing MaraDNS on
# a fresh CentOS 8 virtual machine.

FROM centos:8

RUN yum -y update && yum -y install gcc && yum -y install git && \
	yum -y install make && cd /tmp && git clone \
	https://github.com/samboy/MaraDNS && cd MaraDNS && \
	./configure && make

CMD ["/bin/bash"]
