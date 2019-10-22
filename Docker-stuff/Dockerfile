# This is a Dockerfile to make a Docker image to test installing MaraDNS on
# a fresh CentOS 8 virtual machine.

FROM centos:8

RUN yum -y update && yum -y install gcc && yum -y install git 
RUN yum -y install make

CMD ["/bin/bash"]
