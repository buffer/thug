#
# This Docker image encapsulates Thug, a low-interaction honeyclient,
# which was created by Angelo Dell'Aera  and is available at
# https://github.com/buffer/thug.
#
# To run this image after installing Docker, use a command like this:
#
# sudo docker run --rm -it remnux/thug bash
#
# then run "thug" with the desired parameters (such as -F to enable
# file logging).
#
# To share the "logs" directory between your host and the container,
# create a "logs" directory on your host and make it world-accessible
# (e.g., "chmod a+xwr ~/logs"). Then run the tool like this:
#
# sudo docker run --rm -it -v ~/logs:/tmp/thug/logs remnux/thug bash
# 
# To support distributed operations and MongoDB output, install the folloging
# packages into the image using "apt-get": mongodb, mongodb-dev, python-pymongo,
# rabbitmq-server, python-pika.
#
# This file was originally based on ideas from Spenser Reinhardt's Dockerfile
# (https://registry.hub.docker.com/u/sreinhardt/honeynet/dockerfile),
# on instructions outlined by M. Fields (@shakey_1) and 
# on the installation script created by Payload Security
# (https://github.com/PayloadSecurity/VxCommunity/blob/master/bash/thuginstallation.sh)
#

FROM ubuntu:18.04
MAINTAINER Lenny Zeltser (@lennyzeltser, www.zeltser.com)

USER root
RUN apt-get update && \
  apt-get install -y --no-install-recommends \
    build-essential \
    sudo \
    python \
    python3 \
    python3-dev \
    python3-setuptools \
    python3-wheel \ 
    libboost-dev \
    libboost-python-dev \
    libboost-system-dev \
    python3-pip \
    libxml2-dev \
    libxslt-dev \
    git \
    libtool \
    graphviz-dev \
    automake \
    libffi-dev \
    graphviz \
    libfuzzy-dev \
    libfuzzy2 \
    libjpeg-dev \
    libffi-dev \
    pkg-config \
    autoconf && \
  rm -rf /var/lib/apt/lists/*

RUN pip3 install --upgrade pip
RUN pip3 install --upgrade setuptools
WORKDIR /home

RUN git clone https://github.com/buffer/thug.git && \
  pip3 install thug/.travis/stpyv8-7.9.317.31-cp36-cp36m-linux_x86_64.whl && \
  rm -rf thug

RUN git clone https://github.com/buffer/libemu.git && \
  cd libemu && \
  autoreconf -v -i && \
  ./configure && \
  make install && \
  cd .. && \
  rm -rf libemu

RUN ldconfig
RUN pip3 install thug

RUN groupadd -r thug && \
  useradd -r -g thug -d /home/thug -s /sbin/nologin -c "Thug User" thug && \
  mkdir -p /home/thug /tmp/thug/logs && \
  chown -R thug:thug /home/thug /tmp/thug/logs

USER thug
ENV HOME /home/thug
ENV USER thug
WORKDIR /home/thug
VOLUME ["/tmp/thug/logs"]
CMD ["thug"]
