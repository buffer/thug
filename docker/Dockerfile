#
# This Docker image encapsulates Thug, a low-interaction honeyclient,
# which was created by Angelo Dell'Aera and is available at [1].
#
# To run this image after installing Docker, use a command like this:
#
# sudo docker run --rm -it buffer/thug bash
#
# then run "thug" with the desired parameters (such as -F to enable
# file logging).
#
# To share the "logs" directory between your host and the container,
# create a "logs" directory on your host and make it world-accessible
# (e.g., "chmod a+xwr ~/logs"). Then run the tool like this:
#
# sudo docker run --rm -it -v ~/logs:/tmp/thug/logs buffer/thug bash
# 
# To support MongoDB output, install the folloging packages into the
# image using "apt-get": mongodb, mongodb-dev, python-pymongo
#
# This file was originally based on ideas from Spenser Reinhardt's
# Dockerfile [2] on instructions outlined by M. Fields (@shakey_1) and
# on the installation script created by Payload Security [3]
#
# [1] https://github.com/buffer/thug
# [2] https://registry.hub.docker.com/u/sreinhardt/honeynet/dockerfile
# [3] https://github.com/PayloadSecurity/VxCommunity/blob/master/bash/thuginstallation.sh

FROM ubuntu:22.10
MAINTAINER Angelo Dell'Aera

USER root
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
  apt-get install -y --no-install-recommends \
    build-essential \
    sudo \
    python3 \
    python3-dev \
    python3-setuptools \
    python3-wheel \
    python-is-python3 \
    libboost-dev \
    libboost-iostreams-dev \
    libboost-python-dev \
    libboost-system-dev \
    python3-pip \
    libxml2-dev \
    libxslt-dev \
    tesseract-ocr \
    git \
    wget \
    unzip \
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
    clang \
    autoconf && \
  rm -rf /var/lib/apt/lists/*

RUN pip3 install --upgrade pip
RUN pip3 install --upgrade setuptools
RUN pip3 install --upgrade pytesseract
RUN pip3 install --upgrade pygraphviz
WORKDIR /home

RUN wget https://github.com/cloudflare/stpyv8/releases/download/v12.0.267.10/stpyv8-ubuntu-22.04-python-3.10.zip
RUN unzip stpyv8-ubuntu-22.04-python-3.10.zip
RUN pip3 install stpyv8-ubuntu-22.04-3.10/stpyv8-12.0.267.10-cp310-cp310-linux_x86_64.whl
RUN mkdir -p /usr/share/stpyv8
RUN sudo mv stpyv8-ubuntu-22.04-3.10/icudtl.dat /usr/share/stpyv8

RUN git clone https://github.com/buffer/libemu.git && \
  cd libemu && \
  autoreconf -v -i && \
  ./configure && \
  make install && \
  cd .. && \
  rm -rf libemu

RUN ldconfig
RUN pip3 install thug

RUN git clone https://github.com/buffer/thug.git && \
  mkdir -p /etc/thug && \
  cp -R thug/thug/conf/* /etc/thug && \
  rm -rf thug

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
