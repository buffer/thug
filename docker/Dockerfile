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
    autoconf && \
  rm -rf /var/lib/apt/lists/*

RUN pip3 install --upgrade pip
RUN pip3 install --upgrade setuptools
RUN pip3 install --upgrade pytesseract
RUN pip3 install --upgrade pygraphviz
WORKDIR /home

RUN wget https://github.com/area1/stpyv8/releases/download/v8.9.255.25/stpyv8-ubuntu-18.04-python-3.6.zip
RUN unzip stpyv8-ubuntu-18.04-python-3.6.zip
RUN pip3 install stpyv8-ubuntu-18.04-3.6/stpyv8-8.9.255.25-cp36-cp36m-linux_x86_64.whl
RUN mkdir -p /usr/share/stpyv8
RUN sudo mv stpyv8-ubuntu-18.04-3.6/icudtl.dat /usr/share/stpyv8

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
  mkdir /etc/thug && \
  mkdir /etc/thug/rules && \
  mkdir /etc/thug/personalities && \
  mkdir /etc/thug/scripts && \
  mkdir /etc/thug/plugins && \
  mkdir /etc/thug/hooks && \
  cp -R thug/thug/Classifier/rules/* /etc/thug/rules/ && \
  cp -R thug/thug/DOM/personalities/* /etc/thug/personalities && \
  cp thug/thug/DOM/thug.js /etc/thug/scripts && \
  cp thug/thug/DOM/storage.js /etc/thug/scripts && \
  cp thug/thug/DOM/date.js /etc/thug/scripts && \
  cp thug/thug/DOM/eval.js /etc/thug/scripts && \
  cp thug/thug/DOM/write.js /etc/thug/scripts && \
  cp thug/conf/thug.conf /etc/thug && \
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
