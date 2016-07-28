#
# This Dockerfile is mostly based on the excellent work of Lenny Zeltser for REMnux
# (https://hub.docker.com/r/remnux/thug/~/dockerfile/) which is in turn based on
# ideas from Spenser Reinhardt's Dockerfile
# (https://registry.hub.docker.com/u/sreinhardt/honeynet/dockerfile),
# on instructions outlined by M. Fields (@shakey_1) and 
# on the installation script created by Payload Security
# (https://github.com/PayloadSecurity/VxCommunity/blob/master/bash/thuginstallation.sh)
#
# To run this image after installing Docker, use a command like this:
#
# docker run --rm -it remnux/thug bash
#
# then run ./thug.py with the desired parameters. For example, if you are running
# its address to Thug this way:
#
# ./thug.py -D <ip>:<port> http://example.com/
#
# Please see Thug's docs for more info about specifying the MongoDB address
# via command line.
#
# If you prefer to use the -F switch to enable file logging, you may want to
# share the "logs" directory between your host and the container:
# create a "logs" directory on your host and make it world-accessible
# (e.g., "chmod a+xwr ~/logs"). Then run the tool like this:
#
# docker run --rm -it -v ~/logs:/home/thug/logs remnux/thug bash
# 
# If you'd like to share an additional directory (e.g., "files"), supply the
# mapping using another -v parameter such as "-v ~/files:/home/thug/files",
# but remember to make the directory on your host world-accessible.
#
# To support distributed operations, install the folloging packages into the image
# using "apt-get": rabbitmq-server, python-pika
#
FROM ubuntu:14.04

USER root
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      autoconf \
      automake \
      build-essential \
      curl \
      git \
      graphviz \
      graphviz-dev \
      libboost-all-dev \
      libboost-python-dev \
      libffi-dev \
      libtool \
      libxml2-dev \
      libxslt-dev \
      python-dev \
      python-gridfs \
      python-pip \
      python-pygraphviz \
      python-pymongo \
      python-setuptools \
      python-socksipy \
      subversion \
        && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /home
RUN git clone https://github.com/buffer/libemu.git && \
    cd libemu && \
    autoreconf -v -i && \
    export CFLAGS=-Wno-error && \
    ./configure --prefix=/opt/libemu && \
    make install && \
    ldconfig -n /opt/libemu && \
    touch /etc/ld.so.conf.d/libemu.conf && \
    echo "/opt/libemu/lib/" > /etc/ld.so.conf.d/libemu.conf && \
    ldconfig && \
    cd .. && \
    rm -rf libemu

RUN pip install -q \
      jsbeautifier \
      rarfile \
      beautifulsoup4 \
      pefile \
      six \
      html5lib \
      chardet \
      requests \
      PySocks \
      cssutils \
      zope.interface \
      pyparsing \
      python-magic \
      lxml \
      pylibemu

RUN curl -sSL "https://github.com/plusvic/yara/archive/v3.4.0.tar.gz" | tar -xzC . && \
    cd yara-3.4.0 && \
    ./bootstrap.sh && \
    ./configure && \
    make && \
    make install && \
    cd yara-python/ && \
    python setup.py build && \
    python setup.py install && \
    cd ../.. && \
    rm -rf yara-3.4.0 && \
    ldconfig

RUN BUILD_LIB=1 pip install ssdeep

RUN groupadd -r thug && \
    useradd -r -g thug -d /home/thug -s /sbin/nologin -c "Thug User" thug

RUN git clone https://github.com/buffer/pyv8.git && \
    cd pyv8 && \
    python setup.py build && \
    python setup.py install && \
    cd .. && \
    rm -rf pyv8

WORKDIR /home
RUN git clone https://github.com/buffer/thug.git && \
    chmod a+x thug/src/thug.py && \
    mkdir thug/logs && \
    mkdir thug/files && \
    sed -i 's/    True/    False/g' thug/src/Logging/logging.conf && \
    chown -R thug:thug /home/thug

USER thug
ENV HOME /home/thug
ENV USER thug
WORKDIR /home/thug/src
CMD ["./thug.py"]
