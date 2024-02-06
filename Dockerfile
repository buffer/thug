FROM python:3.11 as builder
LABEL maintainer="Angelo Dell'Aera"
WORKDIR /home

RUN apt-get update && \
  apt-get install -y --no-install-recommends \
    build-essential \
    libxml2-dev \
    libxslt-dev \
    git \
    libtool \
    graphviz-dev \
    automake \
    libffi-dev \
    libfuzzy-dev \
    libjpeg-dev \
    libffi-dev \
    pkg-config \
    clang \
    autoconf \
    libssl-dev
RUN pip install --no-cache-dir -U pip setuptools
RUN git clone https://github.com/buffer/libemu.git && \
  cd libemu && \
  autoreconf -v -i && \
  ./configure && \
  make install && \
  cd ..
COPY thug/conf thug/conf
RUN pip wheel --no-cache-dir --wheel-dir /tmp/wheels thug pytesseract pygraphviz

# HACK: this is to have the pylibemu wheel package statically linked with the libemu library
RUN apt-get install -y patchelf
RUN pip install --no-cache-dir -U auditwheel
RUN auditwheel repair --plat linux_x86_64 -w /tmp/wheelhouse /tmp/wheels/*pylibemu*
RUN rm /tmp/wheels/*pylibemu*
RUN mv /tmp/wheelhouse/* /tmp/wheels/

FROM python:3.11-slim
MAINTAINER "Angelo Dell'Aera"

RUN groupadd -r thug && \
  useradd -r -g thug -d /home/thug -s /sbin/nologin -c "Thug User" thug && \
  mkdir -p /home/thug /tmp/thug/logs /etc/thug && \
  chown -R thug:thug /home/thug /tmp/thug
RUN apt-get update && \
  apt-get install -y --no-install-recommends \
    tesseract-ocr \
    graphviz \
    libfuzzy2 \
    file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN --mount=type=bind,from=builder,src=/home/thug/conf,dst=/tmp/thug/conf cp -R /tmp/thug/conf/* /etc/thug
RUN --mount=type=bind,from=builder,src=/tmp/wheels,dst=/tmp/wheels pip install --no-cache-dir --no-deps /tmp/wheels/*

USER thug
ENV HOME /home/thug
ENV USER thug
WORKDIR /home/thug
VOLUME ["/tmp/thug/logs"]
CMD ["thug"]
