#!/bin/sh

# Created on March, 2014. Debian 7.4.0 default installation.
# @author: aortega

if [ `id -u` != "0" ]; then
	echo "root needed for this operation";
	exit 1;
fi

PIP_INSTALLS="beautifulsoup4 html5lib jsbeautifier pefile chardet PySocks cssutils zope.interface pygraphviz python-magic rarfile"
APT_INSTALLS="subversion git python build-essential python-setuptools libboost-python-dev libboost-thread-dev libboost-system-dev python-dev build-essential git-core autoconf libtool python-pip graphviz"

# Forced mitigations just in case
export CFLAGS="-fstack-protector"
export CXXFLAGS="-fstack-protector"

# APT installs

echo "Installing needed libraries and tools ..."
apt-get --yes install ${APT_INSTALLS}

# PyV8

echo "Please wait, checking out subversion repo for [http://pyv8.googlecode.com/svn/trunk/] ..."
svn checkout http://pyv8.googlecode.com/svn/trunk/ pyv8

echo "Building PyV8 and V8 (this may take several minutes) ..."
cd pyv8
python setup.py build

echo "Installing PyV8 and V8 ..."
python setup.py install

cd ..

# Libemu

echo "Please wait, cloning git repo for [https://github.com/buffer/libemu.git] ..."
git clone https://github.com/buffer/libemu.git

echo "Configuring libemu ..."
cd libemu
autoreconf -v -i
./configure --prefix=/opt/libemu
echo "Installing libemu ..."
make install
ldconfig -n /opt/libemu/lib
cd ..

echo "Please wait, cloning git repo for [git://github.com/buffer/pylibemu.git] ..."
git clone git://github.com/buffer/pylibemu.git

echo "Building pylibemu ..."
cd pylibemu
echo /opt/libemu/lib/ > /etc/ld.so.conf.d/pylibemu.conf
python setup.py build
echo "Installing pylibemu ..."
python setup.py install
ldconfig
cd ..

# Yara

wget https://github.com/plusvic/yara/archive/v2.0.0.tar.gz -O yara-2.0.0.tar.gz
tar -zxf yara-2.0.0.tar.gz
cd yara-2.0.0
sh build.sh
make install

ldconfig

cd yara-python
python setup.py build
python setup.py install

ldconfig

# PIP installs

# Old pyparsing
# ref: http://stackoverflow.com/a/17902926

pip install -Iv "https://pypi.python.org/packages/source/p/pyparsing/pyparsing-1.5.7.tar.gz#md5=9be0fcdcc595199c646ab317c1d9a709"

echo "Installing python libraries: ${PIP_INSTALLS}"
pip install ${PIP_INSTALLS}

# OPTIONAL installs

echo -n "Install MongoDB?(y/N): "
read response
if [ "$response" = "y" ]; then
	echo "Installing MongoDB & PyMongo ..."
	apt-get --yes install mongodb
	pip install pymongo
fi

echo -n "Install RabbitMQ?(y/N): "
read response
if [ "$response" = "y" ]; then
	echo "Installing RabbitMQ & pika ..."
	apt-get install rabbitmq-server
	pip install pika
fi

