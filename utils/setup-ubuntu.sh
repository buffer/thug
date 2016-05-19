#!/bin/sh
#Created on Mar 21, 2013
#@author: asteed
#based on https://github.com/buffer/thug/blob/master/doc/source/build.rst

echo "Installing needed libraries and tools..."
sudo apt-get install subversion git python build-essential python-setuptools libboost-python-dev libboost-thread-dev \
libboost-system-dev python-dev build-essential git-core autoconf libtool
echo "Installing pip..."
sudo easy_install pip

echo 'Please wait, checking out subversion repo for [http://v8.googlecode.com/svn/trunk/]...'
svn checkout -r14110 http://v8.googlecode.com/svn/trunk/ v8 1>setup-ubuntu.log

echo 'Patching V8...'
patch -p0 < ../patches/V8-patch1.diff 1>>setup-ubuntu.log


echo 'Please wait, checking out subversion repo for [-r478 http://pyv8.googlecode.com/svn/trunk/]...'
svn checkout -r478 http://pyv8.googlecode.com/svn/trunk/ pyv8 1>>setup-ubuntu.log


echo 'Setting environment variable...'
echo "V8_HOME = \"$PWD/v8\"" >> pyv8/buildconf.py
echo "DEBUG = True" >> pyv8/buildconf.py
echo "V8_SVN_REVISION = 14110" >> pyv8/buildconf.py

echo "Building PyV8 and V8(this may take several minutes)..."
cd pyv8
python setup.py build

echo "Installing PyV8 and V8..."
sudo python setup.py install
	
cd ..

echo "Installing python libraries (beautifulsoup4, html5lib)..."
sudo pip install beautifulsoup4 1>>setup-ubuntu.log
sudo pip install html5lib 1>>setup-ubuntu.log



echo 'Please wait, cloning git repo for [https://github.com/buffer/libemu.git]...'
git clone https://github.com/buffer/libemu.git 1>>setup-ubuntu.log

echo "Configuring libemu..."
cd libemu
autoreconf -v -i
./configure --prefix=/opt/libemu 1>>setup-ubuntu.log
echo "Installing libemu..."
sudo make install 1>>setup-ubuntu.log
sudo ldconfig -n /opt/libemu/lib
cd ..


echo 'Please wait, cloning git repo for [git://github.com/buffer/pylibemu.git]...'
git clone git://github.com/buffer/pylibemu.git 1>>setup-ubuntu.log
echo "Building pylibemu..."
cd pylibemu
sudo sh -c "echo /opt/libemu/lib/ > /etc/ld.so.conf.d/pylibemu.conf"
python setup.py build 1>>setup-ubuntu.log
echo "Installing pylibemu..."
sudo python setup.py install 1>>setup-ubuntu.log
sudo ldconfig
cd ..


echo "Installing python libraries..."
echo "Installing python library: pefile..."
sudo pip install pefile 1>>setup-ubuntu.log
	
echo "Installing python library: chardet..."
sudo pip install chardet 1>>setup-ubuntu.log
	
echo "Installing python library: cssutils..."
sudo pip install cssutils 1>>setup-ubuntu.log

echo "Installing python library: PySocks..."
sudo pip install PySocks 1>>setup-ubuntu.log
	
echo "Installing python library: zope..."
sudo pip install zope.interface 1>>setup-ubuntu.log
	
echo "Installing graphviz..."
sudo apt-get install graphviz

echo "Installing python library: lxml..."
sudo apt-get install python-lxml python-lxml-dbg


echo "Installing python libraries..."
echo "Installing python library: pyparsing==1.5.7..."
sudo easy_install pyparsing==1.5.7
	
echo "Installing python library: pygraphviz..."
sudo pip install pygraphviz 1>>setup-ubuntu.log
	
echo "Installing python library: python-magic..."
sudo pip install python-magic 1>>setup-ubuntu.log

echo "Installing python library: rarfile..."
sudo pip install rarfile 1>>setup-ubuntu.log

echo "Installing python library: jsbeautifier..."
sudo pip install jsbeautifier 1>>setup-ubuntu.log

echo "Installing python library: yara-python..."
sudo pip install yara-python 1>>setup-ubuntu.log

echo -n "Install MongoDB?(y/n): "
read response
if [ "$response" = "y" ]; then
	echo "Installing MongoDB & PyMongo..."
	sudo apt-get install mongodb
	sudo pip install pymongo
fi

echo -n "Install RabbitMQ?(y/n): "
read response
if [ "$response" = "y" ]; then
	echo "Installing RabbitMQ & pika..."
	sudo apt-get install rabbitmq-server
	sudo pip install pika
fi
