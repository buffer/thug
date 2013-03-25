#!/bin/sh
#Created on Mar 21, 2013
#@author: asteed
#based on https://github.com/buffer/thug/blob/master/doc/source/build.rst

echo "Installing needed libraries and tools..."
sudo apt-get install subversion git python build-essential python-setuptools libboost-python-dev libboost-thread-dev python-dev build-essential git-core autoconf libtool
echo "Installing pip..."
sudo easy_install pip

echo 'Please wait, checking out subversion repo for [http://v8.googlecode.com/svn/trunk/]...'
svn checkout http://v8.googlecode.com/svn/trunk/ v8 1>setup-ubuntu.log

echo 'Patching V8...'
patch -p0 < ../patches/V8-patch1.diff 1>>setup-ubuntu.log


echo 'Please wait, checking out subversion repo for [-r478 http://pyv8.googlecode.com/svn/trunk/]...'
svn checkout -r478 http://pyv8.googlecode.com/svn/trunk/ pyv8 1>>setup-ubuntu.log


echo 'Setting environment variable...'
export V8_HOME=`pwd`/v8

echo "Building PyV8 and V8(this may take several minutes)..."
cd pyv8
python setup.py build

echo "Installing PyV8 and V8..."
sudo python setup.py install
	
cd ..

echo "Installing python libraries (beautifulsoup4, html5lib)..."
sudo pip install beautifulsoup4 1>>setup-ubuntu.log
sudo pip install html5lib 1>>setup-ubuntu.log



echo 'Please wait, cloning git repo for [git://git.carnivore.it/libemu.git]...'
git clone git://git.carnivore.it/libemu.git 1>>setup-ubuntu.log

echo "Configuring libemu..."
cd libemu
autoreconf -v -i
./configure --enable-python-bindings --prefix=/opt/libemu 1>>setup-ubuntu.log
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
	
echo "Installing python library: httplib2..."
sudo pip install httplib2 1>>setup-ubuntu.log
	
echo "Installing python library: cssutils..."
sudo pip install cssutils 1>>setup-ubuntu.log
	
echo "Installing python library: zope..."
sudo pip install zope.interface 1>>setup-ubuntu.log
	
echo "Installing python library: cssutils..."
sudo pip install cssutils 1>>setup-ubuntu.log

echo "Installing graphviz..."
sudo apt-get install graphviz


echo "Installing python libraries..."
echo "Installing python library: pyparsing==1.5.7..."
sudo easy_install pyparsing==1.5.7
	
echo "Installing python library: pydot..."
sudo pip install pydot 1>>setup-ubuntu.log
	
echo "Installing python library: python-magic..."
sudo pip install python-magic 1>>setup-ubuntu.log
	
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
