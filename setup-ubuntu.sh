#!/bin/sh
#Created on Mar 21, 2013
#@author: asteed
#based on https://github.com/buffer/thug/blob/master/doc/source/build.rst

echo "Installing (python, build-essential, git-core, autoconf, libtool, python-dev)..."
sudo apt-get install python build-essential git-core autoconf libtool python-dev
echo "Installing pip..."
sudo easy_install pip


echo 'Please wait, checking out subversion repo for [http://v8.googlecode.com/svn/trunk/]...'
svn checkout http://v8.googlecode.com/svn/trunk/ v8

patch -p0 < patches/V8-patch1.diff


echo 'Please wait, checking out subversion repo for [-r478 http://pyv8.googlecode.com/svn/trunk/]...'
svn checkout -r478 http://pyv8.googlecode.com/svn/trunk/ pyv8


echo 'Setting environment variable...'
export V8_HOME=`pwd`/v8

echo "Building PyV8 and V8..."
cd pyv8
python setup.py build

echo "Installing PyV8 and V8..."
sudo python setup.py install
	
cd ..

echo "Installing python libraries..."
sudo pip install beautifulsoup4
sudo pip install html5lib



echo 'Please wait, cloning git repo for [git://git.carnivore.it/libemu.git]...'
git clone git://git.carnivore.it/libemu.git

echo "Configuring libemu..."
cd libemu
autoreconf -v -i
./configure --enable-python-bindings --prefix=/opt/libemu
echo "Installing libemu..."
sudo make install
sudo ldconfig -n /opt/libemu/lib
cd ..


echo 'Please wait, cloning git repo for [git://github.com/buffer/pylibemu.git]...'
git clone git://github.com/buffer/pylibemu.git
echo "Building pylibemu..."
cd pylibemu
sudo sh -c "echo /opt/libemu/lib/ > /etc/ld.so.conf.d/pylibemu.conf"
python setup.py build
echo "Installing pylibemu..."
sudo python setup.py install
sudo ldconfig
cd ..


echo "Installing python libraries..."
sudo pip install pefile
sudo pip install chardet
sudo pip install httplib2
sudo pip install cssutils
sudo pip install zope.interface
sudo pip install cssutils

echo "Installing graphviz..."
sudo apt-get install graphviz


echo "Installing python libraries..."
sudo easy_install pyparsing==1.5.7
sudo pip install pydot
sudo pip install python-magic
	
echo -n "Install mongodb?(y/n): "
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
