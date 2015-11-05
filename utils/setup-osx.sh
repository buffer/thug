#!/bin/bash

if ! which xcode-select >/dev/null; then
    echo "Make sure that you install Xcode via the App Store."
    echo "After it's installed, install the Xcode Command-Line Tools using:"
    echo "xcode-select --install"
    exit 1
fi

echo "Installing homebrew if needed..."
which brew >/dev/null || ruby -e "$(curl -fsSL https://raw.github.com/mxcl/homebrew/go/install)"
if ! which brew >/dev/null; then
    echo "brew failed to install..."
    exit 1
fi

#exit if any command exits non-zero
trap "echo something failed...; exit 1" ERR
set -o errexit
#set +o errexit

echo "Installing needed libraries and tools..."
brew install pkg-config
brew install autoconf
#brew install boost --c++11 --build-from-source
brew tap homebrew/versions || true
brew install gcc48
#brew install gcc46

echo "Installing pip..."
which pip 2>/dev/null || easy_install pip
easy_install -U setuptools

echo "Downloading and configuring Boost 1.55 ..."
export BOOST_HOME=`pwd`/boost
[ -f boost_1_55_0.tar.bz2 ] || \
wget http://downloads.sourceforge.net/project/boost/boost/1.55.0/boost_1_55_0.tar.bz2 1>setup-osx.log
echo 'cef9a0cc7084b1d639e06cd3bc34e4251524c840  boost_1_55_0.tar.bz2' | shasum -s -c - || \
wget http://downloads.sourceforge.net/project/boost/boost/1.55.0/boost_1_55_0.tar.bz2 1>setup-osx.log
tar -xf boost_1_55_0.tar.bz2
cd boost_1_55_0
./bootstrap.sh --with-toolset=clang --prefix=$BOOST_HOME --with-libraries=python --without-icu 1>setup-osx.log

echo "Building Boost 1.55 ..."
./b2 --prefix=$BOOST_HOME -j8 --layout=tagged toolset=clang cxxflags="-stdlib=libstdc++" linkflags="-stdlib=libstdc++" threading=multi,single link=static install debug 1>setup-osx.log

echo 'Please wait, checking out subversion repo for [http://v8.googlecode.com/svn/trunk/]...'
svn checkout -r14110 http://v8.googlecode.com/svn/trunk/ v8 1>setup-osx.log

echo 'Patching V8...'
cd v8
patch -p1 < ../../patches/V8-patch1.diff 1>>setup-osx.log
cd ..

echo 'Please wait, checking out subversion repo for [-r478 http://pyv8.googlecode.com/svn/trunk/]...'
svn checkout -r478 http://pyv8.googlecode.com/svn/trunk/ pyv8 1>>setup-osx.log

echo 'Setting environment variable...'
#export V8_HOME=`pwd`/v8
echo "V8_HOME = \"$PWD/v8\"" >> pyv8/buildconf.py
echo "DEBUG = True" >> pyv8/buildconf.py
echo "V8_SVN_REVISION = 14110" >> pyv8/buildconf.py
echo "BOOST_HOME = \"$(echo `pwd`/../boost)\"" >> buildconf.py

echo "Building PyV8 and V8(this may take several minutes)..."
cd pyv8
patch -p0 < ../../patches/osx-setup.diff
python setup.py build

echo "Installing PyV8 and V8..."
python setup.py install
python -c '
try:
    import PyV8
except:
    exit(1)
'

cd ..

echo "Installing python libraries (beautifulsoup4, html5lib)..."
pip install beautifulsoup4 1>>setup-osx.log
pip install html5lib 1>>setup-osx.log

echo 'Please wait, cloning git repo for [git://git.carnivore.it/libemu.git]...'
git clone git://git.carnivore.it/libemu.git 1>>setup-osx.log

echo "Configuring libemu..."
cd libemu
sed -i-orig -e 's/-no-cpp-precomp//' configure.ac
sed -i-orig -e 's#/usr/lib/pkgconfig/#/usr/local/lib/pkgconfig/#' Makefile.am
autoreconf -v -i
CC=gcc-4.8 CFLAGS="-w" ./configure --prefix=/usr/local --disable-shared 1>>setup-osx.log

echo "Installing libemu..."
make install 1>>setup-osx.log
cd ..

echo 'Please wait, cloning git repo for [git://github.com/buffer/pylibemu.git]...'
git clone git://github.com/buffer/pylibemu.git 1>>setup-osx.log
echo "Building pylibemu..."
cd pylibemu
sed -i-orig -e 's/distutils\.[^ ][^ ]* /setuptools /' setup.py
python setup.py build 1>>setup-osx.log
echo "Installing pylibemu..."
python setup.py install 1>>setup-osx.log
cd ..


echo "Installing python libraries..."
echo "Installing python library: pefile..."
pip install pefile 1>>setup-osx.log

echo "Installing python library: chardet..."
pip install chardet 1>>setup-osx.log

echo "Installing python library: cssutils..."
pip install cssutils 1>>setup-osx.log

echo "Installing python library: zope..."
pip install zope.interface 1>>setup-osx.log

echo "Installing python library: cssutils..."
pip install cssutils 1>>setup-osx.log

echo "Installing graphviz..."
brew install graphviz

echo "Installing python libraries..."
echo "Installing python library: pyparsing==1.5.7..."
easy_install pyparsing==1.5.7

echo "Installing python library: pygraphviz..."
pip install pygraphviz 1>>setup-osx.log

echo "Installing python library: python-magic..."
pip install python-magic 1>>setup-osx.log

echo -n "Install MongoDB?(y/n): "
read response
if [ "$response" = "y" ]; then
	echo "Installing MongoDB & PyMongo..."
	brew install mongodb
	pip install pymongo
fi

echo -n "Install RabbitMQ?(y/n): "
read response
if [ "$response" = "y" ]; then
	echo "Installing RabbitMQ & pika..."
	brew install rabbitmq
	pip install pika
fi

