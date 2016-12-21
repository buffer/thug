#!/bin/bash

if ! which xcode-select > /dev/null; then
    echo "Make sure that you install Xcode via the App Store."
    echo "After it's installed, install the Xcode Command-Line Tools using:"
    echo "xcode-select --install"
    exit 1
fi

echo "Installing Homebrew (if needed)"
which brew >/dev/null || /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
if ! which brew >/dev/null; then
    echo "Brew failed to install. Exiting"
    exit 1
fi

# Exit if any command exits non-zero
trap "echo Something failed...; exit 1" ERR
set -o errexit

echo "Installing libraries and tools"
brew install python
brew install pkg-config
brew install autoconf
brew install automake
brew install libtool
brew tap homebrew/versions || true
brew install gcc49
brew install libmagic

echo "Installing Pip"
which pip 2> /dev/null || easy_install pip

echo "Installing Boost"
brew install boost-python

echo "Installing V8/PyV8"
git clone https://github.com/buffer/pyv8.git
cd pyv8
python setup.py build
sudo python setup.py install
cd ..
rm -rf pyv8

echo "Installing Graphviz"
brew install graphviz

echo "Installing Yara"
brew install yara

echo "Installing MongoDB"
brew install mongodb

echo "Installing ssdeep"
brew install ssdeep

echo -n "Install RabbitMQ?(y/n): "
read response
if [ "$response" = "y" ]; then
	echo "Installing RabbitMQ/Pika"
	brew install rabbitmq
	pip install pika
fi

echo "Installing Thug"
pip install thug
