#!/bin/sh
set -e
set -x

echo "Creating dev environment in ./venv..."

python2 -m virtualenv venv
. venv/bin/activate
pip2 install -U pip setuptools
pip2 install git+git://github.com/buffer/pyv8.git#egg=pyv8
pip2 install .
pip2 install -r requirements-dev.txt

echo ""
echo "  [*] Created virtualenv environment in ./venv."
echo "  [*] Installed all dependencies into the virtualenv."
echo "  [*] You can now activate the $(python2 --version) virtualenv with this command: \`. venv/bin/activate\`"
