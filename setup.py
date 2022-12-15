#!/usr/bin/env python

import os
import shutil

from setuptools import setup
from setuptools.command.install import install

import appdirs

os.environ['BUILD_LIB'] = '1'

THUG_GLOBAL_CONFIG_DIR = "/etc/thug"
THUG_USER_CONFIG_DIR = f"{appdirs.user_config_dir()}/thug/"

class thug_install(install):
    def run(self):
        if not os.path.exists(THUG_GLOBAL_CONFIG_DIR):
            try:
                shutil.copytree("conf",
                                THUG_GLOBAL_CONFIG_DIR,
                                dirs_exist_ok = True)
            except PermissionError:
                if not os.path.exists(THUG_USER_CONFIG_DIR):
                    shutil.copytree("conf",
                                     THUG_USER_CONFIG_DIR,
                                     dirs_exist_ok = True)

        install.run(self)

setup(
    cmdclass = dict(
        install = thug_install
    ),
)
