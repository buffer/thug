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
                shutil.copytree("thug/conf",
                                THUG_GLOBAL_CONFIG_DIR,
                                dirs_exist_ok = True)
            except PermissionError:
                if not os.path.exists(THUG_USER_CONFIG_DIR):
                    shutil.copytree("thug/conf",
                                     THUG_USER_CONFIG_DIR,
                                     dirs_exist_ok = True)

        for folder in (THUG_GLOBAL_CONFIG_DIR, THUG_USER_CONFIG_DIR, ):
            if os.path.exists(folder) and os.access(folder, os.X_OK | os.W_OK):
                shutil.copy("thug/conf/inspector.json", f"{folder}/inspector.json")
                shutil.copytree("thug/conf/personalities", f"{folder}/personalities", dirs_exist_ok = True)
                shutil.copytree("thug/conf/scripts", f"{folder}/scripts", dirs_exist_ok = True)

        install.run(self)

setup(
    cmdclass = dict(
        install = thug_install
    ),
)
