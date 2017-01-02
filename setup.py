#!/usr/bin/env python

import ez_setup
ez_setup.use_setuptools()

import os
import glob
from setuptools import setup, find_packages

os.environ['BUILD_LIB'] = '1'

import thug

personalities_path = os.path.join(thug.__configuration_path__, "personalities")
rules_path         = os.path.join(thug.__configuration_path__, "rules")
scripts_path       = os.path.join(thug.__configuration_path__, "scripts")
plugins_path       = os.path.join(thug.__configuration_path__, "plugins")
hooks_path         = os.path.join(thug.__configuration_path__, "hooks")

html_rules_path    = os.path.join(rules_path, "htmlclassifier")
js_rules_path      = os.path.join(rules_path, "jsclassifier")
url_rules_path     = os.path.join(rules_path, "urlclassifier")
sample_rules_path  = os.path.join(rules_path, "sampleclassifier")
html_filter_path   = os.path.join(rules_path, "htmlfilter")
js_filter_path     = os.path.join(rules_path, "jsfilter")
url_filter_path    = os.path.join(rules_path, "urlfilter")
sample_filter_path = os.path.join(rules_path, "samplefilter")


setup(
    name = "thug",
    version = thug.__version__,
    author = "Angelo Dell'Aera",
    author_email = "angelo.dellaera@honeynet.org",
    description = "Low-interaction honeyclient Thug",
    license = "GPLv2",
    long_description = open("README.rst").read(),
    url = "http://buffer.github.io/thug/",
    download_url = "https://github.com/buffer/thug/",
    platforms = ["Linux", ],
    classifiers = [
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Topic :: Security",
    ],
    package_data = {
           ""       : ["*.js"],
           },
    packages = find_packages(),
    data_files = [
        (thug.__configuration_path__, ["thug/Analysis/honeyagent/honeyagent.conf.sample",
                                       "thug/Analysis/virustotal/virustotal.conf.default",
                                       "thug/Logging/logging.conf.default"]),
        (personalities_path         , glob.glob("thug/DOM/personalities/*.json")),
        (rules_path                 , glob.glob("thug/Classifier/rules/*.yar")),
        (scripts_path               , ["thug/DOM/thug.js",
                                       "thug/DOM/storage.js",
                                       "thug/Debugger/d8.js"]),
        (plugins_path               , []),
        (hooks_path                 , []),
        (html_rules_path            , glob.glob("thug/Classifier/rules/htmlclassifier/*.yar")),
        (js_rules_path              , glob.glob("thug/Classifier/rules/jsclassifier/*.yar")),
        (url_rules_path             , glob.glob("thug/Classifier/rules/urlclassifier/*.yar")),
        (sample_rules_path          , glob.glob("thug/Classifier/rules/sampleclassifier/*.yar")),
        (html_filter_path           , glob.glob("thug/Classifier/rules/htmlfilter/*.yar")),
        (js_filter_path             , glob.glob("thug/Classifier/rules/jsfilter/*.yar")),
        (url_filter_path            , glob.glob("thug/Classifier/rules/urlfilter/*.yar")),
        (sample_filter_path         , glob.glob("thug/Classifier/rules/samplefilter/*.yar")),

    ],
    install_requires = open("requirements.txt").read().splitlines(),
    entry_points = {
        "console_scripts": [
            "thug = thug.thug:main",
        ]
    }
)
