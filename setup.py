#!/usr/bin/env python

import os
import glob
from setuptools import setup
from setuptools import find_packages

import thug

os.environ['BUILD_LIB'] = '1'

personalities_path = os.path.join(thug.__configuration_path__, "personalities")
rules_path         = os.path.join(thug.__configuration_path__, "rules")
scripts_path       = os.path.join(thug.__configuration_path__, "scripts")
plugins_path       = os.path.join(thug.__configuration_path__, "plugins")
hooks_path         = os.path.join(thug.__configuration_path__, "hooks")

html_rules_path    = os.path.join(rules_path, "htmlclassifier")
js_rules_path      = os.path.join(rules_path, "jsclassifier")
vbs_rules_path     = os.path.join(rules_path, "vbsclassifier")
url_rules_path     = os.path.join(rules_path, "urlclassifier")
sample_rules_path  = os.path.join(rules_path, "sampleclassifier")
text_rules_path    = os.path.join(rules_path, "textclassifier")
cookie_rules_path  = os.path.join(rules_path, "cookieclassifier")
image_rules_path   = os.path.join(rules_path, "imageclassifier")
html_filter_path   = os.path.join(rules_path, "htmlfilter")
js_filter_path     = os.path.join(rules_path, "jsfilter")
vbs_filter_path    = os.path.join(rules_path, "vbsfilter")
url_filter_path    = os.path.join(rules_path, "urlfilter")
sample_filter_path = os.path.join(rules_path, "samplefilter")
text_filter_path   = os.path.join(rules_path, "textfilter")
cookie_filter_path = os.path.join(rules_path, "cookiefilter")
image_filter_path  = os.path.join(rules_path, "imagefilter")


setup(
    name = "thug",
    version = thug.__version__,
    author = "Angelo Dell'Aera",
    author_email = "angelo.dellaera@honeynet.org",
    description = "Low-interaction honeyclient Thug",
    license = "GPLv2",
    long_description = open("README.rst", encoding = 'utf-8', mode = 'r').read(),
    url = "http://buffer.github.io/thug/",
    download_url = "https://github.com/buffer/thug/",
    platforms = ["Linux", ],
    classifiers = [
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
        "Programming Language :: Python :: 3",
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        "Topic :: Security",
    ],
    include_package_data = True,
    package_data = {
           ""       : ["*.js"],
           },
    packages = find_packages(),
    data_files = [
        (thug.__configuration_path__, ["conf/thug.conf", ]),
        (thug.__configuration_path__, ["conf/inspector.json", ]),
        (personalities_path         , glob.glob("conf/personalities/*.json")),
        (rules_path                 , glob.glob("conf/rules/*.yar")),
        (scripts_path               , ["thug/DOM/thug.js",
                                       "thug/DOM/storage.js",
                                       "thug/DOM/date.js",
                                       "thug/DOM/eval.js",
                                       "thug/DOM/write.js"]),
        (plugins_path               , []),
        (hooks_path                 , []),
        (html_rules_path            , glob.glob("conf/rules/htmlclassifier/*.yar")),
        (js_rules_path              , glob.glob("conf/rules/jsclassifier/*.yar")),
        (vbs_rules_path             , glob.glob("conf/rules/vbsclassifier/*.yar")),
        (url_rules_path             , glob.glob("conf/rules/urlclassifier/*.yar")),
        (sample_rules_path          , glob.glob("conf/rules/sampleclassifier/*.yar")),
        (text_rules_path            , glob.glob("conf/rules/textclassifier/*.yar")),
        (cookie_rules_path          , glob.glob("conf/rules/cookieclassifier/*.yar")),
        (image_rules_path           , glob.glob("conf/rules/imageclassifier/*.yar")),
        (html_filter_path           , glob.glob("conf/rules/htmlfilter/*.yar")),
        (js_filter_path             , glob.glob("conf/rules/jsfilter/*.yar")),
        (vbs_filter_path            , glob.glob("conf/rules/vbsfilter/*.yar")),
        (url_filter_path            , glob.glob("conf/rules/urlfilter/*.yar")),
        (sample_filter_path         , glob.glob("conf/rules/samplefilter/*.yar")),
        (text_filter_path           , glob.glob("conf/rules/textfilter/*.yar")),
        (cookie_filter_path         , glob.glob("conf/rules/cookiefilter/*.yar")),
        (image_filter_path          , glob.glob("conf/rules/imagefilter/*.yar")),
    ],
    install_requires = open("requirements.txt", encoding = 'utf-8', mode = 'r').read().splitlines(),
    entry_points = {
        "console_scripts": [
            "thug = thug.thug:main",
        ]
    },
    project_urls = {
        'Bug Reports': 'https://github.com/buffer/thug/issues',
        'Funding': 'https://buffer.github.io/thug/',
        'Source': 'https://github.com/buffer/thug/',
    },
)
