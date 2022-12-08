#!/usr/bin/env python

import os
import glob
from setuptools import setup

import thug

os.environ['BUILD_LIB'] = '1'

setup(
   data_files = [
        (thug.__configuration_path__, ["conf/thug.conf", "conf/inspector.json"]),
        (thug.__personalities_path__, glob.glob("conf/personalities/*.json")),
        (thug.__rules_path__        , glob.glob("conf/rules/*.yar")),
        (thug.__scripts_path__      , glob.glob("thug/DOM/scripts/*.js")),
        (thug.__plugins_path__      , []),
        (thug.__hooks_path__        , []),
        (thug.__html_rules_path__   , glob.glob("conf/rules/htmlclassifier/*.yar")),
        (thug.__js_rules_path__     , glob.glob("conf/rules/jsclassifier/*.yar")),
        (thug.__vbs_rules_path__    , glob.glob("conf/rules/vbsclassifier/*.yar")),
        (thug.__url_rules_path__    , glob.glob("conf/rules/urlclassifier/*.yar")),
        (thug.__sample_rules_path__ , glob.glob("conf/rules/sampleclassifier/*.yar")),
        (thug.__text_rules_path__   , glob.glob("conf/rules/textclassifier/*.yar")),
        (thug.__cookie_rules_path__ , glob.glob("conf/rules/cookieclassifier/*.yar")),
        (thug.__image_rules_path__  , glob.glob("conf/rules/imageclassifier/*.yar")),
        (thug.__html_filter_path__  , glob.glob("conf/rules/htmlfilter/*.yar")),
        (thug.__js_filter_path__    , glob.glob("conf/rules/jsfilter/*.yar")),
        (thug.__vbs_filter_path__   , glob.glob("conf/rules/vbsfilter/*.yar")),
        (thug.__url_filter_path__   , glob.glob("conf/rules/urlfilter/*.yar")),
        (thug.__sample_filter_path__, glob.glob("conf/rules/samplefilter/*.yar")),
        (thug.__text_filter_path__  , glob.glob("conf/rules/textfilter/*.yar")),
        (thug.__cookie_filter_path__, glob.glob("conf/rules/cookiefilter/*.yar")),
        (thug.__image_filter_path__ , glob.glob("conf/rules/imagefilter/*.yar")),
   ],
)
