#!/usr/bin/env python
#
# ThugAPI.py
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA  02111-1307  USA

import sys
import os
import logging
import PyV8

from zope.interface import implements

try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

from DOM.W3C import w3c
from DOM import Window
from DOM import HTTPSession
from DOM import DFT
from DOM import MIMEHandler
from DOM import SchemeHandler
from WebTracking import WebTracking
from Encoding import Encoding
from Logging.ThugLogging import ThugLogging

from .IThugAPI import IThugAPI
from .ThugOpts import ThugOpts
from .ThugVulnModules import ThugVulnModules
from .OpaqueFilter import OpaqueFilter
from .abstractmethod import abstractmethod

from Classifier import JSClassifier
from Classifier import URLClassifier
from Classifier import SampleClassifier

log = logging.getLogger("Thug")
log.setLevel(logging.WARN)

__thug_version__ = '0.6.5'


class ThugAPI:
    implements(IThugAPI)

    def __init__(self, args, configuration_path = None):
        self.args               = args
        self.thug_version       = __thug_version__
        log.configuration_path  = configuration_path
        log.personalities_path  = os.path.join(configuration_path, "personalities") if configuration_path else None
        log.ThugOpts            = ThugOpts()
        log.ThugVulnModules     = ThugVulnModules()
        log.WebTracking         = WebTracking.WebTracking()
        log.MIMEHandler         = MIMEHandler.MIMEHandler()
        log.SchemeHandler       = SchemeHandler.SchemeHandler()
        log.JSClassifier        = JSClassifier.JSClassifier()
        log.URLClassifier       = URLClassifier.URLClassifier()
        log.SampleClassifier    = SampleClassifier.SampleClassifier()
        log.Encoding            = Encoding.Encoding()

    def __call__(self):
        self.analyze()

    def usage(self):
        pass

    def version(self):
        print("Thug %s" % (self.thug_version, ))
        sys.exit(0)

    def get_useragent(self):
        return log.ThugOpts.useragent

    def set_useragent(self, useragent):
        log.ThugOpts.useragent = useragent

    def get_events(self):
        return log.ThugOpts.events

    def set_events(self, events):
        log.ThugOpts.events = events

    def get_delay(self):
        return log.ThugOpts.delay

    def set_delay(self, delay):
        log.ThugOpts.delay = delay

    def get_file_logging(self):
        return log.ThugOpts.file_logging

    def set_file_logging(self):
        log.ThugOpts.file_logging = True

    def get_json_logging(self):
        return log.ThugOpts.json_logging

    def set_json_logging(self):
        log.ThugOpts.json_logging = True

    def get_maec11_logging(self):
        return log.ThugOpts.maec11_logging

    def set_maec11_logging(self):
        log.ThugOpts.maec11_logging = True

    def get_elasticsearch_logging(self):
        return log.ThugOpts.elasticsearch_logging

    def set_elasticsearch_logging(self):
        log.ThugOpts.elasticsearch_logging = True
        logging.getLogger("elasticsearch").setLevel(logging.ERROR)

    def get_referer(self):
        return log.ThugOpts.referer

    def set_referer(self, referer):
        log.ThugOpts.referer = referer

    def get_proxy(self):
        return log.ThugOpts.proxy

    def set_proxy(self, proxy):
        log.ThugOpts.proxy = proxy

    def set_no_fetch(self):
        log.ThugOpts.no_fetch = True

    def set_verbose(self):
        log.setLevel(logging.INFO)

    def set_debug(self):
        log.setLevel(logging.DEBUG)

    def set_no_cache(self):
        log.ThugOpts.cache = None

    def set_ast_debug(self):
        log.ThugOpts.ast_debug = True

    def set_http_debug(self):
        log.ThugOpts.http_debug += 1

    def set_acropdf_pdf(self, acropdf_pdf):
        log.ThugVulnModules.acropdf_pdf = acropdf_pdf

    def disable_acropdf(self):
        log.ThugVulnModules.disable_acropdf()

    def set_shockwave_flash(self, shockwave):
        log.ThugVulnModules.shockwave_flash = shockwave

    def disable_shockwave_flash(self):
        log.ThugVulnModules.disable_shockwave_flash()

    def set_javaplugin(self, javaplugin):
        log.ThugVulnModules.javaplugin = javaplugin

    def disable_javaplugin(self):
        log.ThugVulnModules.disable_javaplugin()

    def get_threshold(self):
        return log.ThugOpts.threshold

    def set_threshold(self, threshold):
        log.ThugOpts.threshold = threshold

    def get_extensive(self):
        return log.ThugOpts.extensive

    def set_extensive(self):
        log.ThugOpts.extensive = True

    def get_timeout(self):
        return log.ThugOpts.timeout

    def set_timeout(self, timeout):
        log.ThugOpts.timeout = timeout

    def get_broken_url(self):
        return log.ThugOpts.broken_url

    def set_broken_url(self):
        log.ThugOpts.broken_url = True

    def get_web_tracking(self):
        return log.ThugOpts.web_tracking

    def set_web_tracking(self):
        log.ThugOpts.web_tracking = True

    def disable_honeyagent(self):
        log.ThugOpts.honeyagent = False

    def log_init(self, url):
        log.ThugLogging = ThugLogging(self.thug_version)
        log.ThugLogging.set_basedir(url)

    def set_log_dir(self, logdir):
        log.ThugLogging.set_absbasedir(logdir)

    def set_log_output(self, output):
        fh = logging.FileHandler(os.path.join(log.ThugLogging.baseDir, output))
        log.addHandler(fh)

    def set_log_quiet(self):
        root = logging.getLogger()
        for handler in root.handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.addFilter(OpaqueFilter())

    def set_vt_query(self):
        log.ThugOpts.set_vt_query()

    def set_vt_submit(self):
        log.ThugOpts.set_vt_submit()

    def get_vt_runtime_apikey(self):
        return log.ThugOpts.vt_runtime_apikey

    def set_vt_runtime_apikey(self, vt_runtime_apikey):
        log.ThugOpts.vt_runtime_apikey = vt_runtime_apikey

    def get_mongodb_address(self):
        return log.ThugOpts.mongodb_address

    def set_mongodb_address(self, mongodb_address):
        log.ThugOpts.mongodb_address = mongodb_address

    def add_urlclassifier(self, rule):
        log.URLClassifier.add_rule(rule)

    def add_jsclassifier(self, rule):
        log.JSClassifier.add_rule(rule)

    def add_sampleclassifier(self, rule):
        log.SampleClassifier.add_rule(rule)

    def log_event(self):
        log.ThugLogging.log_event()

    def run(self, window):
        with PyV8.JSLocker():
            dft = DFT.DFT(window)
            dft.run()

    def run_local(self, url):
        log.ThugLogging.set_url(url)
        log.ThugOpts.local = True

        log.HTTPSession = HTTPSession.HTTPSession()

        html   = open(url, 'r').read()
        doc    = w3c.parseString(html)
        window = Window.Window('about:blank', doc, personality = log.ThugOpts.useragent)
        window.open()
        self.run(window)

    def run_remote(self, url):
        scheme = urlparse.urlparse(url).scheme

        if not scheme or not scheme.startswith('http'):
            url = 'http://%s' % (url, )

        log.ThugLogging.set_url(url)

        log.HTTPSession = HTTPSession.HTTPSession()

        doc    = w3c.parseString('')
        window = Window.Window(log.ThugOpts.referer, doc, personality = log.ThugOpts.useragent)
        window = window.open(url)
        if window:
            self.run(window)

    @abstractmethod
    def analyze(self):
        pass
