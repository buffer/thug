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
from zope.interface import implements

try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

from DOM.W3C import w3c
from DOM import Window, DFT, MIMEHandler, SchemeHandler
from Logging.ThugLogging import ThugLogging

from .IThugAPI import IThugAPI
from .ThugOpts import ThugOpts
from .ThugVulnModules import ThugVulnModules
from .OpaqueFilter import OpaqueFilter
from .abstractmethod import abstractmethod

log = logging.getLogger("Thug")

__thug_version__ = '0.4.21'


class ThugAPI:
    implements(IThugAPI)

    def __init__(self, args):
        self.args               = args
        self.thug_version       = __thug_version__
        log.ThugOpts            = ThugOpts()
        log.ThugVulnModules     = ThugVulnModules()
        log.MIMEHandler         = MIMEHandler.MIMEHandler()
        log.SchemeHandler       = SchemeHandler.SchemeHandler()

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

    def get_referer(self):
        return log.ThugOpts.referer

    def set_referer(self, referer):
        log.ThugOpts.referer = referer

    def get_proxy(self):
        return log.ThugOpts.proxy_info

    def set_proxy(self, proxy):
        log.ThugOpts.proxy_info = proxy

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

    def log_event(self):
        log.ThugLogging.log_event()

    def run(self, window):
        dft = DFT.DFT(window)
        dft.run()

    def run_local(self, url):
        log.ThugLogging.set_url(url)
        log.ThugOpts.local = True

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

        doc    = w3c.parseString('')
        window = Window.Window(log.ThugOpts.referer, doc, personality = log.ThugOpts.useragent)
        window = window.open(url)
        if window:
            self.run(window)

    @abstractmethod
    def analyze(self):
        pass
