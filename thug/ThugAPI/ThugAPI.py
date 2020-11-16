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

import os
import sys
import logging
import six.moves.urllib.parse as urlparse
import six
import bs4
from lxml.html import tostring
from lxml.html import builder as E
from zope.interface import implementer

from bs4.element import NavigableString
from bs4.element import CData
from bs4.element import Script

import thug
from thug.DOM.W3C import w3c
from thug.DOM.DFT import DFT
from thug.DOM.Window import Window
from thug.DOM.HTTPSession import HTTPSession
from thug.DOM.HTMLInspector import HTMLInspector
from thug.DOM.MIMEHandler import MIMEHandler
from thug.DOM.SchemeHandler import SchemeHandler
from thug.WebTracking.WebTracking import WebTracking
from thug.Encoding.Encoding import Encoding
from thug.Logging.ThugLogging import ThugLogging

from thug.DOM.JSEngine import JSEngine
from thug.Classifier.JSClassifier import JSClassifier
from thug.Classifier.VBSClassifier import VBSClassifier
from thug.Classifier.URLClassifier import URLClassifier
from thug.Classifier.HTMLClassifier import HTMLClassifier
from thug.Classifier.TextClassifier import TextClassifier
from thug.Classifier.CookieClassifier import CookieClassifier
from thug.Classifier.SampleClassifier import SampleClassifier
from thug.Classifier.ImageClassifier import ImageClassifier

from .IThugAPI import IThugAPI
from .ThugOpts import ThugOpts
from .Watchdog import Watchdog
from .OpaqueFilter import OpaqueFilter
from .abstractmethod import abstractmethod
from .ThugVulnModules import ThugVulnModules

log = logging.getLogger("Thug")
log.setLevel(logging.WARN)


@implementer(IThugAPI)
class ThugAPI(object):
    def __init__(self, configuration_path = thug.__configuration_path__):
        self.__init_conf(configuration_path)
        self.__init_jsengine()
        self.__init_pyhooks()
        self.__init_core()
        self.__init_classifiers()
        self.__init_opaque_filter()
        self.__init_trace()

    def __init_conf(self, configuration_path):
        log.configuration_path = configuration_path
        log.personalities_path = os.path.join(configuration_path, "personalities") if configuration_path else None

    def __init_jsengine(self):
        log.JSEngine = JSEngine()

    def __init_core(self):
        log.ThugOpts        = ThugOpts()
        log.ThugVulnModules = ThugVulnModules()
        log.MIMEHandler     = MIMEHandler()
        log.SchemeHandler   = SchemeHandler()
        log.Encoding        = Encoding()
        log.WebTracking     = WebTracking()
        log.HTMLInspector   = HTMLInspector()

    def __init_classifiers(self):
        log.HTMLClassifier   = HTMLClassifier()
        log.JSClassifier     = JSClassifier()
        log.VBSClassifier    = VBSClassifier()
        log.URLClassifier    = URLClassifier()
        log.SampleClassifier = SampleClassifier()
        log.TextClassifier   = TextClassifier()
        log.CookieClassifier = CookieClassifier()
        log.ImageClassifier  = ImageClassifier()

        self.classifiers_map = {
            'html'   : log.HTMLClassifier,
            'js'     : log.JSClassifier,
            'vbs'    : log.VBSClassifier,
            'url'    : log.URLClassifier,
            'sample' : log.SampleClassifier,
            'cookie' : log.CookieClassifier,
            'text'   : log.TextClassifier,
            'image'  : log.ImageClassifier
        }

    def __init_pyhooks(self):
        log.PyHooks = dict()

    def __init_trace(self):
        log.Trace = None

    def __init_opaque_filter(self):
        self.opaque_filter = OpaqueFilter()

    def __call__(self): # pragma: no cover
        self.analyze()

    def version(self):
        print("Thug %s (JS Engine: %s v%s)" % (thug.__version__,
                                               thug.__jsengine__,
                                               thug.__jsengine_version__))
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

    def get_attachment(self):
        return log.ThugOpts.attachment

    def set_attachment(self):
        log.ThugOpts.attachment = True

    def get_image_processing(self):
        return log.ThugOpts.image_processing

    def set_image_processing(self):
        log.ThugOpts.image_processing = True

    def reset_image_processing(self):
        log.ThugOpts.image_processing = False

    def get_file_logging(self):
        return log.ThugOpts.file_logging

    def set_file_logging(self):
        log.ThugOpts.file_logging = True

    def get_json_logging(self):
        return log.ThugOpts.json_logging

    def set_json_logging(self):
        log.ThugOpts.json_logging = True

    def get_elasticsearch_logging(self):
        return log.ThugOpts.elasticsearch_logging

    def set_elasticsearch_logging(self):
        log.ThugOpts.elasticsearch_logging = True
        logging.getLogger("elasticsearch").setLevel(logging.ERROR)

    def get_features_logging(self):
        return log.ThugOpts.features_logging

    def set_features_logging(self):
        log.ThugOpts.features_logging = True

    def reset_features_logging(self):
        log.ThugOpts.features_logging = False

    def get_referer(self):
        return log.ThugOpts.referer

    def set_referer(self, referer):
        log.ThugOpts.referer = referer

    def get_proxy(self):
        return log.ThugOpts.proxy

    def set_proxy(self, proxy):
        log.ThugOpts.proxy = proxy

    def get_raise_for_proxy(self):
        return log.ThugOpts.raise_for_proxy

    def set_raise_for_proxy(self, raise_for_proxy):
        log.ThugOpts.raise_for_proxy = raise_for_proxy

    def set_no_fetch(self):
        log.ThugOpts.no_fetch = True

    def set_verbose(self):
        log.ThugOpts.verbose = True
        log.setLevel(logging.INFO)

    def set_debug(self):
        log.ThugOpts.debug = True
        log.setLevel(logging.DEBUG)

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

    def set_silverlight(self, silverlight):
        log.ThugVulnModules.silverlight = silverlight

    def disable_silverlight(self):
        log.ThugVulnModules.disable_silverlight()

    def get_threshold(self):
        return log.ThugOpts.threshold

    def set_threshold(self, threshold):
        log.ThugOpts.threshold = threshold

    def get_extensive(self):
        return log.ThugOpts.extensive

    def set_extensive(self):
        log.ThugOpts.extensive = True

    def reset_extensive(self):
        log.ThugOpts.extensive = False

    def get_timeout(self):
        return log.ThugOpts.timeout

    def set_timeout(self, timeout):
        log.ThugOpts.timeout = timeout

    def get_connect_timeout(self):
        return log.ThugOpts.connect_timeout

    def set_connect_timeout(self, timeout):
        log.ThugOpts.connect_timeout = timeout

    def get_broken_url(self):
        return log.ThugOpts.broken_url

    def set_broken_url(self):
        log.ThugOpts.broken_url = True

    def get_ssl_verify(self):
        return log.ThugOpts.ssl_verify

    def set_ssl_verify(self):
        log.ThugOpts.ssl_verify = True

    def get_web_tracking(self):
        return log.ThugOpts.web_tracking

    def set_web_tracking(self):
        log.ThugOpts.web_tracking = True

    def disable_honeyagent(self):
        log.ThugOpts.honeyagent = False

    def enable_code_logging(self):
        log.ThugOpts.code_logging = True

    def disable_code_logging(self):
        log.ThugOpts.code_logging = False

    def enable_cert_logging(self):
        log.ThugOpts.cert_logging = True

    def disable_cert_logging(self):
        log.ThugOpts.cert_logging = False

    def enable_screenshot(self):
        log.ThugOpts.screenshot = True

    def disable_screenshot(self):
        log.ThugOpts.screenshot = False

    def enable_awis(self):
        log.ThugOpts.awis = True

    def disable_awis(self):
        log.ThugOpts.awis = False

    def log_init(self, url):
        log.ThugLogging = ThugLogging()
        log.ThugLogging.set_basedir(url)

    def set_log_dir(self, logdir):
        log.ThugLogging.set_absbasedir(logdir)

    def set_log_output(self, output):
        fh = logging.FileHandler(output)
        log.addHandler(fh)

    def set_log_quiet(self): # pragma: no cover
        root = logging.getLogger()
        for handler in root.handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.addFilter(self.opaque_filter)

    def set_log_verbose(self):
        root = logging.getLogger()
        for handler in root.handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.removeFilter(self.opaque_filter)

    def set_vt_query(self):
        log.ThugOpts.vt_query = True

    def set_vt_submit(self):
        log.ThugOpts.vt_submit = True

    def get_vt_runtime_apikey(self):
        return log.ThugOpts.vt_runtime_apikey

    def set_vt_runtime_apikey(self, vt_runtime_apikey):
        log.ThugOpts.vt_runtime_apikey = vt_runtime_apikey

    def get_mongodb_address(self):
        return log.ThugOpts.mongodb_address

    def set_mongodb_address(self, mongodb_address):
        log.ThugOpts.mongodb_address = mongodb_address

    def add_htmlclassifier(self, rule):
        log.HTMLClassifier.add_rule(rule)

    def add_urlclassifier(self, rule):
        log.URLClassifier.add_rule(rule)

    def add_jsclassifier(self, rule):
        log.JSClassifier.add_rule(rule)

    def add_vbsclassifier(self, rule):
        log.VBSClassifier.add_rule(rule)

    def add_textclassifier(self, rule):
        log.TextClassifier.add_rule(rule)

    def add_cookieclassifier(self, rule):
        log.CookieClassifier.add_rule(rule)

    def add_sampleclassifier(self, rule):
        log.SampleClassifier.add_rule(rule)

    def add_imageclassifier(self, rule):
        log.ImageClassifier.add_rule(rule)

    def add_htmlfilter(self, f):
        log.HTMLClassifier.add_filter(f)

    def add_urlfilter(self, f):
        log.URLClassifier.add_filter(f)

    def add_jsfilter(self, f):
        log.JSClassifier.add_filter(f)

    def add_vbsfilter(self, f):
        log.VBSClassifier.add_filter(f)

    def add_textfilter(self, f):
        log.TextClassifier.add_filter(f)

    def add_cookiefilter(self, f):
        log.CookieClassifier.add_filter(f)

    def add_samplefilter(self, f):
        log.SampleClassifier.add_filter(f)

    def add_imagefilter(self, f):
        log.ImageClassifier.add_filter(f)

    def add_customclassifier(self, cls_type, method):
        classifier_type = cls_type.lower().strip()

        if classifier_type not in self.classifiers_map:
            log.warning("Skipping unknown classifier type %s", cls_type)
            return

        self.classifiers_map[classifier_type].add_customclassifier(method)

    def reset_customclassifiers(self):
        for c in self.classifiers_map.values():
            c.reset_customclassifiers()

    def register_pyhook(self, module, method, hook):
        if module not in log.PyHooks:
            log.PyHooks[module] = dict()

        log.PyHooks[module][method] = hook

    def log_event(self):
        log.ThugLogging.log_event()

    def watchdog_cb(self, signum, frame): # pragma: no cover
        pass

    def __run(self, window):
        if log.Trace: # pragma: no cover
            sys.settrace(log.Trace)

        with log.JSEngine.JSLocker:
            with Watchdog(log.ThugOpts.timeout, callback = self.watchdog_cb):
                dft = DFT(window)
                dft.run()

    def run_local(self, url):
        log.last_url = None
        log.last_url_fetched = None

        log.ThugLogging.set_url(url)
        log.ThugOpts.local = True

        log.HTTPSession = HTTPSession()

        content   = open(url, 'r', encoding = "utf-8").read()
        extension = os.path.splitext(url)

        if len(extension) > 1 and extension[1].lower() in ('.js', '.jse', ):
            if not content.lstrip().startswith('<script'):
                html = tostring(E.HTML(E.HEAD(), E.BODY(E.SCRIPT(content))))
            else:
                soup = bs4.BeautifulSoup(content, "html.parser")

                try:
                    soup.html.unwrap()
                except AttributeError:
                    pass

                try:
                    soup.head.unwrap()
                except AttributeError:
                    pass

                try:
                    soup.body.unwrap()
                except AttributeError:
                    pass

                code = soup.script.get_text(types = (NavigableString, CData, Script))
                html = tostring(E.HTML(E.HEAD(), E.BODY(E.SCRIPT(code))))
        else:
            html = content

        if log.ThugOpts.features_logging:
            log.ThugLogging.Features.add_characters_count(len(html))
            log.ThugLogging.Features.add_whitespaces_count(len([a for a in html if isinstance(a, six.string_types) and a.isspace()]))

        doc    = w3c.parseString(html)
        window = Window('about:blank', doc, personality = log.ThugOpts.useragent)
        window.open()
        self.__run(window)

    def run_remote(self, url):
        log.last_url = None
        log.last_url_fetched = None

        log.ThugOpts.local = False

        try:
            scheme = urlparse.urlparse(url).scheme
        except ValueError as e: # pragma: no cover
            log.warning("[WARNING] Analysis not performed (%s)", str(e))
            return

        if not scheme or not scheme.startswith('http'):
            url = 'http://%s' % (url, )

        log.ThugLogging.set_url(url)

        log.HTTPSession = HTTPSession()

        doc    = w3c.parseString('')
        window = Window(log.ThugOpts.referer, doc, personality = log.ThugOpts.useragent)
        window = window.open(url)
        if window:
            self.__run(window)

    @abstractmethod
    def analyze(self): # pragma: no cover
        pass
