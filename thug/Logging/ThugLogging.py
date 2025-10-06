#!/usr/bin/env python
#
# ThugLogging.py
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
import operator
import types
import copy
import uuid
import random
import string
import errno
import hashlib
import logging
import configparser

from thug.Analysis.awis.AWIS import AWIS
from thug.Analysis.context.ContextAnalyzer import ContextAnalyzer
from thug.Analysis.favicon.Favicon import Favicon
from thug.Analysis.honeyagent.HoneyAgent import HoneyAgent
from thug.Analysis.screenshot.Screenshot import Screenshot
from thug.Analysis.shellcode.Shellcode import Shellcode

from .BaseLogging import BaseLogging
from .SampleLogging import SampleLogging
from .LoggingModules import LoggingModules
from .Features import Features

log = logging.getLogger("Thug")


class ThugLogging(BaseLogging, SampleLogging):
    eval_min_length_logging = 4

    def __init__(self):
        BaseLogging.__init__(self)
        SampleLogging.__init__(self)

        self.AWIS = AWIS()
        self.ContextAnalyzer = ContextAnalyzer()
        self.Favicon = Favicon()
        self.Features = Features()
        self.HoneyAgent = HoneyAgent()
        self.Screenshot = Screenshot()
        self.Shellcode = Shellcode()
        self.baseDir = None
        self.formats = set()
        self.frames = {}
        self.meta = {}
        self.meta_refresh = []
        self.methods_cache = {}
        self.redirections = {}
        self.retrieved_urls = set()
        self.shellcodes = set()
        self.shellcode_urls = set()
        self.ssl_certs = {}
        self.url = ""
        self.windows = {}

        self.__init_hook_symbols()
        self.__init_pyhooks()
        self.__init_config()

    @staticmethod
    def get_random_name():
        return "".join(
            random.choice(string.ascii_lowercase) for _ in range(random.randint(10, 32))
        )

    def __init_hook_symbols(self):
        for name in (
            "eval",
            "write",
        ):
            setattr(
                self,
                f"{name}_symbol",
                (
                    self.get_random_name(),
                    self.get_random_name(),
                ),
            )

    def __init_pyhooks(self):
        hooks = log.PyHooks.get("ThugLogging", None)
        if hooks is None:
            return

        get_method_function = operator.attrgetter("__func__")
        get_method_self = operator.attrgetter("__self__")

        for label, hook in hooks.items():
            name = f"{label}_hook"
            _hook = get_method_function(hook) if get_method_self(hook) else hook
            method = types.MethodType(_hook, ThugLogging)
            setattr(self, name, method)

    def __init_config(self):
        conf_file = os.path.join(log.configuration_path, "thug.conf")
        if not os.path.exists(conf_file):  # pragma: no cover
            log.critical(
                "Logging subsystem not initialized (configuration file not found)"
            )
            return

        self.modules = {}
        config = configparser.ConfigParser()
        config.read(conf_file)

        for name, module in LoggingModules.items():
            if self.check_module(name, config):
                self.modules[name.strip()] = module()

        for m in self.modules.values():
            for fmt in getattr(m, "formats", tuple()):
                self.formats.add(fmt)  # pragma: no cover

    def resolve_method(self, name):
        if name in self.methods_cache:
            return self.methods_cache[name]

        methods = []

        for module in self.modules.values():
            m = getattr(module, name, None)
            if m:
                methods.append(m)

        self.methods_cache[name] = methods
        return methods

    def clear(self):
        self.Features.clear()

    def set_url(self, url):
        self.clear()

        self.url = url

        for m in self.resolve_method("set_url"):
            m(url)

        if log.ThugOpts.awis:  # pragma: no cover
            report = log.ThugLogging.AWIS.query(url)
            if not report:
                return

            for m in self.resolve_method("log_awis"):
                m(report)

    def add_behavior_warn(
        self,
        description=None,
        cve=None,
        snippet=None,
        method="Dynamic Analysis",
        verbose=True,
    ):
        for m in self.resolve_method("add_behavior_warn"):
            m(description, cve, snippet, method)

        if verbose or log.ThugOpts.verbose or log.ThugOpts.debug:
            log.warning(description)

    def check_snippet(self, s):
        return len(s) < self.eval_min_length_logging

    def add_code_snippet(
        self,
        snippet,
        language,
        relationship,
        method="Dynamic Analysis",
        check=False,
        force=False,
    ):
        if not log.ThugOpts.code_logging and not force:
            return None

        if check and self.check_snippet(snippet):
            return None

        tag = uuid.uuid4()

        for m in self.resolve_method("add_code_snippet"):
            m(snippet, language, relationship, tag.hex, method)

        return tag.hex

    def add_shellcode_snippet(self, snippet, language, relationship, method):
        tag = uuid.uuid4()

        for m in self.resolve_method("add_shellcode_snippet"):
            m(snippet, language, relationship, tag.hex, method)

        return tag.hex

    def log_file(self, data, url=None, params=None, sampletype=None):
        if isinstance(data, bytearray):
            data = bytes(data)

        sample = self.build_sample(data, url, sampletype)

        if sample is None:
            return None

        return self.__log_file(sample, data, url, params)

    def __log_file(self, sample, data, url=None, params=None):
        for m in self.resolve_method("log_file"):
            m(copy.deepcopy(sample), url, params)

        if sample["type"] in ("JAR",):
            self.HoneyAgent.analyze(data, sample, self.baseDir, params)

        log.SampleClassifier.classify(data, sample["md5"])
        return sample

    def log_event(self):
        for m in self.resolve_method("export"):
            m(self.baseDir)

        for m in self.resolve_method("log_event"):  # pragma: no cover
            m(self.baseDir)

        if log.ThugOpts.file_logging:
            log.warning("Thug analysis logs saved at %s", self.baseDir)

    def log_connection(self, source, destination, method, flags=None):
        """
        Log the connection (redirection, link) between two pages

        @source         The origin page
        @destination    The page the user is made to load next
        @method         Link, iframe, .... that moves the user from source to destination
        @flags          Additional information flags. Existing are: "exploit"
        """
        if flags is None:
            flags = {}

        for m in self.resolve_method("log_connection"):
            m(source, destination, method, flags)

    def log_location(self, url, data, flags=None):
        """
        Log file information for a given url

        @url    URL we fetched this file from
        @data   File dictionary data
                    Keys:
                        - content     Content
                        - md5         MD5 checksum
                        - sha256      SHA-256 checksum
                        - ssdeep      Ssdeep hash
                        - fsize       Content size
                        - ctype       Content type (whatever the server says it is)
                        - mtype       Calculated MIME type

        @flags  Additional information flags
        """
        if flags is None:
            flags = {}

        for m in self.resolve_method("log_location"):
            m(url, data, flags=flags)

    def log_exploit_event(
        self, url, module, description, cve=None, data=None, forward=True
    ):
        """
        Log file information for a given url

        @url            URL where this exploit occurred
        @module         Module/ActiveX Control, ... that gets exploited
        @description    Description of the exploit
        @cve            CVE number (if available)
        @forward        Forward log to add_behavior_warn
        """
        if forward:
            self.add_behavior_warn(f"[{module}] {description}", cve=cve)

        for m in self.resolve_method("log_exploit_event"):
            m(url, module, description, cve=cve, data=data)

    def log_image_ocr(self, url, result, forward=True):
        """
        Log the results of images OCR-based analysis

        @url            Image URL
        @result         OCR analysis result
        @forward        Forward log to log.warning
        """
        if forward:
            log.warning("[OCR] Result: %s (URL: %s)", result, url)

        for m in self.resolve_method("log_image_ocr"):
            m(url, result)

    def log_classifier(self, classifier, url, rule, tags="", meta=None):
        """
        Log classifiers matching for a given url

        @classifier     Classifier name
        @url            URL where the rule match occurred
        @rule           Rule name
        @meta           Rule meta
        @tags           Rule tags
        """
        self.add_behavior_warn(
            f"[{classifier.upper()} Classifier] URL: {url} "
            f"(Rule: {rule}, Classification: {tags})"
        )

        if meta is None:
            meta = {}  # pragma: no cover

        for m in self.resolve_method("log_classifier"):
            m(classifier, url, rule, tags, meta)

        hook = getattr(self, "log_classifier_hook", None)
        if hook:
            hook(classifier, url, rule, tags, meta)  # pylint:disable=not-callable

    def log_cookies(self):
        for m in self.resolve_method("log_cookies"):
            m()

    def log_redirect(self, response, window):
        self.log_cookies()

        if not response.history:
            if "Set-Cookie" in response.headers:
                log.CookieClassifier.classify(
                    response.url, response.headers["Set-Cookie"]
                )

            if response.url:
                log.URLClassifier.classify(response.url)
                log.HTTPSession.fetch_ssl_certificate(response.url)

            return None

        final = response.url

        while final is None:  # pragma: no cover
            for h in reversed(response.history):
                final = h.url

        for h in response.history:
            if "Set-Cookie" in h.headers:
                log.CookieClassifier.classify(h.url, h.headers["Set-Cookie"])

            location = h.headers.get("location", None)

            self.add_behavior_warn(
                f"[HTTP Redirection (Status: {h.status_code})] "
                f"Content-Location: {h.url} --> Location: {location}"
            )

            location = log.HTTPSession.normalize_url(window, location)
            self.log_connection(h.url, location, "http-redirect")

            log.HTMLClassifier.classify(h.url, h.content)
            log.URLClassifier.classify(h.url)
            log.HTTPSession.fetch_ssl_certificate(h.url)

            ctype = h.headers.get("content-type", "unknown")

            md5 = hashlib.md5()  # nosec
            md5.update(h.content)
            sha256 = hashlib.sha256()
            sha256.update(h.content)

            mtype = log.Magic.get_mime(h.content)

            data = {
                "content": h.content,
                "status": h.status_code,
                "md5": md5.hexdigest(),
                "sha256": sha256.hexdigest(),
                "fsize": len(h.content),
                "ctype": ctype,
                "mtype": mtype,
            }

            self.log_location(h.url, data)

        log.URLClassifier.classify(final)
        log.HTTPSession.fetch_ssl_certificate(final)

        return final

    def log_href_redirect(self, referer, url):
        if not url:  # pragma: no cover
            return

        self.add_behavior_warn(
            f"[HREF Redirection (document.location)] Content-Location: {referer} --> Location: {url}"
        )
        self.log_connection(referer, url, "href")

    def log_certificate(self, url, certificate):
        if not log.ThugOpts.cert_logging:
            return

        self.add_behavior_warn(
            f"[Certificate]{os.linesep} {certificate}", verbose=False
        )

        for m in self.resolve_method("log_certificate"):  # pragma: no cover
            m(url, certificate)

    def log_analysis_module(self, dirname, sample, report, module, fmt="json"):
        filename = f"{sample['md5']}.{fmt}"
        self.store_content(dirname, filename, report)

        method = f"log_{module}"
        for m in self.resolve_method(method):  # pragma: no cover
            m(sample, report)

    def log_honeyagent(self, dirname, sample, report):
        self.log_analysis_module(dirname, sample, report, "honeyagent")

    def log_favicon(self, url, favicon):
        dhash = self.Favicon.eval_dhash(favicon)
        if dhash is None:  # pragma: no cover
            return

        self.add_behavior_warn(f"[Favicon] URL: {url} (dhash: {dhash})")

        for m in self.resolve_method("log_favicon"):
            m(url, dhash)

    def log_screenshot(self, url, screenshot):
        """
        Log the screenshot of the analyzed page

        @url        URL
        @screenshot Screenshot
        """
        dirname = os.path.join(self.baseDir, "analysis", "screenshots")
        filename = f"{hashlib.sha256(screenshot).hexdigest()}.pdf"
        self.store_content(dirname, filename, screenshot)

        for m in self.resolve_method("log_screenshot"):  # pragma: no cover
            m(url, screenshot)

    @staticmethod
    def store_content(dirname, filename, content):
        """
        This method is meant to be used when a content (downloaded
        pages, samples, reports, etc. ) has to be saved in a flat
        file.

        @dirname    The directory where to store content
        @filename   The file where to store content
        @content    The content to be stored
        """
        if not log.ThugOpts.file_logging:
            return None

        try:
            os.makedirs(dirname)
        except OSError as e:
            if e.errno == errno.EEXIST:
                pass
            else:  # pragma: no cover
                raise

        fname = os.path.join(dirname, filename)

        try:
            with open(fname, "wb") as fd:
                fd.write(content)
        except Exception as e:  # pragma: no cover,pylint:disable=broad-except
            log.warning(str(e))

        return fname
