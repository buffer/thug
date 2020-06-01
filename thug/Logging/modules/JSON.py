#!/usr/bin/env python
#
# JSON.py
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
#
# Author:   Thorsten Sick <thorsten.sick@avira.com> from Avira
#           (developed for the iTES Project http://ites-project.org)

import os
import json
import base64
import logging
import datetime

import six

from .Mapper import Mapper

log = logging.getLogger("Thug")


class JSON(object):
    def __init__(self, thug_version, provider = False):
        self._tools = ({
                        'id'          : 'json-log',
                        'Name'        : 'Thug',
                        'Version'     : thug_version,
                        'Vendor'      : None,
                        'Organization': 'The Honeynet Project',
                       }, )

        self.associated_code = None
        self.object_pool     = None
        self.signatures      = list()
        self.cached_data     = None
        self.provider        = provider

        self.data = {
                        "url"         : None,
                        "timestamp"   : str(datetime.datetime.now()),
                        "logtype"     : "json-log",
                        "thug"        : {
                                        "version"            : thug_version,
                                        "personality" : {
                                            "useragent"      : log.ThugOpts.useragent
                                            },
                                        "plugins" : {
                                            "acropdf"        : self.get_vuln_module("acropdf"),
                                            "javaplugin"     : self.get_vuln_module("_javaplugin"),
                                            "shockwaveflash" : self.get_vuln_module("shockwave_flash")
                                            },
                                        "options" : {
                                            "local"          : log.ThugOpts.local,
                                            "nofetch"        : log.ThugOpts.no_fetch,
                                            "proxy"          : log.ThugOpts._proxy,
                                            "events"         : log.ThugOpts.events,
                                            "delay"          : log.ThugOpts.delay,
                                            "referer"        : log.ThugOpts.referer,
                                            "timeout"        : log.ThugOpts.timeout,
                                            "threshold"      : log.ThugOpts.threshold,
                                            "extensive"      : log.ThugOpts.extensive,
                                            },
                                        },
                        "behavior"    : [],
                        "code"        : [],
                        "cookies"     : [],
                        "files"       : [],
                        "connections" : [],
                        "locations"   : [],
                        "exploits"    : [],
                        "classifiers" : [],
                        "images"      : []
                    }

    @property
    def json_enabled(self):
        return log.ThugOpts.json_logging or 'json' in log.ThugLogging.formats or self.provider

    def get_vuln_module(self, module):
        disabled = getattr(log.ThugVulnModules, "{}_disabled".format(module), True)
        if disabled:
            return "disabled"

        return getattr(log.ThugVulnModules, module)

    def fix(self, data, drop_spaces = True):
        """
        Fix data encoding

        @data  data to encode properly
        """
        if not data:
            return str()

        try:
            if isinstance(data, six.string_types):
                enc_data = data
            else:
                enc = log.Encoding.detect(data)
                encoding = enc['encoding'] if enc['encoding'] else 'utf-8'
                enc_data = data.decode(encoding)

            return enc_data.replace("\n", "").strip() if drop_spaces else enc_data
        except UnicodeDecodeError: # pragma: no cover
            return str()

    def set_url(self, url):
        if not self.json_enabled:
            return

        self.data["url"] = url

    def add_code_snippet(self, snippet, language, relationship, tag, method = "Dynamic Analysis"):
        if not self.json_enabled:
            return

        self.data["code"].append({"snippet"      : self.fix(snippet),
                                  "language"     : self.fix(language),
                                  "relationship" : self.fix(relationship),
                                  "tag"          : self.fix(tag),
                                  "method"       : self.fix(method)})

    def add_shellcode_snippet(self, snippet, language, relationship, tag, method = "Dynamic Analysis"):
        if not self.json_enabled:
            return

        s = base64.b64encode(snippet.encode())

        self.data["code"].append({"snippet"      : s.decode(),
                                  "language"     : self.fix(language),
                                  "relationship" : self.fix(relationship),
                                  "tag"          : self.fix(tag),
                                  "method"       : self.fix(method)})

    def log_connection(self, source, destination, method, flags = None):
        """
        Log the connection (redirection, link) between two pages

        @source        The origin page
        @destination   The page the user is made to load next
        @method        Link, iframe, .... that moves the user from source to destination
        @flags         Additional information flags. Existing are: "exploit"
        """
        if not self.json_enabled:
            return

        if flags is None:
            flags = dict()

        if "exploit" in flags and flags["exploit"]:
            self.add_behavior_warn("[Exploit]  {} -- {} --> {}".format(source,
                                                                   method,
                                                                   destination, ))
        else:
            self.add_behavior_warn("{} -- {} --> {}".format(source,
                                                        method,
                                                        destination,))

        self.data["connections"].append({"source"       : self.fix(source),
                                         "destination"  : self.fix(destination),
                                         "method"       : method,
                                         "flags"        : flags})

    def get_content(self, data):
        content = "NOT AVAILABLE"

        if not log.ThugOpts.code_logging:
            return content

        try:
            content = self.fix(data.get("content", "NOT AVAILABLE"))
        except Exception as e: # pragma: no cover
            log.info("[ERROR][get_content] %s", str(e))

        return content

    def log_location(self, url, data, flags = None):
        """
        Log file information for a given url

        @url    URL we fetched data from
        @data   File dictionary data
                    Keys:
                        - content     Content
                        - md5         MD5 checksum
                        - sha256      SHA-256 checksum
                        - fsize       Content size
                        - ctype       Content type (whatever the server says it is)
                        - mtype       Calculated MIME type

        @flags  Additional information flags (known flags: "error")
        """
        if not self.json_enabled:
            return

        if flags is None:
            flags = dict()

        self.data["locations"].append({"url"          : self.fix(url),
                                       "content"      : self.get_content(data),
                                       "status"       : data.get("status", None),
                                       "content-type" : data.get("ctype", None),
                                       "md5"          : data.get("md5", None),
                                       "sha256"       : data.get("sha256", None),
                                       "flags"        : flags,
                                       "size"         : data.get("fsize", None),
                                       "mimetype"     : data.get("mtype", None)})

    def log_exploit_event(self, url, module, description, cve = None, data = None):
        """
        Log file information for a given url

        @url            URL where this exploit occured
        @module         Module/ActiveX Control, ... that gets exploited
        @description    Description of the exploit
        @cve            CVE number (if available)
        """
        if not self.json_enabled:
            return

        self.data["exploits"].append({"url"         : self.fix(url),
                                      "module"      : module,
                                      "description" : description,
                                      "cve"         : cve,
                                      "data"        : data})

    def log_image_ocr(self, url, result):
        """
        Log the results of images OCR-based analysis

        @url            Image URL
        @result         OCR analysis result
        """
        if not self.json_enabled:
            return

        self.data["images"].append({"url"        : self.fix(url),
                                    "classifier" : "OCR",
                                    "result"     : result})

    def log_classifier(self, classifier, url, rule, tags = "", meta = dict()):
        """
        Log classifiers matching for a given url

        @classifier     Classifier name
        @url            URL where the rule match occurred
        @rule           Rule name
        @meta           Rule meta
        @tags           Rule tags
        """
        if not self.json_enabled:
            return

        item = {"classifier" : classifier,
                "url"        : self.fix(url),
                "rule"       : rule,
                "meta"       : meta,
                "tags"       : tags}

        if item not in self.data["classifiers"]:
            self.data["classifiers"].append(item)

    def log_cookies(self):
        attrs = ('comment',
                 'comment_url',
                 'discard',
                 'domain',
                 'domain_initial_dot',
                 'domain_specified',
                 'expires',
                 'name',
                 'path',
                 'path_specified',
                 'port',
                 'port_specified',
                 'rfc2109',
                 'secure',
                 'value',
                 'version')

        for cookie in log.HTTPSession.cookies:
            item = dict()

            for attr in attrs:
                value = getattr(cookie, attr, None)
                if value is None:
                    continue

                item[attr] = value

            if item not in self.data["cookies"]:
                self.data["cookies"].append(item)

    def add_behavior(self, description = None, cve = None, snippet = None, method = "Dynamic Analysis"):
        if not cve and not description:
            return

        self.data["behavior"].append({"description" : self.fix(description),
                                      "cve"         : self.fix(cve),
                                      "snippet"     : self.fix(snippet, drop_spaces = False),
                                      "method"      : self.fix(method),
                                      "timestamp"   : str(datetime.datetime.now())})

    def add_behavior_warn(self, description = None, cve = None, snippet = None, method = "Dynamic Analysis"):
        if not self.json_enabled:
            return

        self.add_behavior(description, cve, snippet, method)

    def log_file(self, data, url = None, params = None):
        if not self.json_enabled:
            return

        if data not in self.data["files"]:
            self.data["files"].append(data)

    def export(self, basedir):
        if not self.json_enabled:
            return

        output = six.StringIO()

        if log.ThugOpts.features_logging and (log.ThugOpts.verbose or log.ThugOpts.debug):
            log.warning(log.ThugLogging.Features.features)

        self.data['features'] = log.ThugLogging.Features.features

        json.dump(self.data, output, sort_keys = False, indent = 4)
        if log.ThugOpts.json_logging and log.ThugOpts.file_logging:
            logdir = os.path.join(basedir, "analysis", "json")
            log.ThugLogging.store_content(logdir, 'analysis.json', output.getvalue().encode())

            m = Mapper(logdir)
            m.add_data(self.data)
            m.write_svg()

        self.cached_data = output

    def get_json_data(self, basedir):
        if self.cached_data:
            return self.cached_data.getvalue()

        return None
