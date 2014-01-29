#!/usr/bin/env python
#
# JSONLog.py
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

import sys
import logging
import datetime
import os
import json
import codecs
import chardet
from .Mapper import Mapper
from .compatibility import *

log = logging.getLogger("Thug")


class JSONLog(object):
    def __init__(self, thug_version):
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
                                            "timeout"        : log.ThugOpts._timeout_in_secs,
                                            "threshold"      : log.ThugOpts.threshold,
                                            "extensive"      : log.ThugOpts.extensive,
                                            },
                                        },
                        "behavior"    : [],
                        "code"        : [],
                        "files"       : [],
                        "connections" : [],
                        "locations"   : [],
                        "exploits"    : []
                    }

    def get_vuln_module(self, module):
        disabled = getattr(log.ThugVulnModules, "%s_disabled" % (module, ), True)
        if disabled: 
            return "disabled"

        return getattr(log.ThugVulnModules, module)


    def fix(self, data):
        """
        Fix encoding of data

        @data  data to encode properly
        """
        try:
            enc = chardet.detect(data)
            return data.decode(enc['encoding']).replace("\n", "").strip()
        except:
            return thug_unicode(data).replace("\n", "").strip()

    def make_counter(self, p):
        id = p
        while True:
            yield id
            id += 1

    def set_url(self, url):
        self.data["url"] = self.fix(url)

    def add_code_snippet(self, snippet, language, relationship, method = "Dynamic Analysis"):
        return  # Turned off. We first want files and connections

        self.data["code"].append({"snippet"      : self.fix(snippet),
                                  "language"     : self.fix(language),
                                  "relationship" : self.fix(relationship),
                                  "method"       : self.fix(method)})

    def log_connection(self, source, destination, method, flags = {}):
        """
        Log the connection (redirection, link) between two pages

        @source        The origin page
        @destination   The page the user is made to load next
        @method        Link, iframe, .... that moves the user from source to destination
        @flags         Additional information flags. Existing are: "exploit"
        """

        if "exploit" in flags and flags["exploit"]:
            self.add_behavior_warn("!!!Exploit!!!  %s -- %s --> %s" % (source,
                                                                       method,
                                                                       destination, ))
        else:
            self.add_behavior_warn("%s -- %s --> %s" % (source,
                                                        method,
                                                        destination,))

        self.data["connections"].append({"source"       : self.fix(source),
                                         "destination"  : self.fix(destination),
                                         "method"       : method,
                                         "flags"        : flags})

    def log_location(self, url, ctype, md5, sha256, flags = {}, fsize = 0, mtype = ""):
        """
        Log file information for a given url

        @url       Url we fetched this file from
        @ctype     Content type (whatever the server says)
        @md5       MD5 hash
        @sha256    SHA256 hash
        @flags     Known flags: "error"
        @fsize     File size
        @mtype     Calculated mime type
        """
        self.data["locations"].append({"url"          : self.fix(url),
                                       "content-type" : ctype,
                                       "md5"          : md5,
                                       "sha256"       : sha256,
                                       "flags"        : flags,
                                       "size"         : fsize,
                                       "mimetype"     : mtype})

    def log_exploit_event(self, url, module, description, cve = None, data = None):
        """
        Log file information for a given url

        @url            Url where this exploit occured
        @module         Module/ActiveX Control, ... that gets exploited
        @description    Description of the exploit
        @cve            CVE number (if available)
        """
        self.data["exploits"].append({"url"         : self.fix(url),
                                      "module"      : module,
                                      "description" : description,
                                      "cve"         : cve,
                                      "data"        : data})

    def add_behavior(self, description = None, cve = None, method = "Dynamic Analysis"):
        if not cve and not description:
            return

        self.data["behavior"].append({"description" : self.fix(description),
                                      "cve"         : self.fix(cve),
                                      "method"      : self.fix(method),
                                      "timestamp"   : str(datetime.datetime.now())})

    def add_behavior_warn(self, description = None, cve = None, method = "Dynamic Analysis"):
        self.add_behavior(description, cve, method)
        #log.warning(description)

    def log_file(self, data):
        self.data["files"].append(data)

    def export(self, basedir):
        report = codecs.open(os.path.join(basedir, "avlog.json"),
                             "w", 
                             errors='ignore', 
                             encoding = 'utf-8')

        json.dump(self.data, report, ensure_ascii = False, encoding = "utf-8", sort_keys = False, indent = 4)
        report.close()
        m = Mapper(basedir)
        m.add_data(self.data)
        m.write_svg()
