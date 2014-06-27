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

from .BaseLogging import BaseLogging
from .HPFeeds import HPFeeds
from .MAEC11 import MAEC11
from .MongoDB import MongoDB
from .JSONLog import JSONLog
from virustotal.VirusTotal import VirusTotal
from honeyagent.HoneyAgent import HoneyAgent

import os
import copy
import errno
import hashlib
import datetime
import logging
log = logging.getLogger("Thug")

class ThugLogging(BaseLogging):
    eval_min_length_logging = 4

    def __init__(self, thug_version):
        BaseLogging.__init__(self)

        self.HPFeeds        = HPFeeds()
        self.MAEC11         = MAEC11(thug_version)
        self.MongoDB        = MongoDB()
        self.JSONLog        = JSONLog(thug_version)
        self.VirusTotal     = VirusTotal()
        self.HoneyAgent     = HoneyAgent()
        self.baseDir        = None
        self.windows        = dict()
        self.shellcodes     = set()
        self.shellcode_urls = set()

    def set_url(self, url):
        self.HPFeeds.set_url(url)
        self.MAEC11.set_url(url)
        self.MongoDB.set_url(url)
        self.JSONLog.set_url(url)

    def add_behavior_warn(self, description = None, cve = None, method = "Dynamic Analysis"):
        self.MAEC11.add_behavior_warn(description, cve, method)
        self.JSONLog.add_behavior_warn(description, cve, method)

    def check_snippet(self, s):
        return len(s) < self.eval_min_length_logging

    def add_code_snippet(self, snippet, language, relationship, method = "Dynamic Analysis", check = False):
        if check and self.check_snippet(snippet):
            return

        self.MAEC11.add_code_snippet(snippet, language, relationship, method)
        self.JSONLog.add_code_snippet(snippet, language, relationship, method)

    def log_file(self, data, url = None, params = None):
        sample = self.build_sample(data, url)
        if sample is None:
            return None
        
        self.HPFeeds.log_file(sample)
        self.MAEC11.log_file(sample)
        self.MongoDB.log_file(copy.deepcopy(sample))
        self.JSONLog.log_file(sample)
        self.VirusTotal.analyze(data, sample['md5'], self.baseDir)

        if sample['type'] in ('JAR', ):
            self.HoneyAgent.analyze(data, sample['md5'], self.baseDir, params)

        log.SampleClassifier.classify(data, sample['md5'])
        return sample

    def log_event(self):
        log.warning("Saving log analysis at %s" % (self.baseDir, ))

        maec11logdir = os.path.join(self.baseDir, "analysis", "maec11")
        try:
            os.makedirs(maec11logdir)
        except:
            pass

        jsonlogdir = os.path.join(self.baseDir, "analysis", "json")
        try:
            os.makedirs(jsonlogdir)
        except:
            pass

        with open(os.path.join(maec11logdir, 'analysis.xml'), 'a+r') as fd:
            self.MAEC11.export(outfile = fd)
            fd.seek(0)
            data = fd.read()
            self.HPFeeds.log_event(data)
            self.MongoDB.log_event(data)
            self.JSONLog.export(jsonlogdir)

    def log_connection(self, source, destination, method, flags = {}):
        """
        Log the connection (redirection, link) between two pages

        @source         The origin page
        @destination    The page the user is made to load next
        @method         Link, iframe, .... that moves the user from source to destination
        @flags          Additional information flags. Existing are: "exploit"
        """

        self.JSONLog.log_connection(source, destination, method, flags)

    def log_location(self, url, ctype, md5, sha256, flags = {}, fsize = 0, mtype = ""):
        """
        Log file information for a given url

        @url            Url we fetched this file from
        @ctype          Content type (whatever the server says it is)
        @md5            MD5 hash
        @sha256         SHA256 hash
        @fsize          File size
        @mtype          Calculated mime type
        """
        self.JSONLog.log_location(url, ctype, md5, sha256, flags = flags, fsize = fsize, mtype = mtype)

    def log_exploit_event(self, url, module, description, cve = None, data = None, forward = True):
        """
        Log file information for a given url

        @url            Url where this exploit occured
        @module         Module/ActiveX Control, ... that gets exploited
        @description    Description of the exploit
        @cve            CVE number (if available)
        @forward        Forward log to add_behavior_warn
        """
        if forward:
            self.add_behavior_warn("[%s] %s" % (module, description, ), cve = cve)

        self.JSONLog.log_exploit_event(url, module, description, cve = cve, data = data)

    def log_warning(self, data):
        log.warning(data)
        self.HPFeeds.log_warning(data)

    def log_redirect(self, response):
        if not response:
            return None

        if response.previous is None:
            return None

        redirects = list()
        r         = response
        final     = response['content-location'] if 'content-location' in response else None

        while r.previous:
            if final is None and 'location' in r.previous:
                final = r.previous['location']

            redirects.append(r.previous)
            r = r.previous

        while len(redirects):
            p = redirects.pop()
            log.URLClassifier.classify(p['content-location'])
            self.add_behavior_warn("[HTTP Redirection (Status: %s)] Content-Location: %s --> Location: %s" % (p['status'],
                                                                                                              p['content-location'],
                                                                                                              p['location'], ))
            self.log_connection(p['content-location'], p['location'], "http-redirect")
            last = p['location']

        return final

    def log_href_redirect(self, referer, url):
        self.add_behavior_warn("[HREF Redirection (document.location)] Content-Location: %s --> Location: %s" % (referer, url, ))
        self.log_connection(referer, url, "href")

    def set_basedir(self, url):
        if self.baseDir:
            return

        t = datetime.datetime.now()
        m = hashlib.md5()
        m.update(url)

        base = os.getenv('THUG_LOGBASE', '..')
        self.baseDir = os.path.join(base, 'logs', m.hexdigest(), t.strftime("%Y%m%d%H%M%S"))

        try:
            os.makedirs(self.baseDir)
        except OSError as e:
            if e.errno == errno.EEXIST:
                pass
            else:
                raise

        with open(os.path.join(base, 'logs', 'thug.csv'), 'a+r') as fd:
            csv_line = '%s,%s\n' % (m.hexdigest(), url, )
            for l in fd.readlines():
                if l == csv_line:
                    return

            fd.write(csv_line)

    def set_absbasedir(self, basedir):
        self.baseDir = basedir

        try:
            os.makedirs(self.baseDir)
        except OSError as e:
            if e.errno == errno.EEXIST:
                pass
            else:
                raise
