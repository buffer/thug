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

from BaseLogging import BaseLogging
from HPFeeds import HPFeeds
from MAEC import MAEC
from MongoDB import MongoDB

import os
import errno
import hashlib
import datetime
import logging
log = logging.getLogger("Thug")

class ThugLogging(BaseLogging):
    def __init__(self, thug_version):
        BaseLogging.__init__(self)

        self.HPFeeds        = HPFeeds()
        self.MAEC           = MAEC(thug_version)
        self.MongoDB        = MongoDB()
        self.baseDir        = None
        self.shellcodes     = set()
        self.shellcode_urls = set()

    def set_url(self, url):
        self.HPFeeds.set_url(url)
        self.MAEC.set_url(url)
        self.MongoDB.set_url(url)

    def add_behavior_warn(self, description = None, cve = None, method = "Dynamic Analysis"):
        self.MAEC.add_behavior_warn(description, cve, method)

    def add_code_snippet(self, snippet, language, relationship, method = "Dynamic Analysis"):
        self.MAEC.add_code_snippet(snippet, language, relationship, method)

    def log_file(self, data, url):
        sample = self.build_sample(data, url)
        if sample is None:
            return
        
        self.HPFeeds.log_file(sample)
        self.MAEC.log_file(sample)
        self.MongoDB.log_file(sample)

    def log_event(self):
        log.warning("Saving log analysis at %s" % (self.baseDir, ))

        with open(os.path.join(self.baseDir, 'analysis.xml'), 'a+r') as fd:
            self.MAEC.export(outfile = fd)
            fd.seek(0)
            data = fd.read()
            self.HPFeeds.log_event(data)
            self.MongoDB.log_event(data)

    def log_warning(self, data):
        log.warning(data)
        self.HPFeeds.log_warning(data)

    def log_redirect(self, response):
        if not response:
            return

        redirects = list()
        r         = response

        while r.previous:
            redirects.append(r.previous)
            r = r.previous

        while len(redirects):
            p = redirects.pop()
            self.add_behavior_warn("[HTTP Redirection (Status: %s)] Content-Location: %s --> Location: %s" % (p['status'], 
                                                                                                            p['content-location'], 
                                                                                                            p['location'], ))

    def log_href_redirect(self, referer, url):
        self.add_behavior_warn("[HREF Redirection (document.location)] Content-Location: %s --> Location: %s" % (referer, url, ))


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
