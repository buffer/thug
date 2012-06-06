#!/usr/bin/env python
#
# Logging.py
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
import base64
import hashlib
import zipfile
import pefile

try:
    import cStringIO as StringIO
except ImportError:
    import StringIO

log = logging.getLogger("Thug")

class BaseLogging(object):
    def __init__(self):
        self.types = ('PE', 
                      'PDF',
                      'JAR',
                      'SWF', )

    def is_pe(self, data):
        try:
            pe = pefile.PE(data = data, fast_load = True)
        except:
            return False

        return True

    def is_pdf(self, data):
        return data.startswith('%PDF')

    def is_jar(self, data):
        try:
            z = zipfile.ZipFile(StringIO.StringIO(data))
            if [t for t in z.namelist() if t.endswith('.class')]:
                return True
        except:
            pass

        return False

    def is_swf(self, data):
        return data.startswith('CWS') or data.startswith('FWS')

    def get_sample_type(self, data):
        for t in self.types:
            p = getattr(self, 'is_%s' % (t.lower(), ), None)
            if p and p(data):
                return t 

        return None

    def build_sample(self, data, url = None):
        if not data:
            return None

        p = dict()
        p['type'] = self.get_sample_type(data)
        if p['type'] is None:
            return None

        p['md5']  = hashlib.md5(data).hexdigest()
        p['sha1'] = hashlib.sha1(data).hexdigest()
        
        if url:
            p['url'] = url
            p['data'] = base64.b64encode(data)

        return p
