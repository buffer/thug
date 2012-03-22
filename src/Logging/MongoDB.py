#!/usr/bin/env python
#
# MongoDB.py
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
import pefile
import zipfile
import ConfigParser

try:
    import cStringIO as StringIO
except ImportError:
    import StringIO

log = logging.getLogger("Thug")

class MongoDB(object):
    def __init__(self):
        self.urls    = None
        self.events  = None
        self.samples = None
        self.url_id  = None
        self.opts    = dict()

        config    = ConfigParser.ConfigParser()
        conf_file = "%s/Logging/logging.conf" % (os.getcwd(), )
        config.read(conf_file)
        
        for option in config.options('MongoDB'):
            self.opts[option] = config.get('MongoDB', option)

        if self.opts['enable'].lower() in ('false', ):
            return

        try:
            import pymongo
            connection = pymongo.Connection(self.opts['host'], int(self.opts['port']))
        except:
            log.warning('[MongoDB] MongoDB instance not available')
            return
        
        db           = connection.thug
        self.urls    = db.urls
        self.events  = db.events
        self.samples = db.samples

    def set_url(self, url):
        if not self.urls:
            return

        self.url_id = self.urls.insert({'url': url})

    def log_file(self, data):
        if not self.samples:
            return

        data['url_id'] = self.url_id
        self.samples.insert(data)

    def log_event(self, data):
        if not self.events:
            return

        _data           = dict()
        _data['MAEC']   = data
        _data['url_id'] = self.url_id
        self.events.insert(_data)


        
