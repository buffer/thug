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

import os
import logging
import ConfigParser

log = logging.getLogger("Thug")

class MongoDB(object):
    def __init__(self):
        self.urls    = None
        self.events  = None
        self.samples = None
        self.url_id  = None
        self.opts    = dict()

        config    = ConfigParser.ConfigParser()
        conf_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logging.conf")
        config.read(conf_file)
        
        for option in config.options('MongoDB'):
            self.opts[option] = config.get('MongoDB', option)

        if self.opts['enable'].lower() in ('false', ):
            return

        try:
            import pymongo
            import gridfs
            connection = pymongo.Connection(self.opts['host'], int(self.opts['port']))
        except:
            log.info('[MongoDB] MongoDB instance not available')
            return
        
        db           = connection.thug
        self.urls    = db.urls
        self.events  = db.events
        self.samples = db.samples

        dbfs    = connection.thugfs
        self.fs = gridfs.GridFS(dbfs)

    def set_url(self, url):
        if not self.urls:
            return

        self.url_id = self.urls.insert({'url': url})

    def log_file(self, data):
        if not self.samples:
            return

        with self.fs.new_file() as fp:
            fp.write(data['data'])

        _data              = dict()
        _data['url_id']    = self.url_id
        _data['sample_id'] = fp._id
        _data['type']      = data['type']
        _data['md5']       = data['md5']
        _data['sha1']      = data['sha1']
        self.samples.insert(_data)

    def log_event(self, data):
        if not self.events:
            return

        with self.fs.new_file() as fp:
            fp.write(data)

        _data             = dict()
        _data['url_id']   = self.url_id
        _data['event_id'] = fp._id
        self.events.insert(_data)
