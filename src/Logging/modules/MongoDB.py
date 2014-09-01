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
import datetime
import logging

try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser

MONGO_MODULE = True

try:
    import pymongo
    import gridfs
    from pymongo.errors import DuplicateKeyError
except ImportError:
    MONGO_MODULE = False

log = logging.getLogger("Thug")


class MongoDB(object):
    formats = ('maec11', )

    def __init__(self, thug_version):
        self.thug_version = thug_version
        self.enabled      = True

        if not self.__check_mongo_module():
            return

        if not self.__init_config():
            return

        self.__init_db()
        self.chain_id = self.make_counter(0)

    def __check_mongo_module(self):
        if not MONGO_MODULE:
            log.info('[MongoDB] MongoDB instance not available')
            self.enabled = False

        return self.enabled

    def __init_config(self):
        self.opts = dict()

        config    = ConfigParser.ConfigParser()
        conf_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "logging.conf")
        config.read(conf_file)

        for option in config.options('mongodb'):
            self.opts[option] = config.get('mongodb', option)

        if self.opts['enable'].lower() in ('false', ):
            self.enabled = False

        return self.enabled

    def __init_db(self):
        try:
            connection = pymongo.Connection(self.opts['host'], int(self.opts['port']))
        except:
            log.info('[MongoDB] MongoDB instance not available')
            self.enabled = False
            return
        
        db               = connection.thug
        self.urls        = db.urls
        self.analyses    = db.analyses
        self.locations   = db.locations
        self.connections = db.connections
        self.events      = db.events
        self.samples     = db.samples
        dbfs             = connection.thugfs
        self.fs          = gridfs.GridFS(dbfs)

        self.__build_indexes()

    def __build_indexes(self):
        self.urls.ensure_index('url', unique = True)

    def make_counter(self, p):
        id = p
        while True:
            yield id
            id += 1

    def __get_url(self, url):
        entry = self.urls.find_one({'url': url})
        if entry:
            return entry['_id']

        return None

    def get_url(self, url):
        entry = self.__get_url(url)
        if entry:
            return entry

        try:
            entry = self.urls.insert({'url' : url}, safe = True)
        except DuplicateKeyError:
            entry = self.__get_url(url)

        return entry

    def set_url(self, url):
        if not self.enabled:
            return

        self.url_id = self.get_url(url)
        if self.url_id is None:
            log.warning('[MongoDB] MongoDB internal error')
            self.enabled = False
            return

        analysis = {
            "url"         : self.url_id,
            "timestamp"   : str(datetime.datetime.now()),
            "thug"        : {
                                "version"            : self.thug_version,
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
                            }
        }

        self.analysis_id = self.analyses.insert(analysis)

    def get_vuln_module(self, module):
        disabled = getattr(log.ThugVulnModules, "%s_disabled" % (module, ), True)
        if disabled:
            return "disabled"

        return getattr(log.ThugVulnModules, module)

    def log_location(self, url, ctype, md5, sha256, flags = {}, fsize = 0, mtype = ''):
        location = {
            'analysis_id'   : self.analysis_id,
            'url_id'        : self.get_url(url),
            'content-type'  : ctype,
            'md5'           : md5,
            'sha256'        : sha256,
            'flags'         : flags,
            'size'          : fsize,
            'mime-type'     : mtype
        }

        self.locations.insert(location)

    def log_connection(self, source, destination, method, flags = {}):
        connection = {
            'analysis_id'   : self.analysis_id,
            'chain_id'      : next(self.chain_id),
            'source'        : self.get_url(source),
            'destination'   : self.get_url(destination),
            'method'        : method,
            'flags'         : flags
        }

        self.connections.insert(connection)

    def get_url_from_location(self, md5):
        result = self.locations.find_one({'analysis_id' : self.analysis_id,
                                          'md5'         : md5})
        if not result:
            return None

        return result['url_id']

    def log_file(self, data, url = None, params = None):
        if not self.enabled:
            return

        r = dict(data)

        r['sample_id'] = self.fs.put(data['data'])
        r.pop('data', None)

        if url:
            url_id = self.get_url(url)
            r.pop('url', None)
        else:
            url_id = self.get_url_from_location(data['md5'])

        r['analysis_id'] = self.analysis_id
        r['url_id']      = url_id

        print r
        self.samples.insert(r)

    def __log_event(self, data):
        with self.fs.new_file() as fp:
            fp.write(data)

        _data                = dict()
        _data['analysis_id'] = self.analysis_id
        _data['event_id']    = fp._id
        self.events.insert(_data)

    def log_event(self, basedir):
        if not self.enabled:
            return

        m = None

        for module in self.formats:
            if module in log.ThugLogging.modules:
                p = log.ThugLogging.modules[module]
                m = getattr(p, 'get_data', None)
                if m:
                    break

        if m is None:
            return

        data = m(basedir)
        self.__log_event(data)
