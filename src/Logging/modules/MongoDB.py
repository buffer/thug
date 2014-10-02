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
import base64
import logging
from .compatibility import *

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

from .ExploitGraph import ExploitGraph

log = logging.getLogger("Thug")


class MongoDB(object):
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
        self.graphs      = db.graphs
        self.samples     = db.samples
        self.behavior    = db.behavior
        self.exploits    = db.exploits
        self.code        = db.code
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

        self.graph  = ExploitGraph(url)

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

    def log_location(self, url, data, flags = {}):
        if not self.enabled:
            return

        content    = data.get("content", None)
        content_id = self.fs.put(base64.b64encode(content)) if content else None

        location = {
            'analysis_id'   : self.analysis_id,
            'url_id'        : self.get_url(url),
            "content_id"    : content_id,
            'content-type'  : data.get("ctype", None),
            'md5'           : data.get("md5", None),
            'sha256'        : data.get("sha256", None),
            'flags'         : flags,
            'size'          : data.get("fsize", None),
            'mime-type'     : data.get("mtype", None)
        }

        self.locations.insert(location)

    def log_connection(self, source, destination, method, flags = {}):
        if not self.enabled:
            return

        connection = {
            'analysis_id'   : self.analysis_id,
            'chain_id'      : next(self.chain_id),
            'source'        : self.get_url(source),
            'destination'   : self.get_url(destination),
            'method'        : method,
            'flags'         : flags
        }

        self.connections.insert(connection)
        self.graph.add_connection(source, destination, method)


    def log_exploit_event(self, url, module, description, cve = None, data = None):
        """
        Log file information for a given url

        @url            URL where this exploit occured
        @module         Module/ActiveX Control, ... that gets exploited
        @description    Description of the exploit
        @cve            CVE number (if available)
        """
        exploit = { "url"         : self.fix(url),
                    "module"      : module,
                    "description" : description,
                    "cve"         : cve,
                    "data"        : data,
                    "analysis_id" : self.analysis_id
                  }
        self.exploits.insert(exploit)

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

        self.samples.insert(r)

    def log_event(self, basedir):
        if not self.enabled:
            return

        G = self.graph.draw()
        if G is None:
            return

        graph = {
            'analysis_id'   : self.analysis_id,
            'graph'         : G
        }

        self.graphs.insert(graph)


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


    def add_code_snippet(self, snippet, language, relationship, method = "Dynamic Analysis"):
        this_code = { "snippet"      : self.fix(snippet),
                      "language"     : self.fix(language),
                      "relationship" : self.fix(relationship),
                      "method"       : self.fix(method),
		      "analysis_id"  : self.analysis_id
                    }
        self.code.insert(this_code)


    def add_behavior(self, description = None, cve = None, method = "Dynamic Analysis"):
        if not cve and not description:
            return

        behave = { "description" : self.fix(description),
                   "cve"         : self.fix(cve),
                   "method"      : self.fix(method),
                   "timestamp"   : str(datetime.datetime.now()),
		   "analysis_id" : self.analysis_id
                 }
        self.behavior.insert(behave)


    def add_behavior_warn(self, description = None, cve = None, method = "Dynamic Analysis"):
        self.add_behavior(description, cve, method)


