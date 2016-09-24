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
from .compatibility import thug_unicode

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

        if log.ThugOpts.mongodb_address:
            try:
                self.opts['host'] = log.ThugOpts.mongodb_address
                self.opts['enable'] = 'True'
                return True
            except: #pylint:disable=bare-except
                log.warning("Invalid MongoDB address specified at runtime, using default values instead (if any)")

        config = ConfigParser.ConfigParser()

        conf_file = os.path.join(log.configuration_path, 'logging.conf')

        if not os.path.exists(conf_file):
            conf_file = os.path.join(log.configuration_path, 'logging.conf.default')

        if not os.path.exists(conf_file):
            self.enabled = False
            return False

        config.read(conf_file)

        for option in config.options('mongodb'):
            self.opts[option] = config.get('mongodb', option)

        if self.opts['enable'].lower() in ('false', ):
            self.enabled = False

        return self.enabled

    def __init_db(self):
        # MongoDB Connection class is marked as deprecated (MongoDB >= 2.4).
        # The following code tries to use the new MongoClient if available and
        # reverts to the old Connection class if not. This code will hopefully
        # disappear in the next future.
        client = getattr(pymongo, 'MongoClient', None)
        if client is None:
            client = getattr(pymongo, 'Connection', None)

        try:
            connection = client(self.opts['host'])
        except: #pylint:disable=bare-except
            log.warning('[MongoDB] MongoDB instance not available')
            self.enabled = False
            return

        db                = connection.thug
        self.urls         = db.urls
        self.analyses     = db.analyses
        self.locations    = db.locations
        self.connections  = db.connections
        self.graphs       = db.graphs
        self.samples      = db.samples
        self.behaviors    = db.behaviors
        self.certificates = db.certificates
        self.virustotal   = db.virustotal
        self.honeyagent   = db.honeyagent
        self.androguard   = db.androguard
        self.peepdf       = db.peepdf
        self.exploits     = db.exploits
        self.codes        = db.codes
        self.maec11       = db.maec11
        self.json         = db.json
        dbfs              = connection.thugfs
        self.fs           = gridfs.GridFS(dbfs)

        self.__build_indexes()

    def __build_indexes(self):
        self.urls.ensure_index('url', unique = True)

    def make_counter(self, p):
        _id = p
        while True:
            yield _id
            _id += 1

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
            entry = self.urls.insert({'url' : url})
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
            "url_id"      : self.url_id,
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
        log.warning('[MongoDB] Analysis ID: %s', str(self.analysis_id))

    def get_vuln_module(self, module):
        disabled = getattr(log.ThugVulnModules, "%s_disabled" % (module, ), True)
        if disabled:
            return "disabled"

        return getattr(log.ThugVulnModules, module)

    def log_location(self, url, data, flags = None):
        if not self.enabled:
            return

        if flags is None:
            flags = dict()

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

    def log_connection(self, source, destination, method, flags = None):
        if not self.enabled:
            return

        if flags is None:
            flags = dict()

        connection = {
            'analysis_id'    : self.analysis_id,
            'chain_id'       : next(self.chain_id),
            'source_id'      : self.get_url(source),
            'destination_id' : self.get_url(destination),
            'method'         : method,
            'flags'          : flags
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
        if not self.enabled:
            return

        exploit = {
            'analysis_id' : self.analysis_id,
            'url_id'      : self.get_url(url),
            'module'      : module,
            'description' : description,
            'cve'         : cve,
            'data'        : data
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

    def log_maec11(self, basedir):
        if not self.enabled:
            return

        if not log.ThugOpts.maec11_logging:
            return

        p = log.ThugLogging.modules.get('maec11', None)
        if p is None:
            return

        m = getattr(p, 'get_maec11_data', None)
        if m is None:
            return

        report = m(basedir)
        analysis = {
            'analysis_id'   : self.analysis_id,
            'report'        : report
        }

        self.maec11.insert(analysis)

    def log_json(self, basedir):
        if not self.enabled:
            return

        if not log.ThugOpts.json_logging:
            return

        p = log.ThugLogging.modules.get('json', None)
        if p is None:
            return

        m = getattr(p, 'get_json_data', None)
        if m is None:
            return

        report = m(basedir)
        analysis = {
            'analysis_id'   : self.analysis_id,
            'report'        : report
        }

        self.json.insert(analysis)

    def log_event(self, basedir):
        if not self.enabled:
            return

        self.log_maec11(basedir)
        self.log_json(basedir)

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
            enc = log.Encoding.detect(data)
            return data.decode(enc['encoding']).replace("\n", "").strip()
        except: #pylint:disable=bare-except
            return thug_unicode(data).replace("\n", "").strip()

    def add_code_snippet(self, snippet, language, relationship, method = "Dynamic Analysis"):
        if not self.enabled:
            return

        code = {
            'analysis_id'  : self.analysis_id,
            'snippet'      : self.fix(snippet),
            'language'     : self.fix(language),
            'relationship' : self.fix(relationship),
            'method'       : self.fix(method)
        }

        self.codes.insert(code)

    def add_behavior(self, description = None, cve = None, method = "Dynamic Analysis"):
        if not self.enabled:
            return

        if not cve and not description:
            return

        behavior = {
            'analysis_id' : self.analysis_id,
            'description' : self.fix(description),
            'cve'         : self.fix(cve),
            'method'      : self.fix(method),
            'timestamp'   : str(datetime.datetime.now())
        }

        self.behaviors.insert(behavior)

    def add_behavior_warn(self, description = None, cve = None, method = "Dynamic Analysis"):
        if not self.enabled:
            return

        self.add_behavior(description, cve, method)

    def log_certificate(self, url, certificate):
        if not self.enabled:
            return

        certificate = {
            'analysis_id' : self.analysis_id,
            'url_id'      : self.get_url(url),
            'certificate' : certificate
        }

        self.certificates.insert(certificate)

    def log_analysis_module(self, collection, sample, report):
        if not self.enabled:
            return

        s = self.samples.find_one({'analysis_id' : self.analysis_id,
                                   'md5'         : sample['md5'],
                                   'sha1'        : sample['sha1']})
        if not s:
            return

        r = {
            'analysis_id' : self.analysis_id,
            'sample_id'   : s['_id'],
            'report'      : report
        }

        collection.insert(r)

    def log_virustotal(self, sample, report):
        self.log_analysis_module(self.virustotal, sample, report)

    def log_honeyagent(self, sample, report):
        self.log_analysis_module(self.honeyagent, sample, report)

    def log_androguard(self, sample, report):
        self.log_analysis_module(self.androguard, sample, report)

    def log_peepdf(self, sample, report):
        self.log_analysis_module(self.peepdf, sample, report)
