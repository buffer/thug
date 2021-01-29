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
import six
import base64
import logging
import datetime
import six.moves.configparser as ConfigParser

import pymongo
import gridfs
from pymongo.errors import DuplicateKeyError

import thug

from .ExploitGraph import ExploitGraph

log = logging.getLogger("Thug")


class MongoDB(object):
    def __init__(self):
        self.enabled = True

        if not self.__init_config():
            return

        self.__init_db()
        self.chain_id = self.make_counter(0)

    def __init_config(self):
        self.opts = dict()

        if log.ThugOpts.mongodb_address:
            self.opts['host'] = log.ThugOpts.mongodb_address
            self.opts['enable'] = True
            return True

        conf_file = os.path.join(log.configuration_path, 'thug.conf')
        if not os.path.exists(conf_file): # pragma: no cover
            self.enabled = False
            return False

        config = ConfigParser.ConfigParser()
        config.read(conf_file)

        self.opts['enable'] = config.getboolean('mongodb', 'enable')

        if self.opts['enable']: # pragma: no cover
            self.opts['host'] = config.get('mongodb', 'host')
            return True

        self.enabled = False
        return False

    def __init_db(self):
        client = getattr(pymongo, 'MongoClient', None)

        try:
            connection = client(self.opts['host'])
        except Exception:
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
        self.exploits     = db.exploits
        self.classifiers  = db.classifiers
        self.images       = db.images
        self.screenshots  = db.screenshots
        self.awis         = db.awis
        self.codes        = db.codes
        self.cookies      = db.cookies
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
        return entry['_id'] if entry else None

    def get_url(self, url):
        try:
            entry = self.urls.insert_one({'url' : url}).inserted_id
        except DuplicateKeyError:
            entry = self.__get_url(url)

        return entry

    def set_url(self, url):
        if not self.enabled:
            return

        self.graph = ExploitGraph(url)

        self.url_id = self.get_url(url)
        if self.url_id is None: # pragma: no cover
            log.warning('[MongoDB] MongoDB internal error')
            self.enabled = False
            return

        analysis = {
            "url_id"      : self.url_id,
            "timestamp"   : str(datetime.datetime.now()),
            "thug"        : {
                                "version"            : thug.__version__,
                                "jsengine" : {
                                    "engine"         : thug.__jsengine__,
                                    "version"        : thug.__jsengine_version__
                                },
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
                            }
        }

        self.analysis_id = self.analyses.insert_one(analysis).inserted_id
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
        content_id = self.fs.put(content,
                                 mtype = data.get("mtype", None)
                                 ) if content else None

        location = {
            'analysis_id' : self.analysis_id,
            'url_id'      : self.get_url(url),
            'status'      : data.get("status", None),
            "content_id"  : content_id,
            'content-type': data.get("ctype", None),
            'md5'         : data.get("md5", None),
            'sha256'      : data.get("sha256", None),
            'ssdeep'      : data.get("ssdeep", None),
            'flags'       : flags,
            'size'        : data.get("fsize", None),
            'mime-type'   : data.get("mtype", None)
        }

        self.locations.insert_one(location)

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

        self.connections.insert_one(connection)
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

        self.exploits.insert_one(exploit)

    def log_classifier(self, classifier, url, rule, tags = "", meta = dict()):
        """
        Log classifiers matching for a given url

        @classifier     Classifier name
        @url            URL where the rule match occurred
        @rule           Rule name
        @meta           Rule meta
        @tags           Rule tags
        """
        if not self.enabled:
            return

        classification = {
            'analysis_id' : self.analysis_id,
            'url_id'      : self.get_url(url),
            'classifier'  : classifier,
            'rule'        : rule,
            'meta'        : meta,
            'tags'        : tags
        }

        self.classifiers.insert_one(classification)

    def log_image_ocr(self, url, result):
        """
        Log the results of images OCR-based analysis

        @url            Image URL
        @result         OCR analysis result
        """
        if not self.enabled:
            return

        image = {
            'analysis_id' : self.analysis_id,
            'classifier'  : 'OCR',
            'url_id'      : self.get_url(url),
            'result'      : result
        }

        self.images.insert_one(image)

    def log_screenshot(self, url, screenshot):
        """
        Log the base64-encoded screenshot of the analyzed page

        @url        URL
        @screenshot URL screenshot
        """
        if not self.enabled:
            return

        content = base64.b64encode(screenshot)

        item = {
            'analysis_id' : self.analysis_id,
            'url'         : self.get_url(url),
            'screenshot'  : content.decode()
        }

        self.screenshots.insert_one(item)

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
            item = {
                'analysis_id' : self.analysis_id,
            }

            for attr in attrs:
                value = getattr(cookie, attr, None)
                if value is None:
                    continue

                item[attr] = value

            self.cookies.insert_one(item)

    def get_url_from_location(self, md5):
        result = self.locations.find_one({'analysis_id' : self.analysis_id,
                                          'md5'         : md5})
        if not result: # pragma: no cover
            return None

        return result['url_id']

    def log_file(self, data, url = None, params = None):
        if not self.enabled:
            return

        r = dict(data)

        result = self.samples.find_one({'analysis_id' : self.analysis_id,
                                        'type'        : data['type'],
                                        'md5'         : data['md5'],
                                        'sha1'        : data['sha1']})

        if result:
            return

        r['sample_id'] = self.fs.put(data['data'])
        r.pop('data', None)

        if url: # pragma: no cover
            url_id = self.get_url(url)
            r.pop('url', None)
        else:
            url_id = self.get_url_from_location(data['md5'])

        r['analysis_id'] = self.analysis_id
        r['url_id']      = url_id

        self.samples.insert_one(r)

    def log_json(self, basedir):
        if not self.enabled:
            return

        if not log.ThugOpts.json_logging:
            return

        p = log.ThugLogging.modules.get('json', None)
        if p is None:
            return

        self._log_json(basedir, p) # pragma: no cover

    def _log_json(self, basedir, p): # pragma: no cover
        m = getattr(p, 'get_json_data', None)
        if m is None:
            return

        report = m(basedir)
        analysis = {
            'analysis_id'   : self.analysis_id,
            'report'        : report
        }

        self.json.insert_one(analysis)

    def log_event(self, basedir):
        if not self.enabled:
            return

        self.log_json(basedir)

        G = self.graph.draw()
        if G is None: # pragma: no cover
            return

        graph = {
            'analysis_id'   : self.analysis_id,
            'graph'         : G
        }

        self.graphs.insert_one(graph)

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

    def add_code_snippet(self, snippet, language, relationship, tag, method = "Dynamic Analysis"):
        if not self.enabled:
            return

        code = {
            'analysis_id'  : self.analysis_id,
            'snippet'      : self.fix(snippet, drop_spaces = False),
            'language'     : self.fix(language),
            'relationship' : self.fix(relationship),
            'tag'          : self.fix(tag),
            'method'       : self.fix(method)
        }

        self.codes.insert_one(code)

    def add_shellcode_snippet(self, snippet, language, relationship, tag, method = "Dynamic Analysis"):
        if not self.enabled:
            return

        code = {
            'analysis_id'  : self.analysis_id,
            'snippet'      : base64.b64encode(snippet),
            'language'     : self.fix(language),
            'relationship' : self.fix(relationship),
            'tag'          : self.fix(tag),
            'method'       : self.fix(method)
        }

        self.codes.insert_one(code)

    def add_behavior(self, description = None, cve = None, snippet = None, method = "Dynamic Analysis"):
        if not self.enabled: # pragma: no cover
            return

        if not cve and not description:
            return

        behavior = {
            'analysis_id' : self.analysis_id,
            'description' : self.fix(description),
            'cve'         : self.fix(cve),
            'snippet'     : self.fix(snippet, drop_spaces = False),
            'method'      : self.fix(method),
            'timestamp'   : str(datetime.datetime.now())
        }

        self.behaviors.insert_one(behavior)

    def add_behavior_warn(self, description = None, cve = None, snippet = None, method = "Dynamic Analysis"):
        if not self.enabled:
            return

        self.add_behavior(description, cve, snippet, method)

    def log_certificate(self, url, certificate):
        if not self.enabled:
            return

        certificate = {
            'analysis_id' : self.analysis_id,
            'url_id'      : self.get_url(url),
            'certificate' : certificate
        }

        self.certificates.insert_one(certificate)

    def log_awis(self, report): # pragma: no cover
        if not self.enabled:
            return

        awis = {
            'analysis_id' : self.analysis_id,
            'report'      : report
        }

        self.awis.insert_one(awis)

    def log_analysis_module(self, collection, sample, report):
        if not self.enabled:
            return

        s = self.samples.find_one({'analysis_id' : self.analysis_id,
                                   'md5'         : sample['md5'],
                                   'sha1'        : sample['sha1']})
        if not s: # pragma: no cover
            return

        r = {
            'analysis_id' : self.analysis_id,
            'sample_id'   : s['_id'],
            'report'      : report
        }

        collection.insert_one(r)

    def log_virustotal(self, sample, report):
        self.log_analysis_module(self.virustotal, sample, report)

    def log_honeyagent(self, sample, report):
        self.log_analysis_module(self.honeyagent, sample, report)
