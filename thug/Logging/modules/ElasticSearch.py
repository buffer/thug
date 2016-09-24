#!/usr/bin/env python
#
# ElasticSearch.py
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

import os
import logging

try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser

from .JSON import JSON

log = logging.getLogger("Thug")

try:
    from elasticsearch import Elasticsearch, RequestsHttpConnection
    ELASTICSEARCH_MODULE = True
except ImportError:
    ELASTICSEARCH_MODULE = False


class ElasticSearch(JSON):
    def __init__(self, thug_version):
        JSON.__init__(self, thug_version, provider = True)

        self.enabled = True

        if not ELASTICSEARCH_MODULE:
            self.enabled = False
            return

        if not log.ThugOpts.elasticsearch_logging:
            self.enabled = False
            return

        if not self.__init_elasticsearch():
            self.enabled = False
            return 

    def __init_config(self):
        self.opts = dict()

        config = ConfigParser.ConfigParser()

        conf_file = os.path.join(log.configuration_path, 'logging.conf')

        if not os.path.exists(conf_file):
            conf_file = os.path.join(log.configuration_path, 'logging.conf.default')

        if not os.path.exists(conf_file):
            return False

        config.read(conf_file)

        for option in config.options('elasticsearch'):
            self.opts[option] = config.get('elasticsearch', option)

        if self.opts['enable'].lower() in ('false', ):
            return False

        return True

    def __init_elasticsearch(self):
        if not self.__init_config():
            return False

        self.es = Elasticsearch(self.opts['url'], connection_class = RequestsHttpConnection)

        if not self.es.ping():
            log.warning("[WARNING] ElasticSearch instance not properly initialized")
            return False

        self.es.indices.create(index = self.opts['index'], ignore = 400)
        return True

    def export(self, basedir):
        if not self.enabled:
            return

        res = self.es.index(index = self.opts['index'], doc_type = "analysis", body = self.data)
        return res['created']
