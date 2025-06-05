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
import configparser

try:
    import elasticsearch

    ELASTICSEARCH_MODULE = True
except ImportError:  # pragma: no cover
    ELASTICSEARCH_MODULE = False


from .JSON import JSON

log = logging.getLogger("Thug")


class ElasticSearch(JSON):
    def __init__(self):
        JSON.__init__(self, provider=True)

        self.enabled = False

        if not ELASTICSEARCH_MODULE:  # pragma: no cover
            return

        if not log.ThugOpts.elasticsearch_logging:
            return

        self.enabled = self.__init_elasticsearch()

    def __init_config(self):
        self.opts = {}

        conf_file = os.path.join(log.configuration_path, "thug.conf")
        if not os.path.exists(conf_file):
            return False

        config = configparser.ConfigParser()
        config.read(conf_file)

        self.opts["enable"] = config.getboolean("elasticsearch", "enable")
        if not self.opts["enable"]:
            return False

        self.opts["url"] = config.get("elasticsearch", "url")
        self.opts["index"] = config.get("elasticsearch", "index")

        return True

    def __init_elasticsearch(self):
        if not self.__init_config():
            return False

        self.es = elasticsearch.Elasticsearch(self.opts["url"])

        if self.es.ping():  # pragma: no cover
            self.es.options(ignore_status=404).indices.create(index=self.opts["index"])
            return True

        log.warning("[WARNING] ElasticSearch instance not properly initialized")
        return False

    def export(self, basedir):  # pylint:disable=unused-argument
        if self.enabled:  # pragma: no cover
            res = self.es.index(index=self.opts["index"], document=self.data)
            return res["_id"]

        return None
