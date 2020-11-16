import os
import logging
from mock import patch
import six.moves.configparser as ConfigParser

from elasticmock import elasticmock

import thug
from thug.Logging.modules.ElasticSearch import ElasticSearch
from thug.ThugAPI.ThugVulnModules import ThugVulnModules
from thug.ThugAPI.ThugOpts import ThugOpts

log = logging.getLogger("Thug")

cwd_path = os.path.dirname(os.path.realpath(__file__))
configuration_path = os.path.join(cwd_path, os.pardir, os.pardir, "test_files")

log.configuration_path = thug.__configuration_path__
log.personalities_path = os.path.join(configuration_path, "personalities") if configuration_path else None

log.ThugVulnModules = ThugVulnModules()
log.ThugOpts = ThugOpts()

log.ThugOpts.useragent = 'winxpie60'

config = ConfigParser.ConfigParser()
conf_file = os.path.join(log.configuration_path, 'thug.conf')
config.read(conf_file)


class TestElasticSearch:
    @elasticmock
    def test_export(self):
        log.ThugOpts.elasticsearch_logging = True
        log.configuration_path = configuration_path
        assert log.ThugOpts.elasticsearch_logging

        with patch('elasticmock.FakeElasticsearch.indices', create=True):
            elastic_search = ElasticSearch()

        response = elastic_search.export('sample-dir')
        enabled = elastic_search.enabled
        assert response
        assert enabled

        log.ThugOpts.elasticsearch_logging = False
        log.configuration_path = thug.__configuration_path__
        assert not log.ThugOpts.elasticsearch_logging

    def test_disable_opt(self):
        elastic_search = ElasticSearch()
        response = elastic_search.export('sample-dir')
        enabled = elastic_search.enabled

        assert not response
        assert not enabled

    @patch('six.moves.configparser.ConfigParser.getboolean', return_value = False)
    def test_disable_conf(self, mocked_parser):
        log.ThugOpts.elasticsearch_logging = True
        log.configuration_path = configuration_path
        assert log.ThugOpts.elasticsearch_logging

        elastic_search = ElasticSearch()
        enabled = elastic_search.enabled
        assert not enabled

        log.ThugOpts.elasticsearch_logging = False
        log.configuration_path = thug.__configuration_path__
        assert not log.ThugOpts.elasticsearch_logging

    @patch('elasticsearch.Elasticsearch')
    def test_ping_error(self, mocked_es, caplog):
        caplog.clear()
        ping_mock = mocked_es.return_value.ping
        ping_mock.return_value = False

        log.ThugOpts.elasticsearch_logging = True
        log.configuration_path = configuration_path

        elastic_search = ElasticSearch()
        enabled = elastic_search.enabled
        log.ThugOpts.elasticsearch_logging = False
        log.configuration_path = thug.__configuration_path__

        assert not enabled
        assert "[WARNING] ElasticSearch instance not properly initialized" in caplog.text
        assert not log.ThugOpts.elasticsearch_logging

    def test_no_conf_path(self):
        log.ThugOpts.elasticsearch_logging = True
        log.configuration_path = 'non/existing/path'
        assert log.ThugOpts.elasticsearch_logging

        elastic_search = ElasticSearch()
        enabled = elastic_search.enabled

        assert not enabled

        log.ThugOpts.elasticsearch_logging = False
        log.configuration_path = thug.__configuration_path__
        assert not log.ThugOpts.elasticsearch_logging
