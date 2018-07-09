import os
import shutil
import logging

import pytest
import six.moves.configparser as ConfigParser

import thug
from thug.Logging.BaseLogging import BaseLogging
from thug.ThugAPI.ThugOpts import ThugOpts

configuration_path = thug.__configuration_path__
config             = ConfigParser.ConfigParser()
conf_file          = os.path.join(configuration_path, 'logging.conf.default')
config.read(conf_file)

log                    = logging.getLogger("Thug")
log.personalities_path = os.path.join(configuration_path, "personalities") if configuration_path else None
log.ThugOpts           = ThugOpts()

base_logging = BaseLogging()


class TestBaseLogging:
    def test_set_basedir(self):
        url = "/path/to/example"
        base_logging.set_basedir(url)
        assert not os.path.isdir(base_logging.baseDir)

        base_logging.baseDir      = ""
        log.ThugOpts.file_logging = True
        base_logging.set_basedir(url)
        log_path = os.path.dirname(os.path.dirname(base_logging.baseDir))  # TODO: Make this neat
        assert os.path.isdir(base_logging.baseDir)

        # Testing the self.baseDir variable
        base_logging.set_basedir(url)

        # Testing the thug_csv
        base_logging.baseDir = ""
        base_logging.set_basedir(url)
        assert os.path.isdir(base_logging.baseDir)

        base_logging.set_basedir("/path/to/example1")
        shutil.rmtree(log_path)
        assert not os.path.isdir(base_logging.baseDir)

    def test_set_absbasedir(self):
        url = "../example"
        base_logging.set_absbasedir(url)
        assert os.path.isdir(url)

        with pytest.raises(OSError):
            base_logging.set_absbasedir("/etc/perm-den")

        # Testing the try-except clause
        base_logging.set_absbasedir(url)
        shutil.rmtree(url)

        log.ThugOpts.file_logging = False
        base_logging.set_absbasedir(url)
        assert not os.path.isdir(url)

    def test_json_module(self):
        log.ThugOpts.json_logging = True
        assert base_logging.check_module('json', config)

        log.ThugOpts.json_logging = False
        assert not base_logging.check_module('json', config)

    def test_maec11_module(self):
        log.ThugOpts.maec11_logging = True
        assert base_logging.check_module('maec11', config)

        log.ThugOpts.maec11_logging = False
        assert not base_logging.check_module('maec11', config)

    def test_mongodb_module(self):
        assert not base_logging.check_module('mongodb', config)

    def test_elasticsearch_module(self):
        assert not base_logging.check_module('elasticsearch', config)
