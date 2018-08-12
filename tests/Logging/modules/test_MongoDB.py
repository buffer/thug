import os
import logging
import pymongo
from mock import patch

import mongomock
from gridfs import Database

import thug
from thug.ThugAPI.ThugOpts import ThugOpts
from thug.Logging.modules.MongoDB import MongoDB
from thug.ThugAPI.ThugVulnModules import ThugVulnModules
from thug.Logging.ThugLogging import ThugLogging
from thug.Encoding.Encoding import Encoding

configuration_path = thug.__configuration_path__

log = logging.getLogger("Thug")

log.personalities_path = os.path.join(configuration_path, "personalities") if configuration_path else None
log.ThugOpts           = ThugOpts()
log.configuration_path = configuration_path
log.ThugLogging        = ThugLogging(thug.__version__)
log.ThugVulnModules    = ThugVulnModules()
log.Encoding           = Encoding()


class TestMongoDB:
    with patch(pymongo.__name__ + '.MongoClient', new=mongomock.MongoClient), \
         patch('gridfs.Database', new=mongomock.database.Database):
        log.ThugOpts.mongodb_address = "xyz"
        mongo = MongoDB(thug.__version__)
        log.ThugOpts.mongodb_address = None

    def test_init(self):
        self.mongo = MongoDB(thug.__version__)

    def test_set_url(self):
        self.mongo.set_url("www.example.com")
        self.mongo.set_url("www.example.com")
