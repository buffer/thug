# coding=utf-8
import os
import logging
import pymongo
from mock import patch

import mongomock

import thug
from thug.ThugAPI.ThugOpts import ThugOpts
from thug.Logging.modules.MongoDB import MongoDB
from thug.ThugAPI.ThugVulnModules import ThugVulnModules
from thug.Logging.ThugLogging import ThugLogging
from thug.Encoding.Encoding import Encoding
from thug.DOM.HTTPSession import HTTPSession

configuration_path = thug.__configuration_path__

log = logging.getLogger("Thug")

log.personalities_path = os.path.join(configuration_path, "personalities") if configuration_path else None
log.ThugOpts           = ThugOpts()
log.configuration_path = configuration_path
log.ThugLogging        = ThugLogging()
log.ThugVulnModules    = ThugVulnModules()
log.Encoding           = Encoding()
log.HTTPSession        = HTTPSession()
log.PyHooks            = dict()


class TestMongoDB:
    cve  = "CVE-XXXX"
    url  = "www.example.com"
    data = b"sample-data"
    desc = "sample-desc"
    cert = "sample-cert"

    file_data = {'sha1': 'b13d13733c4c9406fd0e01485bc4a34170b7d326',
                 'data': data,
                 'ssdeep': u'24:9EGtDqSyDVHNkCq4LOmvmuS+MfTAPxokCOB:97tG5DjQ4LDs+sTAPxLT',
                 'sha256': '459bf0aeda19633c8e757c05ee06b8121a51217cea69ce60819bb34092a296a0',
                 'type': 'JAR',
                 'md5': 'd4be8fbeb3a219ec8c6c26ffe4033a16'}

    base_dir       = "path/to/sample/basedir"
    code_snippet   = b"var i = 12;"
    base64_snippet = "dmFyIGkgPSAxMjs="
    language       = "Javascript"
    relationship   = "Contained_Inside"
    tag            = "Tag"  # TODO: Better tag
    method         = "Dynamic Analysis"

    source = "www.ex1.com"
    dest   = "www.ex2.com"
    con_method = "iframe"

    # Creating a MongoDB object for all the test methods.
    with patch(pymongo.__name__ + '.MongoClient', new=mongomock.MongoClient), \
            patch('gridfs.Database', new=mongomock.database.Database):
        log.ThugOpts.mongodb_address = "mongodb://localhost:123"
        mongo = MongoDB()
        log.ThugOpts.mongodb_address = None

    @patch(pymongo.__name__ + '.MongoClient', new=mongomock.MongoClient)
    @patch('gridfs.Database', new=mongomock.database.Database)
    def test_address(self):
        log.ThugOpts.mongodb_address = "syntax-error://localhost:123"
        mongo = MongoDB()
        log.ThugOpts.mongodb_address = None

        assert not mongo.enabled

    def test_init(self):
        """
            Testing for conf file 'thug.conf'
        """
        mongo = MongoDB()
        assert not mongo.enabled

    def test_make_counter(self):
        counter = self.mongo.make_counter(2)
        assert next(counter) in (2, )
        assert next(counter) in (3, )

    def test_get_url(self):
        assert self.mongo.urls.count_documents({}) in (0, )

        self.mongo.get_url(self.url)
        assert self.mongo.urls.count_documents({}) in (1, )

        # Testing for Duplicate entry
        self.mongo.get_url(self.url)
        assert self.mongo.urls.count_documents({}) in (1, )

    def test_set_url(self):
        self.mongo.enabled = False
        self.mongo.set_url(self.url)
        assert self.mongo.analyses.count_documents({}) in (0, )

        self.mongo.enabled = True
        log.ThugVulnModules.disable_acropdf()
        self.mongo.set_url(self.url)
        log.ThugVulnModules._acropdf_disabled = False  # TODO: Have enable_acropdf() function?
        analysis = self.mongo.analyses.find_one({"thug.plugins.acropdf": "disabled"})
        assert analysis
        assert self.mongo.analyses.count_documents({}) in (1, )

    def test_log_location(self):
        self.mongo.enabled = False
        self.mongo.log_location(self.url, self.file_data)
        assert self.mongo.locations.count_documents({}) in (0, )

        self.mongo.enabled = True
        self.mongo.log_location(self.url, self.file_data)
        assert self.mongo.locations.count_documents({}) in (1, )

    def test_log_connection(self):
        self.mongo.enabled = False
        self.mongo.log_connection(self.source, self.dest, self.con_method)
        assert self.mongo.connections.count_documents({}) in (0, )

        self.mongo.enabled = True
        self.mongo.log_connection(self.source, self.dest, self.con_method)
        assert self.mongo.connections.count_documents({}) in (1, )

        nodes = self.mongo.graph.G.nodes
        assert self.source in nodes
        assert self.dest in nodes

    def test_log_exploit_event(self):
        self.mongo.enabled = False
        self.mongo.log_exploit_event(self.url, "ActiveX", self.desc, self.cve)
        assert self.mongo.exploits.count_documents({}) in (0, )

        self.mongo.enabled = True
        self.mongo.log_exploit_event(self.url, "ActiveX", self.desc, self.cve)
        assert self.mongo.exploits.count_documents({}) in (1, )

    def test_log_image_ocr(self):
        self.mongo.enabled = False
        self.mongo.log_image_ocr(self.url, "Test")
        assert self.mongo.images.count_documents({}) in (0, )

        self.mongo.enabled = True
        self.mongo.log_image_ocr(self.url, "Test")
        assert self.mongo.images.count_documents({}) in (1, )

    def test_log_classifier(self):
        self.mongo.enabled = False
        self.mongo.log_classifier("exploit", self.url, self.cve, self.tag)
        assert self.mongo.classifiers.count_documents({}) in (0, )

        self.mongo.enabled = True
        self.mongo.log_classifier("exploit", self.url, self.cve, self.tag)
        assert self.mongo.classifiers.count_documents({}) in (1, )

    @patch('gridfs.grid_file.Collection', new=mongomock.collection.Collection)
    def test_log_file(self):
        self.mongo.enabled = False
        self.mongo.log_file(self.file_data)
        assert self.mongo.samples.count_documents({}) in (0, )

        self.mongo.enabled = True
        self.mongo.log_file(self.file_data)
        assert self.mongo.samples.count_documents({}) in (1, )

        # Testing for duplicate entry
        self.mongo.log_file(self.file_data)
        assert self.mongo.samples.count_documents({}) in (1, )

    def test_log_json(self):
        self.mongo.enabled = False
        self.mongo.log_json(self.base_dir)
        assert self.mongo.json.count_documents({}) in (0, )

        # Setting self.mongo.enabled = True
        self.mongo.enabled = True
        self.mongo.log_json(self.base_dir)
        assert self.mongo.json.count_documents({}) in (0, )

        # Enabling json_logging
        log.ThugOpts.json_logging = True
        self.mongo.log_json(self.base_dir)
        log.ThugOpts.json_logging = False
        assert self.mongo.json.count_documents({}) in (0, )

    def test_log_screenshot(self):
        self.mongo.enabled = False
        self.mongo.log_screenshot(self.url, self.data)
        assert self.mongo.screenshots.count_documents({}) in (0, )

        # Setting self.mongo.enabled = True
        self.mongo.enabled = True
        self.mongo.log_screenshot(self.url, self.data)
        assert self.mongo.screenshots.count_documents({}) in (1, )

    def test_log_event(self):
        self.mongo.enabled = False
        self.mongo.log_event(self.base_dir)
        assert self.mongo.graphs.count_documents({}) in (0, )

        self.mongo.enabled = True
        self.mongo.log_event(self.base_dir)
        assert self.mongo.graphs.count_documents({}) in (1, )

    def test_fix(self):
        encoded_data = self.mongo.fix("")
        assert "" in (encoded_data,)

        encoded_data = self.mongo.fix("sample\n-\ncontent")
        assert "sample-content" in (encoded_data,)

        encoded_data = self.mongo.fix(u"sample\n-\ncontent(í)", drop_spaces=False)
        assert u"sample\n-\ncontent(í)" in (encoded_data,)

    def test_add_code_snippet(self):
        self.mongo.enabled = False
        self.mongo.add_code_snippet(self.code_snippet, self.language, self.relationship, self.tag)
        assert self.mongo.codes.count_documents({}) in (0, )

        self.mongo.enabled = True
        self.mongo.add_code_snippet(self.code_snippet, self.language, self.relationship, self.tag)
        assert self.mongo.codes.count_documents({}) in (1, )

    def test_add_shellcode_snippet(self):
        self.mongo.codes.delete_many({})
        self.mongo.enabled = False
        self.mongo.add_shellcode_snippet(self.code_snippet, self.language, self.relationship, self.tag)
        assert self.mongo.codes.count_documents({}) in (0, )

        self.mongo.enabled = True
        self.mongo.add_shellcode_snippet(self.code_snippet, self.language, self.relationship, self.tag)
        assert self.mongo.codes.count_documents({}) in (1, )

    def test_add_behaviour_warn(self):
        self.mongo.enabled = False
        self.mongo.add_behavior_warn(self.desc, self.cve, self.code_snippet)
        assert self.mongo.behaviors.count_documents({}) in (0, )

        self.mongo.enabled = True
        self.mongo.add_behavior_warn(self.desc, self.cve, self.code_snippet)
        assert self.mongo.behaviors.count_documents({}) in (1, )

        self.mongo.add_behavior_warn()
        assert self.mongo.behaviors.count_documents({}) in (1, )

    def test_log_certificate(self):
        self.mongo.enabled = False
        self.mongo.log_certificate(self.url, self.cert)
        assert self.mongo.certificates.count_documents({}) in (0, )

        self.mongo.enabled = True
        self.mongo.log_certificate(self.url, self.cert)
        assert self.mongo.certificates.count_documents({}) in (1, )

    def test_log_virustotal(self):
        self.mongo.enabled = False
        self.mongo.log_virustotal(self.file_data, "sample-report")
        assert self.mongo.virustotal.count_documents({}) in (0, )

        self.mongo.enabled = True
        self.mongo.log_virustotal(self.file_data, "sample-report")
        assert self.mongo.virustotal.count_documents({}) in (1, )

    def test_log_honeyagent(self):
        assert self.mongo.honeyagent.count_documents({}) in (0, )

        self.mongo.log_honeyagent(self.file_data, "sample-report")
        assert self.mongo.honeyagent.count_documents({}) in (1, )

    def test_log_cookies(self):
        assert self.mongo.cookies.count_documents({}) in (0, )

        log.HTTPSession.cookies.set('domain', 'test.com')
        self.mongo.log_cookies()
        assert self.mongo.honeyagent.count_documents({}) in (1, )
