# coding=utf-8
import os
import logging

import pytest

import thug
from thug.ThugAPI.ThugOpts import ThugOpts
from thug.Logging.modules.MongoDB import MongoDB
from thug.ThugAPI.ThugVulnModules import ThugVulnModules
from thug.Logging.ThugLogging import ThugLogging
from thug.Encoding.Encoding import Encoding
from thug.DOM.HTTPSession import HTTPSession

configuration_path = thug.__configuration_path__

log = logging.getLogger("Thug")

log.personalities_path = thug.__personalities_path__ if configuration_path else None
log.ThugOpts = ThugOpts()
log.configuration_path = configuration_path
log.ThugLogging = ThugLogging()
log.ThugVulnModules = ThugVulnModules()
log.Encoding = Encoding()
log.HTTPSession = HTTPSession()
log.PyHooks = dict()


IN_GITHUB_ACTIONS = os.getenv("GITHUB_ACTIONS") == "true" and os.getenv(
    "RUNNER_OS"
) in ("Linux",)


class TestMongoDB:
    cve = "CVE-XXXX"
    url = "www.example.com"
    data = b"sample-data"
    desc = "sample-desc"
    cert = "sample-cert"

    file_data = {
        "sha1": "b13d13733c4c9406fd0e01485bc4a34170b7d326",
        "data": data,
        "ssdeep": "24:9EGtDqSyDVHNkCq4LOmvmuS+MfTAPxokCOB:97tG5DjQ4LDs+sTAPxLT",
        "sha256": "459bf0aeda19633c8e757c05ee06b8121a51217cea69ce60819bb34092a296a0",
        "type": "JAR",
        "md5": "d4be8fbeb3a219ec8c6c26ffe4033a16",
    }

    base_dir = "path/to/sample/basedir"
    code_snippet = b"var i = 12;"
    base64_snippet = "dmFyIGkgPSAxMjs="
    favicon_dhash = "55aa554d2da796165500d755692bbeb6"
    language = "Javascript"
    relationship = "Contained_Inside"
    tag = "Tag"  # TODO: Better tag
    method = "Dynamic Analysis"

    source = "www.ex1.com"
    dest = "www.ex2.com"
    con_method = "iframe"

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_address(self):
        log.ThugOpts.mongodb_address = "syntax-error://localhost:27017"
        mongo = MongoDB()
        log.ThugOpts.mongodb_address = None

        assert not mongo.enabled

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_init(self):
        """
        Testing for conf file 'thug.conf'
        """
        mongo = MongoDB()
        assert not mongo.enabled

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_make_counter(self):
        log.ThugOpts.mongodb_address = "mongodb://localhost:27017"
        mongo = MongoDB()

        counter = mongo.make_counter(2)
        assert next(counter) in (2,)
        assert next(counter) in (3,)

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_get_url(self):
        log.ThugOpts.mongodb_address = "mongodb://localhost:27017"
        mongo = MongoDB()

        assert mongo.urls.count_documents({}) in (0,)

        mongo.get_url(self.url)
        assert mongo.urls.count_documents({}) in (1,)

        # Testing for Duplicate entry
        mongo.get_url(self.url)
        assert mongo.urls.count_documents({}) in (1,)

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_set_url(self):
        log.ThugOpts.mongodb_address = "mongodb://localhost:27017"
        mongo = MongoDB()

        mongo.enabled = False
        mongo.set_url(self.url)
        assert mongo.analyses.count_documents({}) in (0,)

        mongo.enabled = True
        log.ThugVulnModules.disable_acropdf()
        mongo.set_url(self.url)
        log.ThugVulnModules._acropdf_disabled = (
            False  # TODO: Have enable_acropdf() function?
        )
        analysis = mongo.analyses.find_one({"thug.plugins.acropdf": "disabled"})
        assert analysis
        assert mongo.analyses.count_documents({}) in (1,)

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_log_location(self):
        log.ThugOpts.mongodb_address = "mongodb://localhost:27017"
        mongo = MongoDB()

        mongo.enabled = False
        mongo.set_url(self.url)
        mongo.log_location(self.url, self.file_data)
        assert mongo.locations.count_documents({}) in (0,)

        mongo.enabled = True
        mongo.set_url(self.url)
        mongo.log_location(self.url, self.file_data)
        assert mongo.locations.count_documents({}) in (1,)

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_log_connection(self):
        log.ThugOpts.mongodb_address = "mongodb://localhost:27017"
        mongo = MongoDB()

        mongo.enabled = False
        mongo.set_url(self.url)
        mongo.log_connection(self.source, self.dest, self.con_method)
        assert mongo.connections.count_documents({}) in (0,)

        mongo.enabled = True
        mongo.set_url(self.url)
        mongo.log_connection(self.source, self.dest, self.con_method)
        assert mongo.connections.count_documents({}) in (1,)

        nodes = mongo.graph.G.nodes
        assert self.source in nodes
        assert self.dest in nodes

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_log_exploit_event(self):
        log.ThugOpts.mongodb_address = "mongodb://localhost:27017"
        mongo = MongoDB()

        mongo.enabled = False
        mongo.set_url(self.url)
        mongo.log_exploit_event(self.url, "ActiveX", self.desc, self.cve)
        assert mongo.exploits.count_documents({}) in (0,)

        mongo.enabled = True
        mongo.set_url(self.url)
        mongo.log_exploit_event(self.url, "ActiveX", self.desc, self.cve)
        assert mongo.exploits.count_documents({}) in (1,)

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_log_image_ocr(self):
        log.ThugOpts.mongodb_address = "mongodb://localhost:27017"
        mongo = MongoDB()

        mongo.enabled = False
        mongo.set_url(self.url)
        mongo.log_image_ocr(self.url, "Test")
        assert mongo.images.count_documents({}) in (0,)

        mongo.enabled = True
        mongo.set_url(self.url)
        mongo.log_image_ocr(self.url, "Test")
        assert mongo.images.count_documents({}) in (1,)

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_log_classifier(self):
        log.ThugOpts.mongodb_address = "mongodb://localhost:27017"
        mongo = MongoDB()

        mongo.enabled = False
        mongo.set_url(self.url)
        mongo.log_classifier("exploit", self.url, self.cve, self.tag)
        assert mongo.classifiers.count_documents({}) in (0,)

        mongo.enabled = True
        mongo.set_url(self.url)
        mongo.log_classifier("exploit", self.url, self.cve, self.tag)
        assert mongo.classifiers.count_documents({}) in (1,)

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_log_file(self):
        log.ThugOpts.mongodb_address = "mongodb://localhost:27017"
        mongo = MongoDB()

        mongo.enabled = False
        mongo.set_url(self.url)
        mongo.log_file(self.file_data)
        assert mongo.samples.count_documents({}) in (0,)

        mongo.enabled = True
        mongo.set_url(self.url)
        mongo.log_file(self.file_data)
        assert mongo.samples.count_documents({}) in (1,)

        # Testing for duplicate entry
        mongo.log_file(self.file_data)
        assert mongo.samples.count_documents({}) in (1,)

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_log_json(self):
        log.ThugOpts.mongodb_address = "mongodb://localhost:27017"
        mongo = MongoDB()

        mongo.enabled = False
        mongo.set_url(self.url)
        mongo.log_json(self.base_dir)
        assert mongo.json.count_documents({}) in (0,)

        # Setting mongo.enabled = True
        mongo.enabled = True
        mongo.set_url(self.url)
        mongo.log_json(self.base_dir)
        assert mongo.json.count_documents({}) in (0,)

        # Enabling json_logging
        log.ThugOpts.json_logging = True
        mongo.set_url(self.url)
        mongo.log_json(self.base_dir)
        log.ThugOpts.json_logging = False
        assert mongo.json.count_documents({}) in (0,)

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_log_screenshot(self):
        log.ThugOpts.mongodb_address = "mongodb://localhost:27017"
        mongo = MongoDB()

        mongo.enabled = False
        mongo.set_url(self.url)
        mongo.log_screenshot(self.url, self.data)
        assert mongo.screenshots.count_documents({}) in (0,)

        # Setting mongo.enabled = True
        mongo.enabled = True
        mongo.set_url(self.url)
        mongo.log_screenshot(self.url, self.data)
        assert mongo.screenshots.count_documents({}) in (1,)

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_log_event(self):
        log.ThugOpts.mongodb_address = "mongodb://localhost:27017"
        mongo = MongoDB()

        mongo.enabled = False
        mongo.set_url(self.url)
        mongo.log_event(self.base_dir)
        assert mongo.graphs.count_documents({}) in (0,)

        mongo.enabled = True
        mongo.set_url(self.url)
        mongo.log_event(self.base_dir)
        assert mongo.graphs.count_documents({}) in (1,)

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_fix(self):
        log.ThugOpts.mongodb_address = "mongodb://localhost:27017"
        mongo = MongoDB()

        encoded_data = mongo.fix("")
        assert "" in (encoded_data,)

        encoded_data = mongo.fix("sample\n-\ncontent")
        assert "sample-content" in (encoded_data,)

        encoded_data = mongo.fix("sample\n-\ncontent(í)", drop_spaces=False)
        assert "sample\n-\ncontent(í)" in (encoded_data,)

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_add_code_snippet(self):
        log.ThugOpts.mongodb_address = "mongodb://localhost:27017"
        mongo = MongoDB()

        mongo.enabled = False
        mongo.set_url(self.url)
        mongo.add_code_snippet(
            self.code_snippet, self.language, self.relationship, self.tag
        )
        assert mongo.codes.count_documents({}) in (0,)

        mongo.enabled = True
        mongo.set_url(self.url)
        mongo.add_code_snippet(
            self.code_snippet, self.language, self.relationship, self.tag
        )
        assert mongo.codes.count_documents({}) in (1,)

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_add_shellcode_snippet(self):
        log.ThugOpts.mongodb_address = "mongodb://localhost:27017"
        mongo = MongoDB()

        mongo.codes.delete_many({})
        mongo.enabled = False
        mongo.set_url(self.url)
        mongo.add_shellcode_snippet(
            self.code_snippet, self.language, self.relationship, self.tag
        )
        assert mongo.codes.count_documents({}) in (0,)

        mongo.enabled = True
        mongo.set_url(self.url)
        mongo.add_shellcode_snippet(
            self.code_snippet, self.language, self.relationship, self.tag
        )
        assert mongo.codes.count_documents({}) in (1,)

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_add_behaviour_warn(self):
        log.ThugOpts.mongodb_address = "mongodb://localhost:27017"
        mongo = MongoDB()

        mongo.enabled = False
        mongo.set_url(self.url)
        mongo.add_behavior_warn(self.desc, self.cve, self.code_snippet)
        assert mongo.behaviors.count_documents({}) in (0,)

        mongo.enabled = True
        mongo.set_url(self.url)
        mongo.add_behavior_warn(self.desc, self.cve, self.code_snippet)
        assert mongo.behaviors.count_documents({}) in (1,)

        mongo.add_behavior_warn()
        assert mongo.behaviors.count_documents({}) in (1,)

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_log_certificate(self):
        log.ThugOpts.mongodb_address = "mongodb://localhost:27017"
        mongo = MongoDB()

        mongo.enabled = False
        mongo.set_url(self.url)
        mongo.log_certificate(self.url, self.cert)
        assert mongo.certificates.count_documents({}) in (0,)

        mongo.enabled = True
        mongo.set_url(self.url)
        mongo.log_certificate(self.url, self.cert)
        assert mongo.certificates.count_documents({}) in (1,)

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_log_honeyagent(self):
        log.ThugOpts.mongodb_address = "mongodb://localhost:27017"
        mongo = MongoDB()

        mongo.enabled = False
        assert mongo.honeyagent.count_documents({}) in (0,)

        mongo.enabled = True
        mongo.set_url(self.url)
        mongo.log_honeyagent(self.file_data, "sample-report")
        assert mongo.honeyagent.count_documents({}) in (1,)

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_log_cookies(self):
        log.ThugOpts.mongodb_address = "mongodb://localhost:27017"
        mongo = MongoDB()

        mongo.enabled = False
        mongo.set_url(self.url)
        assert mongo.cookies.count_documents({}) in (0,)

        mongo.enabled = True
        mongo.set_url(self.url)
        log.HTTPSession.cookies.set("domain", "test.com")
        mongo.log_cookies()
        assert mongo.honeyagent.count_documents({}) in (1,)

    @pytest.mark.skipif(
        not (IN_GITHUB_ACTIONS), reason="Test works just in Github Actions (Linux)"
    )
    def test_log_favicon(self):
        log.ThugOpts.mongodb_address = "mongodb://localhost:27017"
        mongo = MongoDB()

        mongo.enabled = False
        mongo.set_url(self.url)
        mongo.log_favicon(self.url, self.favicon_dhash)
        assert mongo.favicons.count_documents({}) in (0,)

        mongo.enabled = True
        mongo.set_url(self.url)
        mongo.log_favicon(self.url, self.favicon_dhash)
        assert mongo.favicons.count_documents({}) in (1,)
