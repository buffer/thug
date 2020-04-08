# coding=utf-8
import os
import shutil
import logging

from six import StringIO

import thug
from thug.ThugAPI.ThugOpts import ThugOpts
from thug.Logging.modules.JSON import JSON
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

json = JSON(thug.__version__)


class TestJSON:
    cve  = "CVE-XXXX"
    url  = "sample-url"
    data = "sample-data"
    desc = "sample-desc"

    file_data = {'content': data,
                 'status' : 200,
                 'md5'    : 'ba4ba63ec75693aedfebc7299a4f7661',
                 'sha256' : 'c45df724cba87ac84892bf3eeb910393d69d163e9ad96cac2e2074487eaa907b',
                 'fsize'  : 11,  # len(data)
                 'ctype'  : 'text/plain',
                 'mtype'  : 'text/plain',
                }

    base_dir       = "sample-basedir"
    code_snippet   = "var i = 12;"
    base64_snippet = "dmFyIGkgPSAxMjs="
    language       = "Javascript"
    relationship   = "Contained_Inside"
    tag            = "Tag"  # TODO: Better tag
    method         = "Dynamic Analysis"

    def test_json_enabled(self):
        log.ThugOpts.json_logging = True
        assert json.json_enabled

        log.ThugOpts.json_logging = False
        assert not json.json_enabled

    def test_get_vuln_module(self):
        acropdf = json.get_vuln_module("acropdf")
        assert acropdf in ("9.1.0", )

        assert "disabled" in json.get_vuln_module("unknown")

    def test_fix(self):
        encoded_data = json.fix("")
        assert "" in (encoded_data, )

        encoded_data = json.fix("sample\n-\ncontent")
        assert "sample-content" in (encoded_data, )

        encoded_data = json.fix(u"sample\n-\ncontent(í)", drop_spaces=False)
        assert u"sample\n-\ncontent(í)" in (encoded_data, )

    def test_set_url(self):
        json.set_url(self.url)
        assert not json.data["url"]

        log.ThugOpts.json_logging = True
        json.set_url(self.url)
        log.ThugOpts.json_logging = False
        assert self.url in (json.data["url"], )

    def test_add_code_snippet(self):
        json.add_code_snippet(self.code_snippet, self.language, self.relationship, self.tag)
        assert not json.data["code"]

        log.ThugOpts.json_logging = True
        json.add_code_snippet(self.code_snippet, self.language, self.relationship, self.tag)
        data = json.data["code"][0]

        log.ThugOpts.json_logging = False

        assert self.code_snippet in (data["snippet"], )
        assert self.language in (data["language"], )
        assert self.relationship in (data["relationship"], )
        assert self.tag in (data["tag"], )
        assert self.method in (data["method"], )

    def test_add_shellcode_snippet(self):
        json.data["code"] = []
        json.add_shellcode_snippet(self.code_snippet, self.language, self.relationship, self.tag)
        assert not json.data["code"]

        log.ThugOpts.json_logging = True
        json.add_shellcode_snippet(self.code_snippet, self.language, self.relationship, self.tag)
        data = json.data["code"][0]

        log.ThugOpts.json_logging = False

        assert self.base64_snippet in (data["snippet"], )
        assert self.language in (data["language"], )
        assert self.relationship in (data["relationship"], )
        assert self.tag in (data["tag"], )
        assert self.method in (data["method"], )

    def test_log_connection(self):
        json.log_connection("source", "destination", "link")
        assert not json.data["connections"]

        log.ThugOpts.json_logging = True
        json.log_connection("source1", "destination1", "link")
        connections = json.data["connections"][0]

        assert "source1" in (connections["source"], )
        assert "destination1" in (connections["destination"], )
        assert "link" in (connections["method"], )
        assert "source1 -- link --> destination1" in (json.data["behavior"][0]["description"], )

        json.log_connection("source1", "destination1", "link", {"exploit": "EXC"})
        assert "[Exploit]  source1 -- link --> destination1" in (json.data["behavior"][1]["description"],)

        log.ThugOpts.json_logging = False

    def test_get_content(self):
        content = json.get_content(self.file_data)
        assert self.data in (content, )

        log.ThugOpts.code_logging = False
        content = json.get_content(self.file_data)
        log.ThugOpts.code_logging = True

        assert "NOT AVAILABLE" in (content, )

    def test_log_location(self):
        json.log_location(self.url, self.file_data)
        assert not json.data["locations"]

        log.ThugOpts.json_logging = True
        json.log_location(self.url, self.file_data)
        locations_json = json.data["locations"][0]
        log.ThugOpts.json_logging = False

        assert self.url in (locations_json["url"], )
        assert self.file_data["content"] in (locations_json["content"], )
        assert self.file_data["status"] in (locations_json["status"], )
        assert self.file_data["ctype"] in (locations_json["content-type"], )
        assert self.file_data["md5"] in (locations_json["md5"], )
        assert self.file_data["sha256"] in (locations_json["sha256"],)
        assert self.file_data["fsize"] in (locations_json["size"],)
        assert self.file_data["mtype"] in (locations_json["mimetype"],)

    def test_log_exploit_event(self):
        json.log_exploit_event(self.url, "ActiveX", self.desc, self.cve, self.data)
        assert not json.data["exploits"]

        log.ThugOpts.json_logging = True
        json.log_exploit_event(self.url, "ActiveX", self.desc, self.cve, self.data)
        exploit_json = json.data["exploits"][0]
        log.ThugOpts.json_logging = False

        assert self.url in (exploit_json["url"], )
        assert "ActiveX" in (exploit_json["module"], )
        assert self.desc in (exploit_json["description"], )
        assert self.cve in (exploit_json["cve"], )
        assert self.data in (exploit_json["data"], )

    def test_log_classifier(self):
        json.log_classifier("exploit", self.url, self.cve, None)
        assert not json.data["classifiers"]

        log.ThugOpts.json_logging = True
        json.log_classifier("exploit", self.url, self.cve, None)
        classifier_json = json.data["classifiers"][0]
        log.ThugOpts.json_logging = False

        assert "exploit" in (classifier_json["classifier"], )
        assert self.url in (classifier_json["url"], )
        assert self.cve in (classifier_json["rule"], )
        assert not classifier_json["tags"]

    def test_add_behaviour_warn(self):
        json.data["behavior"] = []
        json.add_behavior_warn(self.desc, self.cve, self.code_snippet)
        assert not json.data["behavior"]

        log.ThugOpts.json_logging = True
        json.add_behavior_warn()
        assert not json.data["behavior"]

        json.add_behavior_warn(self.desc, self.cve, self.code_snippet)
        behaviour_json = json.data["behavior"][0]
        log.ThugOpts.json_logging = False

        assert self.desc in (behaviour_json["description"], )
        assert self.cve in (behaviour_json["cve"], )
        assert self.code_snippet in (behaviour_json["snippet"], )
        assert self.method in (behaviour_json["method"], )

    def test_log_file(self):
        json.log_file(self.base_dir)
        assert not json.data["files"]

        log.ThugOpts.json_logging = True
        json.log_file(self.base_dir)
        log.ThugOpts.json_logging = False

        assert self.base_dir in json.data["files"]

    def test_log_image_ocr(self):
        json.log_image_ocr("url", "result")
        assert not json.data["images"]

        log.ThugOpts.json_logging = True
        json.log_image_ocr("url", "result")
        assert json.data["images"]
        log.ThugOpts.json_logging = False

    def test_export(self):
        log.ThugOpts.json_logging = True
        log.ThugOpts.file_logging = True
        json.export(self.base_dir)
        assert json.cached_data
        assert os.path.isdir(self.base_dir)

        json.cached_data = None
        shutil.rmtree(self.base_dir)

        log.ThugOpts.json_logging = False
        log.ThugOpts.file_logging = False
        json.export(self.base_dir)
        assert not os.path.isdir(self.base_dir)

    def test_get_json_data(self):
        output = StringIO()
        output.write(self.data)
        json.cached_data = output
        data = json.get_json_data(self.base_dir)
        assert self.data in (data, )

        json.cached_data = None
        assert not json.get_json_data(self.base_dir)
