import sys
import os
import json
import tempfile
import logging
import pytest

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestMiscSamples(object):
    thug_path = os.path.dirname(os.path.realpath(__file__)).split("thug")[0]
    misc_path = os.path.join(thug_path, "thug", "samples/misc")

    def do_perform_test(self, caplog, sample, expected):
        thug = ThugAPI()

        thug.set_useragent('win7ie90')
        thug.set_events('click,storage')
        thug.disable_cert_logging()

        thug.log_init(sample)
        thug.run_local(sample)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1
            
        assert matches >= len(expected)

    def test_plugindetect1(self, caplog):
        sample   = os.path.join(self.misc_path, "PluginDetect-0.7.6.html")
        expected = ['AdobeReader version: 9.1.0.0', 
                    'Flash version: 10.0.64.0']

        self.do_perform_test(caplog, sample, expected)

    def test_plugindetect2(self, caplog):
        sample   = os.path.join(self.misc_path, "PluginDetect-0.7.8.html")
        expected = ['AdobeReader version: 9,1,0,0',
                    'Flash version: 10,0,64,0',
                    'Java version: 1,6,0,32',
                    'ActiveXObject: javawebstart.isinstalled.1.6.0.0', 
                    'ActiveXObject: javaplugin.160_32']

        self.do_perform_test(caplog, sample, expected)

    def test_test1(self, caplog):
        sample   = os.path.join(self.misc_path, "test1.html")
        expected = ['[Window] Alert Text: one']
        self.do_perform_test(caplog, sample, expected)

    def test_test2(self, caplog):
        sample   = os.path.join(self.misc_path, "test2.html")
        expected = ['[Window] Alert Text: Java enabled: true']
        self.do_perform_test(caplog, sample, expected)

    def test_test3(self, caplog):
        sample   = os.path.join(self.misc_path, "test3.html")
        expected = ['[Window] Alert Text: foo']
        self.do_perform_test(caplog, sample, expected)

    def test_testAppendChild(self, caplog):
        sample   = os.path.join(self.misc_path, "testAppendChild.html")
        expected = ["<div>Don't care about me</div>",
                    '<div>Just a sample</div>']
        self.do_perform_test(caplog, sample, expected)

    def test_testClipboardData(self, caplog):
        sample   = os.path.join(self.misc_path, "testClipboardData.html")
        expected = ['Test ClipboardData']
        self.do_perform_test(caplog, sample, expected)

    def test_testCloneNode(self, caplog):
        sample   = os.path.join(self.misc_path, "testCloneNode.html")
        expected = ['<div id="cloned"><q>Can you copy <em>everything</em> I say?</q></div>']
        self.do_perform_test(caplog, sample, expected)

    def test_testCloneNode2(self, caplog):
        sample   = os.path.join(self.misc_path, "testCloneNode2.html")
        expected = ['<button align="left" id="myButton">Clone node</button>']
        self.do_perform_test(caplog, sample, expected)

    def test_testCreateHTMLDocument(self, caplog):
        sample   = os.path.join(self.misc_path, "testCreateHTMLDocument.html")
        expected = ['<html><head><title>New Document</title></head><body><p>This is a new paragraph.</p></body></html>']
        self.do_perform_test(caplog, sample, expected)

    def test_testCreateStyleSheet(self, caplog):
        sample   = os.path.join(self.misc_path, "testCreateStyleSheet.html")
        expected = ['style1.css" rel="stylesheet"></link><link href="style2.css" rel="stylesheet"></link><link href="style3.css" rel="stylesheet"></link><link href="style4']
        self.do_perform_test(caplog, sample, expected)

    def test_testDocumentAll(self, caplog):
        sample   = os.path.join(self.misc_path, "testDocumentAll.html")
        expected = ['<a href="http://www.google.com">Google</a>']
        self.do_perform_test(caplog, sample, expected)

    def test_testDocumentWrite1(self, caplog):
        sample   = os.path.join(self.misc_path, "testDocumentWrite1.html")
        expected = ['Foobar',
                    "Google</a><script>alert('foobar');</script><script language=\"VBScript\">alert('Gnam');</script><script>alert('Aieeeeee');</script></body>"]
        self.do_perform_test(caplog, sample, expected)

    def test_testExternalSidebar(self, caplog):
        sample   = os.path.join(self.misc_path, "testExternalSidebar.html")
        expected = ['[Window] Alert Text: Internet Explorer >= 7.0 or Chrome']
        self.do_perform_test(caplog, sample, expected)

    def test_testGetElementsByClassName(self, caplog):
        sample   = os.path.join(self.misc_path, "testGetElementsByClassName.html")
        expected = ['<div class="example">First</div>',
                    '<div class="example">Hello World!</div>',
                    '<div class="example">Second</div>']
        self.do_perform_test(caplog, sample, expected)

    def test_testInnerHTML(self, caplog):
        sample   = os.path.join(self.misc_path, "testInnerHTML.html")
        expected = ['dude', 'Fred Flinstone']
        self.do_perform_test(caplog, sample, expected)

    def test_testInsertBefore(self, caplog):
        sample   = os.path.join(self.misc_path, "testInsertBefore.html")
        expected = ["<div>Just a sample</div><div>I'm your reference!</div></body></html>"]
        self.do_perform_test(caplog, sample, expected)
