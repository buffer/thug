import os
import pytest
import logging
import collections

import thug
from thug.ThugAPI.ThugOpts import ThugOpts

configuration_path = thug.__configuration_path__

log                    = logging.getLogger("Thug")
log.configuration_path = configuration_path
log.personalities_path = os.path.join(configuration_path, "personalities") if configuration_path else None


class TestThugOpts:
    opts = ThugOpts()

    def test_verbose(self):
        assert not self.opts.verbose

        self.opts.verbose = True
        assert self.opts.verbose

    def test_debug(self):
        assert not self.opts.debug

        self.opts.debug = True
        assert self.opts.debug

    def test_proxy(self):
        assert self.opts.proxy is None

        self.opts.proxy = ''
        assert self.opts.proxy is None

        self.opts.proxy = 'http://www.example.com'
        addr = self.opts.proxy
        assert addr in ('http://www.example.com', )

    def test_error_proxy(self, caplog):
        caplog.clear()

        with pytest.raises(SystemExit) as cm:
            self.opts.proxy = 'ftp://www.example.com'
        assert '[ERROR] Invalid proxy scheme' in caplog.text

    def test_raise_for_proxy(self):
        assert self.opts.raise_for_proxy

        self.opts.raise_for_proxy = False
        assert not self.opts.raise_for_proxy

    def test_useragent(self):
        assert self.opts.useragent in ('winxpie60', )

        self.opts.useragent = 'linuxchrome26'
        ua = self.opts.useragent
        assert ua in ('linuxchrome26', )

    def test_warning_useragent(self, caplog):
        caplog.clear()

        self.opts.useragent = 'nonexistent-ua'
        assert '[WARNING] Invalid User Agent provided' in caplog.text

    def test_referer(self):
        assert self.opts.referer in ('about:blank', )

        self.opts.referer = 'https://www.example.com'
        referer = self.opts.referer
        assert referer in ('https://www.example.com', )

    def test_events(self):
        sample_events = 'event1,event2,event2,event3'
        assert self.opts.events in ([], )

        self.opts.events = ''
        assert self.opts.events in ([], )

        self.opts.events = sample_events
        event_list = self.opts.events
        assert event_list in (['event1', 'event2', 'event3'], )

    def test_delay(self):
        assert self.opts.delay in (0, )

        self.opts.delay = 10
        time = self.opts.delay
        assert time in (10, )

    def test_warning_delay(self, caplog):
        caplog.clear()

        self.opts.delay = 'a'
        assert '[WARNING] Ignoring invalid delay value' in caplog.text

    def test_attachment(self):
        assert not self.opts.attachment

        self.opts.attachment = True
        assert self.opts.attachment

    def test_file_logging(self):
        assert not self.opts.file_logging

        self.opts.file_logging = True
        assert self.opts.file_logging

    def test_json_logging(self):
        assert not self.opts.json_logging

        self.opts.json_logging = True
        assert self.opts.json_logging

    def test_maec11_logging(self):
        assert not self.opts.maec11_logging

        self.opts.maec11_logging = True
        assert self.opts.maec11_logging

    def test_elasticsearch_logging(self):
        assert not self.opts.elasticsearch_logging

        self.opts.elasticsearch_logging = True
        assert self.opts.elasticsearch_logging

    def test_code_logging(self):
        assert self.opts.code_logging

        self.opts.code_logging = False
        assert not self.opts.code_logging

    def test_cert_logging(self):
        assert self.opts.cert_logging

        self.opts.cert_logging = False
        assert not self.opts.cert_logging

    def test_no_fetch(self):
        assert not self.opts.no_fetch

        self.opts.no_fetch = True
        assert self.opts.no_fetch

    def test_threshold(self):
        assert self.opts.threshold in (0, )

        self.opts.threshold = 5
        pages = self.opts.threshold
        assert pages in (5, )

    def test_warning_threshold(self, caplog):
        caplog.clear()

        self.opts.threshold = 'a'
        assert '[WARNING] Ignoring invalid threshold value' in caplog.text

    def test_connect_timeout(self):
        assert self.opts.connect_timeout in (10, )

        self.opts.connect_timeout = 20
        time = self.opts.connect_timeout
        assert time in (20, )

    def test_warning_connect_timeout(self, caplog):
        caplog.clear()

        self.opts.connect_timeout = 'a'
        assert '[WARNING] Ignoring invalid connect timeout value' in caplog.text

    def test_timeout(self):
        assert self.opts.timeout in (600, )

        self.opts.timeout = 300
        time = self.opts.timeout
        assert time in (300, )

    def test_warning_timeout(self, caplog):
        caplog.clear()

        self.opts.timeout = 'a'
        assert '[WARNING] Ignoring invalid timeout value' in caplog.text

    def test_broken_url(self):
        assert not self.opts.broken_url

        self.opts.broken_url = True
        assert self.opts.broken_url

    def test_vt_query(self):
        assert not self.opts.vt_query

        self.opts.vt_query
        # assert self.opts.vt_query FIXME

    def test_vt_submit(self):
        assert not self.opts.vt_submit

        self.opts.vt_submit
        # assert self.opts.vt_submit FIXME

    def test_vt_runtime_apikey(self):
        assert self.opts.vt_runtime_apikey is None

        self.opts.vt_runtime_apikey = 'sample-key'
        key = self.opts.vt_runtime_apikey
        assert key in ('sample-key', )

    def test_web_tracking(self):
        assert not self.opts.web_tracking

        self.opts.web_tracking = True
        assert self.opts.web_tracking

    def test_honeyagent(self):
        assert self.opts.honeyagent

        self.opts.honeyagent = False
        assert not self.opts.honeyagent

    def test_mongodb_address(self):
        assert self.opts.mongodb_address is None

        self.opts.mongodb_address = '127.0.0.1:27017'
        addr = self.opts.mongodb_address
        assert addr in ('127.0.0.1:27017', )