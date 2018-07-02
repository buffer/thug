import logging
import pytest

from thug.ThugAPI.ThugAPI import ThugAPI

log = logging.getLogger("Thug")


class TestThugAPI:
    thug_api = ThugAPI()

    def test_version(self):
        with pytest.raises(SystemExit):
            self.thug_api.version()

    def test_useragent(self):
        assert self.thug_api.get_useragent() in ('winxpie60', )

        self.thug_api.set_useragent('winxpchrome20')
        assert self.thug_api.get_useragent() in ('winxpchrome20', )

    def test_events(self):
        assert self.thug_api.get_events() in ([], )

        self.thug_api.set_events('event1,event2,event2,event3')
        assert self.thug_api.get_events() in (['event1', 'event2', 'event3'], )

    def test_delay(self):
        assert self.thug_api.get_delay() in (0,)

        self.thug_api.set_delay(10)
        assert self.thug_api.get_delay() in (10,)

    def test_attachment(self):
        assert not self.thug_api.get_attachment()

        self.thug_api.set_attachment()
        assert self.thug_api.get_attachment()

    def test_file_logging(self):
        assert not self.thug_api.get_file_logging()

        self.thug_api.set_file_logging()
        assert self.thug_api.get_file_logging()

    def test_json_logging(self):
        assert not self.thug_api.get_json_logging()

        self.thug_api.set_json_logging()
        assert self.thug_api.get_json_logging()

    def test_maec_logging(self):
        assert not self.thug_api.get_maec11_logging()

        self.thug_api.set_maec11_logging()
        assert self.thug_api.get_maec11_logging()

    def test_elasticsearch_logging(self):  # TODO: Check for logging.level?
        assert not self.thug_api.get_elasticsearch_logging()

        self.thug_api.set_elasticsearch_logging()
        assert self.thug_api.get_elasticsearch_logging()

    def test_referer(self):
        assert self.thug_api.get_referer() in ('about:blank', )

        self.thug_api.set_referer('https://www.example.com')
        assert self.thug_api.get_referer() in ('https://www.example.com', )

    def test_proxy(self):
        assert self.thug_api.get_proxy() is None

        self.thug_api.set_proxy('http://www.example.com')
        assert self.thug_api.get_proxy() in ('http://www.example.com', )

    def test_raise_for_proxy(self):
        assert self.thug_api.get_raise_for_proxy()

        self.thug_api.set_raise_for_proxy(False)
        assert not self.thug_api.get_raise_for_proxy()

    def test_no_fetch(self):
        assert not log.ThugOpts.no_fetch

        self.thug_api.set_no_fetch()
        assert log.ThugOpts.no_fetch

    def test_verbose(self):  # TODO: Check for logging.level
        assert not log.ThugOpts.verbose

        self.thug_api.set_verbose()
        assert log.ThugOpts.verbose

    def test_debug(self):  # TODO: Check for logging.level
        assert not log.ThugOpts.debug

        self.thug_api.set_debug()
        assert log.ThugOpts.debug

    def test_ast_debug(self):
        assert not log.ThugOpts.ast_debug

        self.thug_api.set_ast_debug()
        assert log.ThugOpts.ast_debug

    def test_http_debug(self):
        assert log.ThugOpts.http_debug in (0, )

        self.thug_api.set_http_debug()
        assert log.ThugOpts.http_debug in (1, )

        self.thug_api.set_http_debug()
        assert log.ThugOpts.http_debug in (2, )

    def test_acropdf_pdf(self):
        assert log.ThugVulnModules.acropdf_pdf in ('9.1.0', )

        self.thug_api.set_acropdf_pdf('1.0.0', )
        assert log.ThugVulnModules.acropdf_pdf in ('1.0.0',)

    def test_shockwave_flash(self):
        assert log.ThugVulnModules.shockwave_flash in ('10.0.64.0', )

        self.thug_api.set_shockwave_flash('8.0', )
        assert log.ThugVulnModules.shockwave_flash in ('8.0',)

    def test_javaplugin(self):
        pass

    def test_silverlight(self):
        pass

    def test_threshold(self):
        pass

    def test_extensive(self):
        pass

    def test_timeout(self):
        pass

    def test_connect_timeout(self):
        pass

    def test_broken_url(self):
        pass

    def test_web_tracking(self):
        pass

    def test_honeyagent(self):
        pass

    def test_code_logging(self):
        pass

    def test_cert_logging(self):
        pass

    def test_vt_query(self):
        pass

    def test_vt_submit(self):
        pass

    def test_vt_runtime_apikey(self):
        pass

    def test_mongodb_address(self):
        pass

    def test_add_htmlclassifier(self):
        pass

    def test_add_urlclassifier(self):
        pass

    def test_add_jsclassifier(self):
        pass

    def test_add_vbsclassifier(self):
        pass

    def test_add_textclassifier(self):
        pass

    def test_add_sampleclassifier(self):
        pass

    def test_add_htmlfilter(self):
        pass

    def test_add_urlfilter(self):
        pass

    def test_add_jsfilter(self):
        pass

    def test_add_vbsfilter(self):
        pass

    def test_add_textfilter(self):
        pass

    def test_add_samplefilter(self):
        pass
