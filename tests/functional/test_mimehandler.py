from thug.ThugAPI.ThugAPI import ThugAPI


class TestMIMEHandler(object):
    def do_perform_test(self, caplog, url, expected, type_ = "remote"):
        thug = ThugAPI()

        thug.set_useragent('win7ie90')
        thug.set_features_logging()
        thug.set_ssl_verify()
        thug.log_init(url)

        m = getattr(thug, "run_{}".format(type_))
        m(url)

        records = [r.message for r in caplog.records]

        matches = 0

        for e in expected:
            for record in records:
                if e in record:
                    matches += 1

        assert matches >= len(expected)

    def test_zip_handler(self, caplog):
        expected = ['[Window] Alert Text: Foobar']
        self.do_perform_test(caplog, "https://github.com/buffer/thug/raw/master/tests/test_files/test.js.zip", expected)
