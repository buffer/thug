from thug.Logging.modules.compatibility import thug_string,thug_unicode


class TestCompatibility:
    def test_python2(self):
        assert thug_string in (basestring, )
        assert thug_unicode in (unicode, )
