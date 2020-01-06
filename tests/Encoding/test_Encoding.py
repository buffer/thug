# coding=utf-8

from thug.Encoding.Encoding import Encoding
encoding = Encoding()


class TestEncoding:
    def test_string(self):
        result = encoding.detect('sample-content')
        assert result['encoding'] in ('ASCII', )

    def test_unicode(self):
        result = encoding.detect(u'sample-content')
        assert result['encoding'] in ('ASCII', )

    def test_utf8_bom(self):
        result = encoding.detect(b'\xEF\xBB\xBF')
        assert result['encoding'] in ('UTF-8-SIG', )

    def test_unicode_utf8(self):
        result = encoding.detect(u'í')
        assert result['encoding'] in ('UTF-8', )
