# coding=utf-8

from thug.Encoding.Encoding import Encoding

encoding = Encoding()


class TestEncoding:
    def test_string(self):
        result = encoding.detect("sample-content")
        assert result["encoding"] in ("ascii",)

    def test_unicode(self):
        result = encoding.detect("sample-content")
        assert result["encoding"] in ("ascii",)

    def test_utf8_bom(self):
        result = encoding.detect(b"\xef\xbb\xbf")
        assert result["encoding"] in ("UTF-8-SIG",)

    def test_unicode_utf8(self):
        result = encoding.detect("函数")
        assert result["encoding"] in ("utf-8",)
