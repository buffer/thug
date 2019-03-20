from thug.DOM.MimeType import MimeType

class TestMimeType(object):
    def test_items(self):
        mimetype = MimeType()
        
        mimetype.foo = 'bar'
        assert mimetype.foo in ('bar', )

        mimetype.foo = 'foo'
        assert mimetype.foo in ('foo', )

        del mimetype.foo
