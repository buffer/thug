from thug.DOM.MimeType import MimeType

class TestMimeType(object):
    def test_items(self):
        mimetype = MimeType()

        mimetype['test1'] = 'value1'
        assert mimetype['test1'] in ('value1', )

        mimetype.test2 = 'value2'
        assert mimetype.test2 in ('value2', )

        del mimetype['test1']
        del mimetype.test2

        del mimetype['test3']
