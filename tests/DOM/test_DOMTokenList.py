from thug.DOM.W3C.DOMTokenList import DOMTokenList

class TestDOMTokenList(object):
    def testDOMTokenList(self):
        domtokenlist = DOMTokenList(['download', 'fullscreen', 'remoteplayback'])

        assert domtokenlist.length == 0
        assert domtokenlist.supports('download')

        domtokenlist.add('foo')
        assert domtokenlist.length == 0

        assert domtokenlist.supports('nofullscreen')
        domtokenlist.add('nofullscreen')
        assert domtokenlist.length == 1

        assert domtokenlist.item(0) == 'nofullscreen'
        assert domtokenlist.contains('nofullscreen')

        domtokenlist.replace('nofullscreen', 'fullscreen')
        assert domtokenlist.contains('fullscreen')

        domtokenlist.toggle('fullscreen')
        domtokenlist.toggle('fullscreen')

        assert domtokenlist.contains('fullscreen')
        assert domtokenlist.value == 'fullscreen'
