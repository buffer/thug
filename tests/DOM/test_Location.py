from thug.DOM.Location import Location


class WindowDict(dict):
    def __setitem__(self, key, value):
        self[key] = value

    def __getitem__(self, key):
        return self[key]
    

class TestLocation(object):
    def testParts(self):
        window = WindowDict()
        window.url = 'https://www.google.com:1234/search?&q=test'

        location = Location(window)
        
        assert location.host == 'www.google.com:1234'
        assert location.hostname == 'www.google.com'
        assert location.pathname == '/search'
        assert location.search == '&q=test'
        assert location.port == 1234
