
class XMLDOMParseError:
    def __init__(self):
        self._errorCode = 0
        self._filepos   = 0
        self._line      = 0
        self._linepos   = 0
        self._reason    = 0
        self._srcText   = ''
        self._url       = ''

        @property
        def errorCode(self):
            return self._errorCode

        @property
        def filepos(self):
            return self._filepos

        @property
        def line(self):
            return self._line

        @property
        def linepos(self):
            return self._linepos

        @property
        def reason(self):
            return self._reason

        @property
        def srcText(self):
            return self._srcText

        @property
        def url(self):
            return self._url
