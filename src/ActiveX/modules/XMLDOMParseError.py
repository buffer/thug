
class XMLDOMParseError(object):
    def __init__(self):
        self._errorCode = 0
        self._filepos   = 0
        self._line      = 0
        self._linepos   = 0
        self._reason    = 0
        self._srcText   = ''
        self._url       = ''

        @property
        def errorCode(self): #pylint:disable=unused-variable
            return self._errorCode

        @property
        def filepos(self): #pylint:disable=unused-variable
            return self._filepos

        @property
        def line(self): #pylint:disable=unused-variable
            return self._line

        @property
        def linepos(self): #pylint:disable=unused-variable
            return self._linepos

        @property
        def reason(self): #pylint:disable=unused-variable
            return self._reason

        @property
        def srcText(self): #pylint:disable=unused-variable
            return self._srcText

        @property
        def url(self): #pylint:disable=unused-variable
            return self._url
